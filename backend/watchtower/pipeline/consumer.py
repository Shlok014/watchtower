"""The consumer: one raw event in, one committed, detected, chained record out.

Every source — synthetic, syslog, file tail, dataset replay — funnels through
``process_log``. That is deliberate: it is what makes a replayed HDFS line light
up the same detection windows, the same alerts and the same ledger as a live
one, instead of each source growing its own half of the pipeline.
"""

import time
from datetime import UTC, datetime

from .. import ledger, telemetry
from ..detect import rules
from ..soar import engine as soar
from ..store import db as store_db
from ..store import repos
from .normalize import normalize_log


def create_alert(conn, log_entry: dict, detection_result: dict, event_id: int) -> dict:
    """Create an alert, run its response playbook, and record what happened."""
    alert = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event": log_entry["event"],
        "source": log_entry["source"],
        "ip": log_entry["ip"],
        "user": log_entry["user"],
        "severity": log_entry["severity"],
        "anomaly_score": detection_result["anomaly_score"],
        "features": detection_result["features"],
        "explanation": detection_result["explanation"],
        "reasons": detection_result["reasons"],
        "ruleset_version": detection_result["ruleset_version"],
        "reputation": log_entry.get("reputation", {}),
        "status": "open",
        "soar_response": None,
    }
    alert["id"] = repos.insert_alert(conn, alert, event_id)

    # The playbook runs, and the alert's status is then whatever the playbook
    # earned. It used to be set to "mitigated" on the line after selecting a
    # playbook — and selection only built a dict, so every alert in the system
    # claimed to have been remediated the instant it was raised.
    response = soar.respond(conn, alert)
    response["id"] = repos.insert_soar(conn, response, alert["id"])
    if response["status"] != "open":
        repos.set_alert_status(conn, alert["id"], response["status"])
        alert["status"] = response["status"]
    alert["soar_response"] = response
    return alert


def process_log(raw_log: dict) -> dict:
    """Full pipeline: normalize → detect → alert → ledger.

    Stages are bracketed with inline perf_counter reads rather than a context
    manager: a @contextmanager timer measures ~2.1us of overhead against stages
    that run in under 1us, so the instrument would have dominated the reading.
    """
    t_pipeline = time.perf_counter()

    t0 = time.perf_counter()
    normalized = normalize_log(raw_log)
    telemetry.record("normalize", time.perf_counter() - t0)

    ingested_ts_ms = repos.now_ms()

    # One transaction for the whole event: the row, its alert, its SOAR record
    # and its ledger block commit together or not at all. A half-committed
    # event would leave a ledger block chained to a log entry that does not
    # exist.
    with store_db.write() as conn:
        # ── enforcement, before detection ──
        # This is the closed loop's other half. A blocked address has its
        # events suppressed here, so the block is a real consequence rather
        # than a row in a table that nothing reads.
        #
        # Before detection, deliberately: running the rules first and
        # discarding the verdict would keep the alert count climbing for an
        # address that is supposed to be silenced, which is precisely the
        # "we blocked it" / "then why is it still alerting" contradiction.
        block = repos.blocked_entry(conn, normalized["ip"])
        normalized["dropped"] = bool(block)

        t0 = time.perf_counter()
        event_id = repos.insert_event(conn, normalized, ingested_ts_ms)
        normalized["id"] = event_id
        event_ts_ms = repos.from_iso(normalized["timestamp"])
        telemetry.record("ingest", time.perf_counter() - t0)

        # The ledger chains the event as it arrived, before anything decides
        # what it means, and whether or not the blocklist suppressed it. Two
        # reasons, and the second was found by a test:
        #
        #  * An audit ledger that omits the events a response action silenced
        #    has a hole exactly where the interesting traffic is.
        #  * Chaining last meant an incident report written during the alert
        #    could not cite the block covering its own triggering event — the
        #    block did not exist yet. A report whose evidence points at nothing
        #    verifiable is a press release.
        t0 = time.perf_counter()
        ledger.append(conn, normalized, event_id, event_ts_ms, ingested_ts_ms)
        repos.bump(conn, "blocks")
        telemetry.record("ledger", time.perf_counter() - t0)

        if block:
            repos.record_block_hit(conn, normalized["ip"])
        else:
            t0 = time.perf_counter()
            detection = rules.detect(conn, normalized, ingested_ts_ms)
            telemetry.record("detect", time.perf_counter() - t0)

            if detection["is_anomaly"]:
                t0 = time.perf_counter()
                create_alert(conn, normalized, detection, event_id)
                telemetry.record("alert", time.perf_counter() - t0)

    telemetry.record("pipeline", time.perf_counter() - t_pipeline)
    telemetry.record_event()
    return normalized


# ── housekeeping ─────────────────────────────────────────────────────────────
_last_prune = 0.0
PRUNE_INTERVAL_S = 300


def housekeeping() -> None:
    """Retention sweep and WAL truncation, every few minutes."""
    global _last_prune
    now = time.monotonic()
    if now - _last_prune < PRUNE_INTERVAL_S:
        return
    _last_prune = now
    try:
        with store_db.write() as conn:
            repos.prune(conn)
            # Expiry is already enforced by the blocklist lookup, so this only
            # reclaims rows. Relying on a sweep to stop enforcement would mean a
            # lagging sweep goes on dropping traffic past its TTL.
            repos.purge_expired_blocks(conn)
        store_db.checkpoint()
    except Exception as exc:
        # Surfaced, not swallowed: a store that stopped pruning is a store that
        # will fill the disk.
        print(f"⚠️  housekeeping failed: {type(exc).__name__}: {exc}")
