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
    """Create an alert from an anomalous log, and select a response playbook."""
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

    # The status stays "open". It used to be set to "mitigated" on the line
    # after the playbook was selected — but selection only builds a dict, so
    # every alert in the system claimed to have been remediated the instant it
    # was raised. A status has to be earned by an action that actually ran.
    response = soar.respond(alert)
    response["id"] = repos.insert_soar(conn, response, alert["id"])
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
        t0 = time.perf_counter()
        event_id = repos.insert_event(conn, normalized, ingested_ts_ms)
        normalized["id"] = event_id
        event_ts_ms = repos.from_iso(normalized["timestamp"])
        telemetry.record("ingest", time.perf_counter() - t0)

        t0 = time.perf_counter()
        detection = rules.detect(conn, normalized, ingested_ts_ms)
        telemetry.record("detect", time.perf_counter() - t0)

        if detection["is_anomaly"]:
            t0 = time.perf_counter()
            create_alert(conn, normalized, detection, event_id)
            telemetry.record("alert", time.perf_counter() - t0)

        t0 = time.perf_counter()
        ledger.append(conn, normalized, event_id, event_ts_ms, ingested_ts_ms)
        repos.bump(conn, "blocks")
        telemetry.record("ledger", time.perf_counter() - t0)

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
        store_db.checkpoint()
    except Exception as exc:
        # Surfaced, not swallowed: a store that stopped pruning is a store that
        # will fill the disk.
        print(f"⚠️  housekeeping failed: {type(exc).__name__}: {exc}")
