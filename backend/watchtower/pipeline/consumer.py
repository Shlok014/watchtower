"""The consumer: one raw event in, one committed, detected, chained record out.

Every source — synthetic, syslog, file tail, dataset replay — funnels through
``process_log``. That is deliberate: it is what makes a replayed HDFS line light
up the same detection windows, the same alerts and the same ledger as a live
one, instead of each source growing its own half of the pipeline.
"""

import time
from datetime import UTC, datetime

from .. import ledger, telemetry
from ..detect import live_shadow, rules
from ..soar import engine as soar
from ..store import db as store_db
from ..store import repos
from .normalize import normalize_log


def create_alert(conn, log_entry: dict, detection_result: dict, event_id: int) -> dict:
    """Insert the alert row. The response runs later, outside this transaction."""
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
    return alert


def run_response(alert: dict) -> dict | None:
    """Run the alert's playbook in its own transaction, after the event is safe.

    **This deliberately does not share the ingest transaction**, and two
    reproduced failures are why.

    *The event used to vanish.* Playbook selection can raise — a typo in a YAML
    file is enough — and the exception unwound the transaction that had already
    inserted the event row, its ledger block and the counter bump. An operator
    who mistyped one action name got every *benign* event stored normally and
    every *alerting* event erased: no event, no block, no alert, no counter. And
    because SQLite reuses the rowids of a rolled-back transaction, the chain had
    no height gap — `verify` reported it clean over a record set missing exactly
    the anomalous traffic.

    *And concurrent events were lost.* The webhook's 3-second network call ran
    inside `BEGIN IMMEDIATE`, holding the single write lock for its duration.
    With busy_timeout at 5s, the third concurrent writer got
    "database is locked" out of BEGIN, so its event was never written at all —
    and the source threads print that and carry on.

    The alert is committed before its response, so a failure here leaves an
    alert whose status has not advanced. That is recoverable; losing the event
    is not.

    **But "no SOAR record" was not a true statement, and round two caught it.**
    ``block_ip`` writes on an autocommit connection, so the blocklist row lands
    the moment it runs — while the alert still read "open" and no execution row
    existed. A stop or a crash in that window left an address under active
    enforcement beside an alert whose status means, in ``soar/engine.py``'s own
    words, "the alert was raised and nothing has run yet". The docstring that
    used to sit here called that state true. It was not.

    So the execution row is now written *before* the first action can have an
    effect, and each step is recorded as it completes. A crash leaves a row
    saying ``running`` with the steps that finished — incomplete, and true.
    """
    exec_id: list[int] = []

    def on_start(playbook):
        # Committed before the first action can have a side effect, so a crash
        # from here on leaves a row saying `running` rather than silence.
        with store_db.write() as conn:
            exec_id.append(
                repos.begin_soar(
                    conn,
                    alert_id=alert["id"],
                    playbook=playbook.name,
                    priority=playbook.priority,
                    event=alert["event"],
                    ip=alert["ip"],
                )
            )

    def on_step(position, step):
        # Each step lands as it completes. The stored record therefore never
        # claims less than what has actually happened.
        with store_db.write() as conn:
            repos.record_soar_step(conn, exec_id[0], position, step)

    try:
        response = soar.respond(store_db.connect(), alert, on_step=on_step, on_start=on_start)
    except Exception as exc:
        # A broken playbook, a vanished alert row, anything. The event is
        # already safe; say what failed and leave the partial record standing.
        print(f"⚠️  response failed for alert {alert['id']}: {type(exc).__name__}: {exc}")
        if exec_id:
            try:
                with store_db.write() as conn:
                    repos.finish_soar(conn, exec_id[0], "interrupted", 0.0)
            except Exception:
                pass
        return None

    try:
        with store_db.write() as conn:
            repos.finish_soar(conn, exec_id[0], response["status"], response["selection_time_us"])
            if response["status"] != "open":
                repos.set_alert_status(conn, alert["id"], response["status"])
                alert["status"] = response["status"]
    except Exception as exc:
        print(f"⚠️  could not finalise response for alert {alert['id']}: {exc}")
        return None
    response["id"] = exec_id[0]
    alert["soar_response"] = response
    return response


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

    # One transaction for the *record*: the row, its ledger block and its alert
    # commit together or not at all. A half-committed event would leave a ledger
    # block chained to a log entry that does not exist.
    #
    # The response is NOT in here — see run_response. Everything inside this
    # block is local, bounded work against SQLite. Nothing that can make a
    # network call or read a config file off disk belongs in a transaction that
    # holds the single write lock.
    alert = None
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
            shadow_verdict = live_shadow.verdict(blocked=True)
        else:
            t0 = time.perf_counter()
            detection = rules.detect(conn, normalized, ingested_ts_ms)
            telemetry.record("detect", time.perf_counter() - t0)

            # Pure, bounded scoring against the profile loaded at startup.
            # This does no file IO or fitting and cannot trigger an alert.
            shadow_verdict = live_shadow.verdict(detection["features"])

            if detection["is_anomaly"]:
                t0 = time.perf_counter()
                alert = create_alert(conn, normalized, detection, event_id)
                telemetry.record("alert", time.perf_counter() - t0)

        repos.insert_shadow_verdict(conn, event_id, shadow_verdict)

    # Committed. From here the event is safe whatever the response does.
    if alert is not None:
        t0 = time.perf_counter()
        run_response(alert)
        telemetry.record("respond", time.perf_counter() - t0)

    # Housekeeping runs on the pipeline, not on one source's tick. It used to be
    # wired only into SyntheticSource(on_tick=...), so every documented real
    # configuration — syslog, file tail, replay — never pruned, never truncated
    # the WAL, and never reclaimed an expired blocklist row, while /api/v1/stats
    # went on publishing the retention policy as fact. The call is a monotonic
    # comparison on all but one invocation in five minutes.
    housekeeping()

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
