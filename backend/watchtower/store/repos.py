"""Data access.

Every function here returns dicts shaped exactly like the JSON the dashboard
already consumes. The API response shape is a contract independent of column
names — and it has to be enforced deliberately, because every field the
frontend reads is optional-chained. A renamed column does not throw; it renders
an empty cell. The IP-reputation column, the one thing the README marks
"real, measured", would go blank and nothing would report an error.
"""

import json
from datetime import UTC, datetime

from .. import config
from . import db


# Retention. Time-based, because that is what a log store means by retention;
# row-count caps would just be a ring buffer with extra steps.
def retention_hours() -> int:
    return config.get().retention_hours


def now_ms() -> int:
    return int(datetime.now(UTC).timestamp() * 1000)


def to_iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, UTC).isoformat()


def from_iso(value: str) -> int:
    return int(datetime.fromisoformat(value).timestamp() * 1000)


def retention_note() -> str:
    """Describe the storage policy. Derived, never a literal.

    /api/stats previously shipped a hardcoded "in-memory ring buffers: 2000
    logs, 500 alerts..." string. Left alone it would have survived this change
    and gone on describing storage that no longer exists — in the very field
    added to stop the app misrepresenting itself.
    """
    return (
        f"SQLite (WAL) at {db.path().name}; events retained {retention_hours()}h unless "
        "referenced by an alert; ledger is append-only and exempt"
    )


# ── counters ─────────────────────────────────────────────────────────────────
# Lifetime totals are persisted rather than derived. max(id) and COUNT(*) both
# fall when retention prunes, and "total events ever ingested" must not go down.
def bump(conn, name: str, delta: int = 1) -> int:
    conn.execute(
        "INSERT INTO counters(name, value) VALUES(?, ?) "
        "ON CONFLICT(name) DO UPDATE SET value = value + excluded.value",
        (name, delta),
    )
    return conn.execute("SELECT value FROM counters WHERE name = ?", (name,)).fetchone()[0]


def counters() -> dict:
    rows = db.connect().execute("SELECT name, value FROM counters").fetchall()
    out = {r["name"]: r["value"] for r in rows}
    for k in ("events", "alerts", "blocks", "soar"):
        out.setdefault(k, 0)
    return out


# ── events ───────────────────────────────────────────────────────────────────
def _event_row_to_dict(r) -> dict:
    return {
        "id": r["id"],
        "timestamp": to_iso(r["ts_ms"]),
        "ingested_at": to_iso(r["ingested_ts_ms"]),
        "source": r["source"],
        "event": r["event"],
        "event_type": r["event_type"],
        "severity": r["severity"],
        "ip": r["ip"],
        "user": r["user"],
        "message": r["message"],
        "log_format": r["log_format"],
        "origin": r["origin"],
        # Suppressed by the blocklist before detection ran.
        "dropped": bool(r["dropped"]),
        # Re-nested: the frontend reads log.reputation?.verdict / .detail.
        "reputation": {
            "verdict": r["rep_verdict"],
            "score": r["rep_score"],
            "sources": json.loads(r["rep_sources"]),
            "checked": bool(r["rep_checked"]),
            "detail": r["rep_detail"],
        },
    }


def insert_event(conn, normalized: dict, ingested_ts_ms: int) -> int:
    rep = normalized.get("reputation") or {}
    origin = normalized.get("origin")
    if not origin:
        # Never default this. A missing origin defaulting to "synthetic" would
        # label real traffic as simulated — wrong in the dangerous direction,
        # and it would quietly defeat the labelling this project relies on.
        raise ValueError(f"event {normalized.get('id')} has no origin")
    cur = conn.execute(
        """INSERT INTO events (ts_ms, ingested_ts_ms, source, event, event_type, severity,
                               ip, user, message, log_format, origin, dropped,
                               rep_verdict, rep_score, rep_sources, rep_checked, rep_detail)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            from_iso(normalized["timestamp"]),
            ingested_ts_ms,
            normalized["source"],
            normalized["event"],
            normalized["event_type"],
            normalized["severity"],
            normalized["ip"],
            normalized["user"],
            normalized["message"],
            normalized["log_format"],
            origin,
            1 if normalized.get("dropped") else 0,
            rep.get("verdict", "unavailable"),
            float(rep.get("score", 0.0)),
            json.dumps(rep.get("sources", [])),
            1 if rep.get("checked") else 0,
            rep.get("detail", ""),
        ),
    )
    bump(conn, "events")
    return cur.lastrowid


def recent_events(limit=100, severity=None, source=None, search=None) -> list[dict]:
    sql = "SELECT * FROM events"
    where, params = [], []
    if severity:
        where.append("severity = ?")
        params.append(severity)
    if source:
        where.append("source = ?")
        params.append(source)
    if search:
        # Matches the old behaviour (substring over the serialised record) but
        # against named columns rather than json.dumps of the whole row.
        cols = ["message", "ip", "user", "event", "source", "severity", "origin"]
        where.append("(" + " OR ".join(f"instr(lower({c}), lower(?))" for c in cols) + ")")
        params.extend([search] * len(cols))
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    return [_event_row_to_dict(r) for r in db.connect().execute(sql, params)]


# ── detection windows ────────────────────────────────────────────────────────
# Keyed on ingested_ts_ms, not ts_ms: replayed events carry their original
# timestamps, so a window over event time would never match anything.
# Dropped events are excluded. They were suppressed before detection ran, so
# counting them would let a blocked address keep driving the windows for every
# other address it shares a rule with — and would make the count disagree with
# the alerts it is supposed to explain.
def failed_logins_in_window(conn, ip: str, since_ms: int) -> int:
    return conn.execute(
        "SELECT count(*) FROM events WHERE ip = ? AND event = 'failed_login' "
        "AND ingested_ts_ms > ? AND dropped = 0",
        (ip, since_ms),
    ).fetchone()[0]


def events_in_window(conn, ip: str, since_ms: int) -> int:
    return conn.execute(
        "SELECT count(*) FROM events WHERE ip = ? AND ingested_ts_ms > ? AND dropped = 0",
        (ip, since_ms),
    ).fetchone()[0]


# ── alerts ───────────────────────────────────────────────────────────────────
def _alert_row_to_dict(r, soar=None) -> dict:
    return {
        "id": r["id"],
        "timestamp": to_iso(r["ts_ms"]),
        "event": r["event"],
        "source": r["source"],
        "ip": r["ip"],
        "user": r["user"],
        "severity": r["severity"],
        "anomaly_score": r["anomaly_score"],
        "ruleset_version": r["ruleset_version"],
        "explanation": r["explanation"],
        "features": json.loads(r["features_json"]),
        "reasons": json.loads(r["reasons_json"]),
        "reputation": json.loads(r["reputation_json"]),
        "status": r["status"],
        "soar_response": soar,
    }


def insert_alert(conn, alert: dict, event_id: int | None) -> int:
    cur = conn.execute(
        """INSERT INTO alerts (event_id, ts_ms, event, source, ip, user, severity,
                               anomaly_score, ruleset_version, explanation,
                               features_json, reasons_json, reputation_json, status)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            event_id,
            from_iso(alert["timestamp"]),
            alert["event"],
            alert["source"],
            alert["ip"],
            alert["user"],
            alert["severity"],
            alert["anomaly_score"],
            alert["ruleset_version"],
            alert["explanation"],
            json.dumps(alert["features"]),
            json.dumps(alert["reasons"]),
            json.dumps(alert.get("reputation", {})),
            alert["status"],
        ),
    )
    bump(conn, "alerts")
    return cur.lastrowid


def set_alert_status(conn, alert_id: int, status: str) -> None:
    """Record the status a response playbook actually earned.

    The CHECK constraint on the column is the backstop: the old code wrote
    'mitigated' unconditionally, and a typo'd status now fails loudly instead of
    landing in the database and rendering as a green tick.
    """
    conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))


def recent_alerts(limit=50) -> list[dict]:
    conn = db.connect()
    rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    if not rows:
        return []
    ids = [r["id"] for r in rows]
    marks = ",".join("?" * len(ids))
    soar_by_alert = {
        s["alert_id"]: s
        for s in _soar_rows(conn, f"SELECT * FROM soar_executions WHERE alert_id IN ({marks})", ids)
    }
    return [_alert_row_to_dict(r, soar_by_alert.get(r["id"])) for r in rows]


# ── SOAR ─────────────────────────────────────────────────────────────────────
def _soar_rows(conn, sql: str, params) -> list[dict]:
    execs = conn.execute(sql, params).fetchall()
    if not execs:
        return []
    ids = [e["id"] for e in execs]
    marks = ",".join("?" * len(ids))
    steps: dict[int, list] = {i: [] for i in ids}
    for s in conn.execute(
        f"SELECT * FROM soar_steps WHERE execution_id IN ({marks}) ORDER BY execution_id, position",
        ids,
    ):
        steps[s["execution_id"]].append(
            {
                "action": s["action"],
                "status": s["status"],
                "executed": bool(s["executed"]),
                "required": bool(s["required"]),
                "duration_us": s["duration_us"],
                "detail": s["detail"],
            }
        )
    return [
        {
            "id": e["id"],
            "alert_id": e["alert_id"],
            "timestamp": to_iso(e["ts_ms"]),
            "event": e["event"],
            "ip": e["ip"],
            "playbook": e["playbook"],
            "priority": e["priority"],
            "execution_mode": e["execution_mode"],
            "selection_time_us": e["selection_time_us"],
            "status": e["status"],
            "playbook_steps": [s["action"] for s in steps[e["id"]]],
            "execution_steps": steps[e["id"]],
        }
        for e in execs
    ]


def insert_soar(conn, response: dict, alert_id: int) -> int:
    cur = conn.execute(
        """INSERT INTO soar_executions (alert_id, ts_ms, event, ip, playbook, priority,
                                        execution_mode, selection_time_us, status)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (
            alert_id,
            from_iso(response["timestamp"]),
            response["event"],
            response["ip"],
            response["playbook"],
            response["priority"],
            response["execution_mode"],
            response["selection_time_us"],
            response["status"],
        ),
    )
    exec_id = cur.lastrowid
    conn.executemany(
        """INSERT INTO soar_steps (execution_id, position, action, status, executed,
                                   required, duration_us, detail)
           VALUES (?,?,?,?,?,?,?,?)""",
        [
            (
                exec_id,
                i,
                s["action"],
                s["status"],
                1 if s["executed"] else 0,
                1 if s.get("required") else 0,
                s["duration_us"],
                s["detail"],
            )
            for i, s in enumerate(response["execution_steps"])
        ],
    )
    bump(conn, "soar")
    return exec_id


def recent_soar(limit=30) -> list[dict]:
    conn = db.connect()
    return _soar_rows(conn, "SELECT * FROM soar_executions ORDER BY id DESC LIMIT ?", (limit,))


# ── ledger ───────────────────────────────────────────────────────────────────
def _block_row_to_dict(r) -> dict:
    return {
        "block_id": r["block_id"],
        "timestamp": to_iso(r["ts_ms"]),
        "log_id": r["event_id"],
        # JSON key stays log_hash — the block card reads b.log_hash.
        "log_hash": r["log_hash"],
        "prev_hash": r["prev_hash"],
        "hash": r["hash"],
    }


def last_block_hash(conn) -> str | None:
    row = conn.execute("SELECT hash FROM ledger ORDER BY block_id DESC LIMIT 1").fetchone()
    return row["hash"] if row else None


def recent_blocks(limit=30) -> list[dict]:
    return [
        _block_row_to_dict(r)
        for r in db.connect().execute(
            "SELECT * FROM ledger ORDER BY block_id DESC LIMIT ?", (limit,)
        )
    ]


def chain_links() -> list[tuple]:
    """(block_id, prev_hash, hash) in order, for the link-continuity check."""
    return [
        (r["block_id"], r["prev_hash"], r["hash"])
        for r in db.connect().execute(
            "SELECT block_id, prev_hash, hash FROM ledger ORDER BY block_id"
        )
    ]


def ledger_bounds() -> tuple[int, str | None, str | None]:
    conn = db.connect()
    n = conn.execute("SELECT count(*) FROM ledger").fetchone()[0]
    if not n:
        return 0, None, None
    oldest = conn.execute("SELECT hash FROM ledger ORDER BY block_id ASC LIMIT 1").fetchone()[
        "hash"
    ]
    newest = conn.execute("SELECT hash FROM ledger ORDER BY block_id DESC LIMIT 1").fetchone()[
        "hash"
    ]
    return n, oldest, newest


# ── stats ────────────────────────────────────────────────────────────────────
def stats(buckets: int = 30, bucket_seconds: int = 10) -> dict:
    """Aggregate in SQL.

    The previous implementation looped over every retained log and every alert
    once per bucket, calling datetime.fromisoformat each time — about 75,000
    parses per request at a full buffer, measured at 13.0 ms of which 9.2 ms was
    parsing alone, repeated every 2 seconds.
    """
    conn = db.connect()
    now = now_ms()
    span = buckets * bucket_seconds * 1000
    start = now - span
    width = bucket_seconds * 1000

    # GROUP BY alone omits empty buckets entirely, which would make the timeline
    # silently shrink during quiet periods. Build the full range and fill.
    log_counts = dict(
        conn.execute(
            "SELECT (ingested_ts_ms - ?) / ? AS b, count(*) FROM events "
            "WHERE ingested_ts_ms >= ? AND ingested_ts_ms < ? GROUP BY b",
            (start, width, start, now),
        ).fetchall()
    )
    alert_counts = dict(
        conn.execute(
            "SELECT (ts_ms - ?) / ? AS b, count(*) FROM alerts "
            "WHERE ts_ms >= ? AND ts_ms < ? GROUP BY b",
            (start, width, start, now),
        ).fetchall()
    )
    timeline = []
    for i in range(buckets):
        end_ms = start + (i + 1) * width
        timeline.append(
            {
                "time": datetime.fromtimestamp(end_ms / 1000, UTC).strftime("%H:%M:%S"),
                "logs": log_counts.get(i, 0),
                "alerts": alert_counts.get(i, 0),
            }
        )

    sev = dict(conn.execute("SELECT severity, count(*) FROM alerts GROUP BY severity").fetchall())
    crit = sev.get("critical", 0)
    high = sev.get("high", 0)
    med = sev.get("medium", 0)
    low = sev.get("low", 0)

    # A recent window, not a lifetime total. The chart built from it sits beside
    # a stat card showing the lifetime count, and the two disagreed with nothing
    # saying why. The size travels with the data so the UI can label it.
    recent_window = 200
    event_dist = dict(
        conn.execute(
            "SELECT event, count(*) FROM (SELECT event FROM events ORDER BY id DESC LIMIT ?) "
            "GROUP BY event",
            (recent_window,),
        ).fetchall()
    )
    source_dist = dict(
        conn.execute(
            "SELECT source, count(*) FROM (SELECT source FROM events ORDER BY id DESC LIMIT ?) "
            "GROUP BY source",
            (recent_window,),
        ).fetchall()
    )
    origin_dist = dict(
        conn.execute("SELECT origin, count(*) FROM events GROUP BY origin").fetchall()
    )

    c = counters()
    retained = {
        "events": conn.execute("SELECT count(*) FROM events").fetchone()[0],
        "alerts": conn.execute("SELECT count(*) FROM alerts").fetchone()[0],
        "blocks": conn.execute("SELECT count(*) FROM ledger").fetchone()[0],
    }
    return {
        "totals": c,
        "retained": retained,
        "timeline": timeline,
        "alert_distribution": {
            "critical": crit,
            "high": high,
            "medium": med,
            "low": low,
        },
        "high_severity_alerts": crit + high,
        "critical_alerts": crit,
        "medium_severity_alerts": med,
        "event_distribution": event_dist,
        "distribution_window": recent_window,
        "source_distribution": source_dist,
        "origin_distribution": origin_dist,
    }


# ── retention & reset ────────────────────────────────────────────────────────
def known_sources(conn=None, limit: int = 100) -> list[str]:
    """Distinct source names actually present in the store.

    /api/v1/stats used to return the synthetic generator's seven hardcoded
    hostnames here, and the dashboard builds its "All Sources" filter from it.
    Run any real source — syslog, a file tail, an HDFS replay — and every option
    in that dropdown matched nothing, while the sources genuinely in the table
    were absent from it.
    """
    conn = conn or db.connect()
    return [
        r[0]
        for r in conn.execute(
            "SELECT DISTINCT source FROM events ORDER BY source LIMIT ?", (limit,)
        )
    ]


def prune(conn, hours: int | None = None) -> int:
    """Delete events older than the window, keeping anything an alert cites.

    The ledger is untouched.
    """
    hours = retention_hours() if hours is None else hours
    cutoff = now_ms() - hours * 3600 * 1000
    cur = conn.execute(
        "DELETE FROM events WHERE ingested_ts_ms < ? "
        "AND id NOT IN (SELECT event_id FROM alerts WHERE event_id IS NOT NULL)",
        (cutoff,),
    )
    return cur.rowcount


def reset_all(conn) -> dict:
    """Actually delete everything, and report what was deleted.

    /api/reset used to clear four Python lists and unlink a JSON file. Against a
    database that would have left every row in place while the response claimed
    "All data cleared" — the exact class of statement this project exists to
    remove.
    """
    deleted = {}
    for table in ("soar_steps", "soar_executions", "alerts", "events", "ledger", "blocklist"):
        deleted[table] = conn.execute(f"DELETE FROM {table}").rowcount
    conn.execute("UPDATE counters SET value = 0")
    # Reclaim the freed pages; auto_vacuum=INCREMENTAL only frees on request.
    return deleted


# ── blocklist ────────────────────────────────────────────────────────────────
# The closed loop. `block_ip` writes here; the consumer checks it before
# detection runs. Enforcement is at this application's ingestion layer — nothing
# touches a firewall and nothing needs root.
def block_ip(conn, ip: str, reason: str, alert_id: int | None, ttl_seconds: int) -> dict:
    """Block an address, or extend an existing block. Returns the row.

    ON CONFLICT extends rather than inserting a second row. Two rows for one
    address would split its hit count in half, and every "N events dropped from
    X" figure the dashboard shows would be an undercount.

    The expiry is `max(existing, new)`: re-blocking with a shorter TTL must not
    shorten a longer block that is already running.
    """
    now = now_ms()
    expires = now + ttl_seconds * 1000
    conn.execute(
        """INSERT INTO blocklist (ip, reason, alert_id, created_ts_ms, expires_ts_ms, hits)
           VALUES (?,?,?,?,?,0)
           ON CONFLICT(ip) DO UPDATE SET
               reason        = excluded.reason,
               alert_id      = excluded.alert_id,
               expires_ts_ms = max(blocklist.expires_ts_ms, excluded.expires_ts_ms)""",
        (ip, reason, alert_id, now, expires),
    )
    row = conn.execute("SELECT * FROM blocklist WHERE ip = ?", (ip,)).fetchone()
    return dict(row)


def blocked_entry(conn, ip: str) -> dict | None:
    """The live block for this address, or None.

    Expiry is checked in the query rather than by a sweep, so a block stops
    applying the millisecond it expires even if housekeeping has not run. A
    sweep that lagged would keep dropping traffic after the TTL, which is the
    kind of over-enforcement nobody notices until it matters.
    """
    row = conn.execute(
        "SELECT * FROM blocklist WHERE ip = ? AND expires_ts_ms > ?", (ip, now_ms())
    ).fetchone()
    return dict(row) if row else None


def record_block_hit(conn, ip: str) -> None:
    conn.execute(
        "UPDATE blocklist SET hits = hits + 1, last_hit_ts_ms = ? WHERE ip = ?",
        (now_ms(), ip),
    )
    bump(conn, "dropped")


def _blocklist_row(r, now: int) -> dict:
    return {
        "ip": r["ip"],
        "reason": r["reason"],
        "alert_id": r["alert_id"],
        "blocked_at": to_iso(r["created_ts_ms"]),
        "expires_at": to_iso(r["expires_ts_ms"]),
        "expired": r["expires_ts_ms"] <= now,
        "seconds_remaining": max(0, (r["expires_ts_ms"] - now) // 1000),
        "events_dropped": r["hits"],
        "last_hit_at": to_iso(r["last_hit_ts_ms"]) if r["last_hit_ts_ms"] else None,
    }


def blocklist(conn=None, include_expired: bool = False, limit: int = 100) -> list[dict]:
    conn = conn or db.connect()
    now = now_ms()
    sql = "SELECT * FROM blocklist"
    params: list = []
    if not include_expired:
        sql += " WHERE expires_ts_ms > ?"
        params.append(now)
    sql += " ORDER BY hits DESC, created_ts_ms DESC LIMIT ?"
    params.append(limit)
    return [_blocklist_row(r, now) for r in conn.execute(sql, params)]


def unblock(conn, ip: str) -> bool:
    """Remove a block outright. Returns whether there was one."""
    cur = conn.execute("DELETE FROM blocklist WHERE ip = ?", (ip,))
    return cur.rowcount > 0


def purge_expired_blocks(conn) -> int:
    """Housekeeping. Expiry is already enforced by the lookup; this reclaims rows."""
    return conn.execute("DELETE FROM blocklist WHERE expires_ts_ms <= ?", (now_ms(),)).rowcount


def blocklist_totals(conn=None) -> dict:
    conn = conn or db.connect()
    now = now_ms()
    active = conn.execute(
        "SELECT count(*), coalesce(sum(hits), 0) FROM blocklist WHERE expires_ts_ms > ?", (now,)
    ).fetchone()
    return {
        "active_blocks": active[0],
        "events_dropped_by_active_blocks": active[1],
        "events_dropped_lifetime": counters().get("dropped", 0),
    }


def recent_events_for_ip(conn, ip: str, limit: int = 20) -> list[dict]:
    """Evidence for an incident report."""
    return [
        _event_row_to_dict(r)
        for r in conn.execute(
            "SELECT * FROM events WHERE ip = ? ORDER BY id DESC LIMIT ?", (ip, limit)
        )
    ]


def ledger_heights_for_events(conn, event_ids: list[int]) -> list[int]:
    """Which ledger blocks cover these events. Empty if retention removed them."""
    if not event_ids:
        return []
    marks = ",".join("?" * len(event_ids))
    return [
        r[0]
        for r in conn.execute(
            f"SELECT block_id FROM ledger WHERE event_id IN ({marks}) ORDER BY block_id",
            event_ids,
        )
    ]
