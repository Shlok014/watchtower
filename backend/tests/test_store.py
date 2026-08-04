"""Tests for the persistence layer.

Each of these targets a specific defect that existed before SQLite, and each
would fail if that defect were reintroduced — a test that passes either way is
worse than no test.
"""

import sqlite3
import threading

import pytest

from watchtower.store import db, repos


@pytest.fixture()
def store_db(tmp_path):
    # A file, not ":memory:". An in-memory database is per-connection, and the
    # design hands each thread its own connection — so the concurrency tests
    # below would each get a private empty database and pass vacuously.
    db.configure(tmp_path / "t.db")
    db.connect()
    yield
    db.close_all()


def _event(ip="9.9.9.9", event="failed_login", origin="synthetic", ts=None, ing=None):
    ts = ts or repos.now_ms()
    return dict(
        ts_ms=ts,
        ingested_ts_ms=ing if ing is not None else ts,
        source="linux-server",
        event=event,
        event_type="authentication",
        severity="medium",
        ip=ip,
        user="root",
        message="m",
        log_format="syslog",
        origin=origin,
    )


def _insert(conn, **kw):
    e = _event(**kw)
    cur = conn.execute(
        """INSERT INTO events (ts_ms,ingested_ts_ms,source,event,event_type,severity,ip,
                               user,message,log_format,origin,rep_verdict,rep_score,
                               rep_sources,rep_checked,rep_detail)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,'unlisted',0,'[]',1,'')""",
        tuple(e.values()),
    )
    repos.bump(conn, "events")
    return cur.lastrowid


# ── provenance ───────────────────────────────────────────────────────────────
@pytest.mark.parametrize("origin", ["synthetic", "syslog", "file", "replay:hdfs_v1"])
def test_valid_origins_accepted(store_db, origin):
    with db.write() as conn:
        assert _insert(conn, origin=origin)


@pytest.mark.parametrize("origin", ["REPLAY:hdfs", "Replay:x", "replay:", "bogus", ""])
def test_invalid_origins_rejected(store_db, origin):
    """GLOB, not LIKE.

    SQLite's LIKE is ASCII case-insensitive, so a `LIKE 'replay:%'` constraint
    accepts REPLAY: and Replay: as well — two spellings of one provenance, which
    makes every GROUP BY origin under-count replayed data.
    """
    with pytest.raises(sqlite3.IntegrityError), db.write() as conn:
        _insert(conn, origin=origin)


# ── the race the lists had ───────────────────────────────────────────────────
def test_concurrent_writers_and_reader(store_db):
    errors, per_thread, threads = [], 250, 4

    def writer(k):
        try:
            for _ in range(per_thread):
                with db.write() as conn:
                    _insert(conn, ip=f"10.0.0.{k}")
        except Exception as exc:  # noqa: BLE001 - the assertion is that there are none
            errors.append(f"writer{k}: {type(exc).__name__}: {exc}")

    stop = threading.Event()

    def reader():
        while not stop.is_set():
            try:
                repos.recent_events(limit=50)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"reader: {type(exc).__name__}: {exc}")

    r = threading.Thread(target=reader)
    r.start()
    ws = [threading.Thread(target=writer, args=(k,)) for k in range(threads)]
    for w in ws:
        w.start()
    for w in ws:
        w.join()
    stop.set()
    r.join()

    assert errors == []
    conn = db.connect()
    total = conn.execute("SELECT count(*) FROM events").fetchone()[0]
    distinct = conn.execute("SELECT count(DISTINCT id) FROM events").fetchone()[0]
    assert total == threads * per_thread
    # No lost or duplicated ids. `x += 1` under the old scheme was a
    # LOAD/ADD/STORE that could interleave between two writer threads.
    assert distinct == total
    assert repos.counters()["events"] == total


# ── retention ────────────────────────────────────────────────────────────────
def test_prune_keeps_alert_referenced_events(store_db):
    now = repos.now_ms()
    old = now - 48 * 3600 * 1000
    with db.write() as conn:
        old_ids = [_insert(conn, ts=old, ing=old) for _ in range(5)]
        fresh = [_insert(conn) for _ in range(3)]
        conn.execute(
            """INSERT INTO alerts (event_id,ts_ms,event,source,ip,user,severity,anomaly_score,
                                   ruleset_version,explanation,features_json,reasons_json,
                                   reputation_json,status)
               VALUES (?,?,'e','s','9.9.9.9','u','low',0.9,'r','x','{}','[]','{}','open')""",
            (old_ids[0], old),
        )
    with db.write() as conn:
        pruned = repos.prune(conn, hours=24)
    assert pruned == 4
    conn = db.connect()
    survivors = {r[0] for r in conn.execute("SELECT id FROM events")}
    assert old_ids[0] in survivors, "an event cited by an alert must not be pruned"
    assert set(fresh) <= survivors


def test_lifetime_counter_survives_pruning(store_db):
    """'Total events ever ingested' must never fall.

    Deriving it from COUNT(*) or max(id) would make the dashboard's headline
    number drop every time retention ran.
    """
    old = repos.now_ms() - 48 * 3600 * 1000
    with db.write() as conn:
        for _ in range(10):
            _insert(conn, ts=old, ing=old)
    before = repos.counters()["events"]
    with db.write() as conn:
        repos.prune(conn, hours=24)
    assert db.connect().execute("SELECT count(*) FROM events").fetchone()[0] == 0
    assert repos.counters()["events"] == before == 10


def test_ledger_is_exempt_from_retention(store_db):
    old = repos.now_ms() - 48 * 3600 * 1000
    with db.write() as conn:
        conn.execute(
            "INSERT INTO ledger (ts_ms,event_id,payload_json,log_hash,prev_hash,hash) "
            "VALUES (?,NULL,'{}','a','b','c')",
            (old,),
        )
        repos.bump(conn, "blocks")
    with db.write() as conn:
        repos.prune(conn, hours=24)
    assert db.connect().execute("SELECT count(*) FROM ledger").fetchone()[0] == 1


# ── replay time separation ───────────────────────────────────────────────────
def test_detection_windows_use_ingest_time_not_event_time(store_db):
    """A replayed 2008 event must still be visible to the detection windows.

    Keying the windows on event time instead would return zero for every
    replayed event — the detector would report "no rule matched" forever, which
    is indistinguishable from a quiet network.
    """
    now = repos.now_ms()
    ancient = repos.from_iso("2008-11-09T20:35:00+00:00")
    with db.write() as conn:
        for _ in range(6):
            _insert(conn, ip="7.7.7.7", origin="replay:hdfs_v1", ts=ancient, ing=now)

    conn = db.connect()
    assert repos.failed_logins_in_window(conn, "7.7.7.7", now - 60_000) == 6
    on_event_time = conn.execute(
        "SELECT count(*) FROM events WHERE ip='7.7.7.7' AND ts_ms > ?", (now - 60_000,)
    ).fetchone()[0]
    assert on_event_time == 0, "event time is genuinely old; that is the point"


# ── transactions ─────────────────────────────────────────────────────────────
def test_failed_transaction_rolls_back_and_connection_stays_usable(store_db):
    with db.write() as conn:
        _insert(conn)
    before = db.connect().execute("SELECT count(*) FROM events").fetchone()[0]

    with pytest.raises(RuntimeError), db.write() as conn:
        _insert(conn, ip="2.2.2.2")
        raise RuntimeError("boom")

    conn = db.connect()
    assert not conn.in_transaction, "a wedged connection breaks every later write"
    assert conn.execute("SELECT count(*) FROM events").fetchone()[0] == before
    with db.write() as conn:
        _insert(conn, ip="3.3.3.3")
    assert db.connect().execute("SELECT count(*) FROM events").fetchone()[0] == before + 1


# ── durability & reset ───────────────────────────────────────────────────────
def test_data_survives_reconnect(store_db):
    with db.write() as conn:
        for _ in range(5):
            _insert(conn)
    db.close_all()
    assert db.connect().execute("SELECT count(*) FROM events").fetchone()[0] == 5
    assert repos.counters()["events"] == 5


def test_reset_reports_what_it_actually_deleted(store_db):
    with db.write() as conn:
        for _ in range(7):
            _insert(conn)
    with db.write() as conn:
        deleted = repos.reset_all(conn)
    assert deleted["events"] == 7
    assert db.connect().execute("SELECT count(*) FROM events").fetchone()[0] == 0
    assert repos.counters()["events"] == 0


# ── pragmas ──────────────────────────────────────────────────────────────────
def test_pragmas(store_db):
    conn = db.connect()
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    # 2 == INCREMENTAL. Setting auto_vacuum after the first CREATE TABLE is
    # silently ignored, so this asserts it was set at the right moment.
    assert conn.execute("PRAGMA auto_vacuum").fetchone()[0] == 2
    assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000


def test_retention_note_describes_the_real_backend(store_db):
    note = repos.retention_note()
    assert "SQLite" in note and str(repos.retention_hours()) in note
    # The string it replaced described in-memory ring buffers and would have
    # survived this change unnoticed.
    assert "ring buffer" not in note.lower()
