"""Tests for the tamper-evident ledger.

Each mutation below is applied with raw SQL, bypassing the application, because
anything routed through the app would re-chain the block and there would be
nothing to detect.
"""

import pytest

import ledger
from store import db, repos


@pytest.fixture()
def chain(tmp_path):
    db.configure(tmp_path / "t.db")
    conn = db.connect()
    ids = []
    with db.write() as w:
        for i in range(20):
            ts = repos.now_ms() + i
            event = {
                "ts_ms": ts,
                "source": "linux-server",
                "event": "failed_login",
                "event_type": "authentication",
                "severity": "medium",
                "ip": f"10.0.0.{i}",
                "user": "root",
                "message": f"event {i}",
                "log_format": "syslog",
                "origin": "synthetic",
            }
            eid = w.execute(
                """INSERT INTO events (ts_ms,ingested_ts_ms,source,event,event_type,severity,
                                       ip,user,message,log_format,origin,rep_verdict,
                                       rep_score,rep_sources,rep_checked,rep_detail)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,'unlisted',0,'[]',1,'')""",
                (ts, ts, event["source"], event["event"], event["event_type"],
                 event["severity"], event["ip"], event["user"], event["message"],
                 event["log_format"], event["origin"]),
            ).lastrowid
            ledger.append(w, event, eid, ts, ts)
            ids.append(eid)
    yield conn, ids
    db.close_all()


def test_clean_chain_verifies(chain):
    conn, _ = chain
    r = ledger.verify(conn)
    assert r.ok, [f.detail for f in r.findings]
    assert r.blocks_checked == 20
    assert r.findings == []


def test_heights_are_monotonic_past_any_cap(tmp_path):
    """Regression for the original bug: block_id was len(list)+1 over a list
    capped at 500 that popped from the front, so every block past the cap was
    id 501 forever. 600 appends must yield 600 distinct, contiguous ids."""
    db.configure(tmp_path / "big.db")
    with db.write() as w:
        for i in range(600):
            ledger.append(w, {"message": str(i), "origin": "synthetic"}, None, i, i)
    rows = [r[0] for r in db.connect().execute("SELECT block_id FROM ledger ORDER BY block_id")]
    assert len(rows) == 600
    assert len(set(rows)) == 600
    assert rows == list(range(1, 601))
    db.close_all()


def test_editing_an_event_is_detected(chain):
    conn, ids = chain
    with db.write() as w:
        w.execute("UPDATE events SET message = ? WHERE id = ?", ("nothing happened", ids[6]))
    r = ledger.verify(conn)
    assert not r.ok
    assert len(r.findings) == 1
    assert r.findings[0].reason == "payload_mismatch"
    assert r.findings[0].height == 7
    assert r.first_bad_height == 7


@pytest.mark.parametrize("column", ["ip", "user", "severity", "origin"])
def test_editing_any_hashed_column_is_detected(chain, column):
    conn, ids = chain
    new = {"ip": "1.2.3.4", "user": "mallory", "severity": "low", "origin": "syslog"}[column]
    with db.write() as w:
        w.execute(f"UPDATE events SET {column} = ? WHERE id = ?", (new, ids[3]))
    r = ledger.verify(conn)
    assert not r.ok
    assert any(f.reason == "payload_mismatch" for f in r.findings)


def test_editing_the_ledger_row_is_detected(chain):
    """Rewriting a block's own stored digest must not launder the edit."""
    conn, ids = chain
    with db.write() as w:
        # Make the event edit AND update the block's payload digest to match —
        # the old link-only check passed exactly this.
        w.execute("UPDATE events SET message = ? WHERE id = ?", ("forged", ids[4]))
        forged = ledger.payload_hash(
            {
                **dict(conn.execute("SELECT * FROM events WHERE id = ?", (ids[4],)).fetchone()),
                "message": "forged",
            }
        )
        w.execute("UPDATE ledger SET log_hash = ? WHERE block_id = ?", (forged, 5))
    r = ledger.verify(conn)
    assert not r.ok
    # The header digest covers log_hash, so rewriting it breaks the header.
    assert any(f.reason == "header_mismatch" for f in r.findings)


def test_deleting_a_block_is_detected(chain):
    conn, _ = chain
    with db.write() as w:
        w.execute("DELETE FROM ledger WHERE block_id = 10")
    r = ledger.verify(conn)
    assert not r.ok
    assert any(f.reason == "height_gap" for f in r.findings)
    assert any(f.reason == "chain_break" for f in r.findings)


def test_backdating_a_block_is_detected(chain):
    """ts_ms is inside the header digest, so back-dating breaks it."""
    conn, _ = chain
    with db.write() as w:
        w.execute("UPDATE ledger SET ts_ms = 0 WHERE block_id = 8")
    r = ledger.verify(conn)
    assert not r.ok
    assert any(f.reason == "header_mismatch" and f.block_id == 8 for f in r.findings)


def test_pruned_events_are_reported_not_flagged(chain):
    """Retention removing an event is not tampering.

    The stored preimage is still checked against the recorded digest, and the
    block is counted as pruned rather than reported as a mismatch.
    """
    conn, ids = chain
    with db.write() as w:
        w.execute("DELETE FROM events WHERE id = ?", (ids[2],))
    r = ledger.verify(conn)
    assert r.pruned == 1
    assert r.ok, [f.detail for f in r.findings]


def test_canonical_form_is_stable_across_field_additions(chain):
    """Adding a field to an event must not invalidate historical digests."""
    conn, _ = chain
    before = ledger.payload_hash({"id": 1, "ts_ms": 5, "message": "x", "origin": "synthetic"})
    after = ledger.payload_hash(
        {"id": 1, "ts_ms": 5, "message": "x", "origin": "synthetic", "brand_new_field": "zzz"}
    )
    assert before == after
