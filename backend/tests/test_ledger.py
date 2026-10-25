"""Tests for the tamper-evident ledger.

Each mutation below is applied with raw SQL, bypassing the application, because
anything routed through the app would re-chain the block and there would be
nothing to detect.
"""

import pytest

from watchtower import ledger
from watchtower.store import db, repos


DAY_MS = 24 * 3600 * 1000


def _seed(age_ms=0, n=20):
    """Chain n events ingested age_ms ago, exactly as the consumer would."""
    ids = []
    with db.write() as w:
        for i in range(n):
            ts = repos.now_ms() - age_ms + i
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
                (
                    ts,
                    ts,
                    event["source"],
                    event["event"],
                    event["event_type"],
                    event["severity"],
                    event["ip"],
                    event["user"],
                    event["message"],
                    event["log_format"],
                    event["origin"],
                ),
            ).lastrowid
            ledger.append(w, event, eid, ts, ts)
            ids.append(eid)
    return ids


def _cite(event_id):
    with db.write() as w:
        w.execute(
            """INSERT INTO alerts (event_id,ts_ms,event,source,ip,user,severity,anomaly_score,
                                   ruleset_version,explanation,features_json,reasons_json,
                                   reputation_json,status)
               VALUES (?,0,'e','s','9.9.9.9','u','low',0.9,'r','x','{}','[]','{}','open')""",
            (event_id,),
        )


@pytest.fixture()
def chain(tmp_path):
    db.configure(tmp_path / "t.db")
    conn = db.connect()
    yield conn, _seed()
    db.close_all()


@pytest.fixture()
def old_chain(tmp_path):
    """Twenty events ingested two days ago: past the default 24h retention."""
    db.configure(tmp_path / "old.db")
    conn = db.connect()
    yield conn, _seed(age_ms=2 * DAY_MS)
    db.close_all()


def test_clean_chain_verifies(chain):
    conn, _ = chain
    r = ledger.verify(conn)
    assert r.ok, [f.detail for f in r.findings]
    assert r.blocks_checked == 20
    assert r.findings == []
    assert r.as_dict()["completeness_verified"] is False


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


def test_retention_prune_is_reported_not_flagged(old_chain):
    """Retention removing an event is not tampering.

    The sweep records what it removed in a hashed prune block, the stored
    preimage is still checked against the recorded digest, and the block is
    counted as pruned rather than reported as a mismatch.
    """
    conn, ids = old_chain
    _cite(ids[5])
    with db.write() as w:
        assert repos.prune(w, hours=24) == 19
    r = ledger.verify(conn)
    assert r.ok, [f.detail for f in r.findings]
    assert r.pruned == 19
    assert r.blocks_checked == 21, "the prune record is itself a chained block"


def test_deleting_a_recent_event_is_detected(chain):
    """Retention never removes an event newer than its cutoff, so a missing
    recent event is a deletion, not a prune. It used to verify as `pruned`."""
    conn, ids = chain
    with db.write() as w:
        w.execute("DELETE FROM events WHERE id = ?", (ids[2],))
    r = ledger.verify(conn)
    assert not r.ok
    assert [(f.reason, f.height) for f in r.findings] == [("unrecorded_deletion", 3)]


def test_deleting_an_alert_cited_event_is_detected(old_chain):
    """Old enough to prune, but an alert cites it, so retention keeps it.

    alerts.event_id is ON DELETE SET NULL, so the deletion also erases the
    alert's link to it: nothing at verify time could tell that it was cited.
    Only a record of what retention actually removed can.
    """
    conn, ids = old_chain
    _cite(ids[4])
    with db.write() as w:
        repos.prune(w, hours=24)
        w.execute("DELETE FROM events WHERE id = ?", (ids[4],))
    r = ledger.verify(conn)
    assert not r.ok
    assert [(f.reason, f.height) for f in r.findings] == [("unrecorded_deletion", 5)]


def test_repointing_a_block_at_a_pruned_event_is_detected(old_chain):
    """event_id is outside the header digest. Pointing a block at an event that
    retention really did remove must not let it pass as pruned."""
    conn, ids = old_chain
    _cite(ids[7])
    with db.write() as w:
        repos.prune(w, hours=24)
        w.execute("UPDATE ledger SET event_id = ? WHERE event_id = ?", (ids[3], ids[7]))
    r = ledger.verify(conn)
    assert not r.ok
    assert any(f.reason == "unrecorded_deletion" and f.height == 8 for f in r.findings)


def test_reset_is_recorded_not_reported_clean(chain):
    """/reset erases the ledger through the application. It used to leave an
    empty chain that verified exactly like a clean one."""
    conn, _ = chain
    with db.write() as w:
        repos.reset_all(w)
    result = ledger.verify(conn).as_dict()
    assert result["status"] == "reset"
    assert result["reset_at_ms"] is not None
    assert result["blocks_erased_by_reset"] == 20


def test_reset_record_cannot_be_edited(chain):
    conn, _ = chain
    with db.write() as w:
        repos.reset_all(w)
        w.execute("UPDATE ledger SET payload_json = replace(payload_json, '20', '0')")
    assert ledger.verify(conn).as_dict()["status"] == "tampered"


def test_canonical_form_is_stable_across_field_additions(chain):
    """Adding a field to an event must not invalidate historical digests."""
    conn, _ = chain
    before = ledger.payload_hash({"id": 1, "ts_ms": 5, "message": "x", "origin": "synthetic"})
    after = ledger.payload_hash(
        {"id": 1, "ts_ms": 5, "message": "x", "origin": "synthetic", "brand_new_field": "zzz"}
    )
    assert before == after
