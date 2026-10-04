"""An off-host checkpoint detects a database owner's consistent chain rewrite."""

import hashlib
import json
import stat

from watchtower import ledger
from watchtower.__main__ import main
from watchtower.store import db


def _database(tmp_path):
    path = tmp_path / "events.db"
    db.configure(path)
    with db.write() as conn:
        for height in range(1, 4):
            ledger.append(conn, {"message": f"event {height}"}, None, height, height)
    return path


def _run(path, *args):
    return main(["--db", str(path), "ledger", *args])


def test_checkpoint_survives_append_but_detects_consistent_rewrite(tmp_path, capsys):
    path = _database(tmp_path)
    checkpoint = tmp_path / "off-host.json"
    assert _run(path, "checkpoint", "--output", str(checkpoint)) == 0
    saved = json.loads(checkpoint.read_text())
    assert saved["height"] == 3
    assert len(saved["hash"]) == 64
    assert stat.S_IMODE(checkpoint.stat().st_mode) == 0o600

    with db.write() as conn:
        ledger.append(conn, {"message": "later"}, None, 4, 4)
    assert _run(path, "verify", "--checkpoint", str(checkpoint)) == 0

    # The attacker controls the whole DB. Recompute all affected digests and
    # links so ordinary full-chain verification passes after the rewrite.
    with db.write() as conn:
        previous = ledger.GENESIS_PREV
        for row in conn.execute("SELECT * FROM ledger ORDER BY block_id").fetchall():
            payload = "forged" if row["block_id"] == 1 else row["payload_json"]
            digest = hashlib.sha256(payload.encode()).hexdigest()
            head = ledger.block_hash(row["block_id"], row["ts_ms"], previous, digest)
            conn.execute(
                "UPDATE ledger SET payload_json=?, log_hash=?, prev_hash=?, hash=? WHERE block_id=?",
                (payload, digest, previous, head, row["block_id"]),
            )
            previous = head
    assert ledger.verify(db.connect()).ok
    assert _run(path, "verify", "--checkpoint", str(checkpoint)) == 1
    assert "checkpoint mismatch" in capsys.readouterr().out.lower()


def test_checkpoint_detects_truncation_and_refuses_overwrite(tmp_path, capsys):
    path = _database(tmp_path)
    checkpoint = tmp_path / "off-host.json"
    assert _run(path, "checkpoint", "--output", str(checkpoint)) == 0
    original = checkpoint.read_bytes()
    assert _run(path, "checkpoint", "--output", str(checkpoint)) == 2
    assert checkpoint.read_bytes() == original
    with db.write() as conn:
        conn.execute("DELETE FROM ledger WHERE block_id = 3")
    # A local hash chain has no way to infer that its final block disappeared.
    assert _run(path, "verify") == 0
    unanchored_output = capsys.readouterr().out.lower()
    assert "present blocks" in unanchored_output
    assert "external checkpoint" in unanchored_output
    assert _run(path, "verify", "--checkpoint", str(checkpoint)) == 1
    assert "checkpoint mismatch" in capsys.readouterr().out.lower()


def test_checkpoint_refuses_dirty_or_empty_ledger(tmp_path):
    path = tmp_path / "empty.db"
    checkpoint = tmp_path / "checkpoint.json"
    assert _run(path, "checkpoint", "--output", str(checkpoint)) == 2
    assert not checkpoint.exists()
    path = _database(tmp_path)
    with db.write() as conn:
        conn.execute("UPDATE ledger SET hash='bad' WHERE block_id=2")
    assert _run(path, "checkpoint", "--output", str(checkpoint)) == 1
    assert not checkpoint.exists()


def test_invalid_checkpoint_fails_closed(tmp_path):
    path = _database(tmp_path)
    checkpoint = tmp_path / "checkpoint.json"
    checkpoint.write_text('{"height": true, "hash": "x"}')
    assert _run(path, "verify", "--checkpoint", str(checkpoint)) == 2
    checkpoint.write_text(json.dumps({"version": True, "height": 1, "hash": "a" * 64}))
    assert _run(path, "verify", "--checkpoint", str(checkpoint)) == 2
    checkpoint.write_bytes(b" " * 4097)
    assert _run(path, "verify", "--checkpoint", str(checkpoint)) == 2
