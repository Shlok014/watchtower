"""Tamper-evident audit ledger.

A single-writer hash chain: the data structure inside a blockchain, without the
consensus, because there is exactly one trusted writer. It is not a blockchain,
it is not distributed, and it is emphatically not Hyperledger.

What changed here, and why it matters:

The previous verification compared each block's ``prev_hash`` against its
predecessor's ``hash`` and nothing else. Both values are stored side by side in
the same row, so it checked that two stored strings matched — it never
recomputed a digest from the data it claimed to protect. Editing a log entry
passed. Editing a block's own ``log_hash`` passed. It reported
"blocks_checked: N" while checking nothing about those blocks' contents.

``verify()`` now recomputes every digest from the live ``events`` row and
distinguishes *how* the chain is broken:

    payload_mismatch  the event was edited after it was recorded
    header_mismatch   the ledger row itself was edited
    chain_break       prev_hash does not point at the previous block
    height_gap        a block was deleted outright
    pruned            the event is gone (retention), so only the stored
                      payload digest can be checked — reported, not an error

There is deliberately no proof-of-work nonce. Proof-of-work exists to make
*consensus* expensive among mutually distrusting writers; with one trusted
writer it would burn CPU to prove nothing. The old block carried a
``random.randint`` "nonce" that was never even an input to the digest.
"""

import hashlib
import json
from dataclasses import dataclass, field

# The exact serialisation, named so it can be reproduced. json.dumps defaults to
# ensure_ascii=True and ', ' / ': ' separators — "utf8 json" would not be enough
# to reproduce a single byte, and a digest you cannot reproduce is not evidence.
CANON_V1 = "py-json-sortkeys-ensureascii-defaultsep-v1"
CANON_V2 = "py-json-sortkeys-ensureascii-defaultsep-v2"
CANON_V3 = "py-json-sortkeys-ensureascii-defaultsep-v3"
PAYLOAD_CANON = CANON_V3

# Pinned field tuples. Hashing the whole dict would break every historical
# digest the moment a field is added to events — which is exactly what would
# have happened when `geo` was replaced by `reputation`.
# ts_ms, not the ISO string: the digest must cover the value as *stored*.
# Hashing the ISO form at append and reconstructing it from milliseconds at
# verify loses sub-millisecond precision, so every digest mismatches and the
# whole chain reports as tampered. That bug is invisible until verification
# actually recomputes something — which the previous implementation never did.
_V1_FIELDS = (
    "id",
    "ts_ms",
    "source",
    "event",
    "event_type",
    "severity",
    "ip",
    "user",
    "message",
    "log_format",
    "origin",
)

# v2 adds `dropped`. It has to be inside the digest: it is the record of which
# events a response action suppressed, and in a system whose selling point is
# that enforcement is real, "which traffic was silenced" is exactly the field
# worth protecting. Left outside, flipping dropped 1 → 0 with raw SQL would
# rewrite the enforcement history and `verify` would still report a clean chain.
_V2_FIELDS = (*_V1_FIELDS, "dropped")
_V3_FIELDS = (*_V2_FIELDS, "transport_peer_ip")

CANON_FIELDS_BY_VERSION = {CANON_V1: _V1_FIELDS, CANON_V2: _V2_FIELDS, CANON_V3: _V3_FIELDS}
# Kept as the current tuple for callers that just want "the fields".
CANON_FIELDS = _V3_FIELDS

GENESIS_PREV = "0" * 64


class UnknownCanon(ValueError):
    """A block records a serialisation this build cannot reproduce."""


def canonical(event: dict, canon: str = PAYLOAD_CANON) -> str:
    """Serialise an event to the exact bytes that get hashed.

    ``canon`` selects the field tuple. This is why the ledger row stores the
    name: a block written under v1 must go on verifying under v1 forever, or
    adding one field to the schema retroactively accuses every historical block
    of being tampered with — a false alarm that is indistinguishable, to anyone
    reading the output, from a real one.
    """
    fields = CANON_FIELDS_BY_VERSION.get(canon)
    if fields is None:
        raise UnknownCanon(canon)
    return json.dumps({k: _coerce(k, event.get(k)) for k in fields}, sort_keys=True, default=str)


# Fields whose Python type at append differs from their SQLite type at verify.
# `dropped` arrives as a bool on the way in and comes back as 0/1 — and
# json.dumps writes `true` for one and `0` for the other, so every block would
# fail verification with a payload_mismatch that names tampering nobody did.
_INT_FLAGS = frozenset({"dropped"})


def _coerce(key: str, value):
    if key in _INT_FLAGS:
        return int(bool(value))
    return value


def payload_hash(event: dict, canon: str = PAYLOAD_CANON) -> str:
    return hashlib.sha256(canonical(event, canon).encode()).hexdigest()


def block_hash(height: int, ts_ms: int, prev_hash: str, payload_digest: str) -> str:
    """Digest over the block header.

    Height and timestamp are inside the digest, so renumbering or back-dating a
    block breaks it. Under the old scheme the digest covered only
    prev_hash + payload, leaving both fields freely editable.
    """
    return hashlib.sha256(f"{height}|{ts_ms}|{prev_hash}|{payload_digest}".encode()).hexdigest()


@dataclass
class Finding:
    height: int
    block_id: int
    reason: str
    detail: str


@dataclass
class VerifyResult:
    ok: bool
    blocks_checked: int
    findings: list = field(default_factory=list)
    pruned: int = 0
    first_bad_height: int | None = None
    content_hashes_recomputed: bool = True

    def as_dict(self) -> dict:
        return {
            "check": "full_verification",
            "ok": self.ok,
            "blocks_checked": self.blocks_checked,
            "content_hashes_recomputed": True,
            "pruned_events": self.pruned,
            "first_bad_height": self.first_bad_height,
            "findings": [
                {
                    "height": f.height,
                    "block_id": f.block_id,
                    "reason": f.reason,
                    "detail": f.detail,
                }
                for f in self.findings
            ],
        }


def verify(conn, page: int = 500) -> VerifyResult:
    """Recompute the whole chain from the live event rows.

    Reads in pages so a long chain does not materialise in memory, and uses only
    SELECTs so it never blocks the writer under WAL.
    """
    result = VerifyResult(ok=True, blocks_checked=0)
    prev_hash = GENESIS_PREV
    expected_height = 1
    last_id = 0

    while True:
        rows = conn.execute(
            """SELECT l.block_id, l.ts_ms, l.event_id, l.payload_json, l.payload_canon,
                      l.log_hash, l.prev_hash, l.hash,
                      e.id AS e_id, e.ts_ms AS e_ts_ms, e.source, e.event, e.event_type,
                      e.severity, e.ip, e.transport_peer_ip, e.user, e.message,
                      e.log_format, e.origin, e.dropped
               FROM ledger l
               LEFT JOIN events e ON e.id = l.event_id
               WHERE l.block_id > ?
               ORDER BY l.block_id LIMIT ?""",
            (last_id, page),
        ).fetchall()
        if not rows:
            break

        for r in rows:
            last_id = r["block_id"]
            result.blocks_checked += 1
            height = result.blocks_checked

            # 1. A block that vanished leaves a gap in the sequence.
            if r["block_id"] != expected_height:
                _fail(
                    result,
                    height,
                    r["block_id"],
                    "height_gap",
                    f"expected block_id {expected_height}, found {r['block_id']} — "
                    "a block was deleted",
                )
                expected_height = r["block_id"]
            expected_height += 1

            # 2. Recompute the payload digest from the live event row. This is
            #    the check the old implementation never performed.
            if r["e_id"] is None:
                # Retention removed the event. Only the stored preimage remains,
                # so verify that against the recorded digest and say so.
                result.pruned += 1
                recomputed = hashlib.sha256(r["payload_json"].encode()).hexdigest()
            else:
                live = {
                    "id": r["e_id"],
                    "ts_ms": r["e_ts_ms"],
                    "source": r["source"],
                    "event": r["event"],
                    "event_type": r["event_type"],
                    "severity": r["severity"],
                    "ip": r["ip"],
                    "transport_peer_ip": r["transport_peer_ip"],
                    "user": r["user"],
                    "message": r["message"],
                    "log_format": r["log_format"],
                    "origin": r["origin"],
                    "dropped": r["dropped"],
                }
                # Each block is recomputed under the serialisation IT records,
                # not under the current one. Otherwise adding a single field
                # would retroactively accuse every older block of tampering —
                # a false alarm indistinguishable, in the output, from a real
                # one, which would make the whole check worthless.
                try:
                    recomputed = payload_hash(live, r["payload_canon"])
                except UnknownCanon:
                    _fail(
                        result,
                        height,
                        r["block_id"],
                        "unknown_canon",
                        f"block records serialisation {r['payload_canon']!r}, which this "
                        "build cannot reproduce — its digest can be neither confirmed "
                        "nor refuted",
                    )
                    prev_hash = r["hash"]
                    continue

            if recomputed != r["log_hash"]:
                _fail(
                    result,
                    height,
                    r["block_id"],
                    "payload_mismatch",
                    f"event {r['event_id']} was modified after it was recorded "
                    f"(stored {r['log_hash'][:12]}…, recomputed {recomputed[:12]}…)",
                )

            # 3. Recompute the block header digest.
            expected_hash = block_hash(r["block_id"], r["ts_ms"], r["prev_hash"], r["log_hash"])
            if expected_hash != r["hash"]:
                _fail(
                    result,
                    height,
                    r["block_id"],
                    "header_mismatch",
                    f"ledger row was modified (stored {r['hash'][:12]}…, "
                    f"recomputed {expected_hash[:12]}…)",
                )

            # 4. Link continuity — the only thing the old check did.
            if r["prev_hash"] != prev_hash:
                _fail(
                    result,
                    height,
                    r["block_id"],
                    "chain_break",
                    f"prev_hash {r['prev_hash'][:12]}… does not match the previous "
                    f"block's hash {prev_hash[:12]}…",
                )
            prev_hash = r["hash"]

        if len(rows) < page:
            break

    return result


def _fail(result: VerifyResult, height: int, block_id: int, reason: str, detail: str) -> None:
    result.ok = False
    if result.first_bad_height is None:
        result.first_bad_height = height
    result.findings.append(Finding(height, block_id, reason, detail))


def append(conn, event: dict, event_id: int, event_ts_ms: int, ts_ms: int) -> dict:
    """Append one event to the chain and return the new block.

    event_ts_ms is the value stored in events.ts_ms; ts_ms is when the block was
    appended. Both are hashed, so back-dating either breaks the digest.
    """
    payload = {**event, "id": event_id, "ts_ms": event_ts_ms}
    digest = payload_hash(payload)
    row = conn.execute("SELECT hash FROM ledger ORDER BY block_id DESC LIMIT 1").fetchone()
    prev = row["hash"] if row else GENESIS_PREV

    # block_id is allocated by the table, so the header digest cannot be
    # computed until after the insert. Insert with a placeholder, then fill in
    # the real digest inside the same transaction.
    cur = conn.execute(
        """INSERT INTO ledger (ts_ms, event_id, payload_json, payload_canon,
                               log_hash, prev_hash, hash)
           VALUES (?,?,?,?,?,?,'')""",
        (ts_ms, event_id, canonical(payload), PAYLOAD_CANON, digest, prev),
    )
    block_id = cur.lastrowid
    h = block_hash(block_id, ts_ms, prev, digest)
    conn.execute("UPDATE ledger SET hash = ? WHERE block_id = ?", (h, block_id))
    return {
        "block_id": block_id,
        "ts_ms": ts_ms,
        "log_id": event_id,
        "log_hash": digest,
        "prev_hash": prev,
        "hash": h,
    }
