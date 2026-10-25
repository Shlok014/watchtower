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
    height_gap        an interior block was deleted; a missing final block
                      requires an external checkpoint to detect
    pruned            the event is gone and a prune record says retention
                      removed it, so only the stored payload digest can be
                      checked — reported, not an error
    unrecorded_deletion
                      the event is gone and no prune record covers it: it was
                      deleted outside retention (recent, alert-cited, or the
                      block was repointed at an event that was pruned)

Retention and /reset are the two in-app paths that delete what the chain
covers. Each appends a record block saying what it removed, so verification
can tell a sweep from a deletion and a reset from a clean chain. Those blocks
are hash-chained like any other: editing one breaks its digest.

There is deliberately no proof-of-work nonce. Proof-of-work exists to make
*consensus* expensive among mutually distrusting writers; with one trusted
writer it would burn CPU to prove nothing. The old block carried a
``random.randint`` "nonce" that was never even an input to the digest.
"""

import bisect
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

# Record blocks: no event_id, and payload_canon names the record kind. The
# preimage is the JSON itself, hashed exactly like a pruned event's.
PRUNE_CANON = "watchtower-prune-v1"
RESET_CANON = "watchtower-reset-v1"


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
    reset_at_ms: int | None = None
    blocks_erased_by_reset: int = 0

    @property
    def status(self) -> str:
        if not self.ok:
            return "tampered"
        return "reset" if self.reset_at_ms is not None else "clean"

    def as_dict(self) -> dict:
        return {
            "check": "full_verification",
            "ok": self.ok,
            # "reset" is not tampering, but it is not a clean history either:
            # every block before the reset was erased through the application.
            "status": self.status,
            "reset_at_ms": self.reset_at_ms,
            "blocks_erased_by_reset": self.blocks_erased_by_reset,
            # Hashes prove only the rows still present. A missing suffix has no
            # successor link to expose it without an independently kept tip.
            "completeness_verified": False,
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
    pruned_by = _prune_records(conn)
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
                # Only the stored preimage remains, so verify that against the
                # recorded digest. Whether the event is legitimately gone is a
                # separate question, answered by the prune records.
                recomputed = hashlib.sha256(r["payload_json"].encode()).hexdigest()
                record = _record(r["payload_json"])
                cutoff = pruned_by(r["event_id"])
                if r["event_id"] is None and record.get("id") is None:
                    # A prune or reset record, or a block chained with no event.
                    if r["payload_canon"] == RESET_CANON and record.get("kind") == "reset":
                        result.reset_at_ms = r["ts_ms"]
                        result.blocks_erased_by_reset += int(record.get("blocks_erased") or 0)
                elif (
                    cutoff is not None
                    and r["ts_ms"] < cutoff
                    # event_id is outside the header digest, so the preimage's
                    # own id must agree with it, or repointing a block at an
                    # event retention really did remove would launder it.
                    and record.get("id") == r["event_id"]
                ):
                    result.pruned += 1
                else:
                    _fail(
                        result,
                        height,
                        r["block_id"],
                        "unrecorded_deletion",
                        f"event {r['event_id']} is missing and no retention sweep "
                        "recorded removing it — it was deleted, not pruned",
                    )
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


def _record(payload_json: str) -> dict:
    try:
        record = json.loads(payload_json)
    except ValueError:
        return {}
    return record if isinstance(record, dict) else {}


def _prune_records(conn):
    """Return a lookup: event_id -> the retention cutoff under which a sweep
    recorded removing it, or None.

    An edited record still has to verify as a block in the main pass, so
    trusting its contents here costs nothing: an edited one fails there.
    Kept as id ranges, because the ledger never forgets a sweep.
    """
    ranges = []
    for row in conn.execute(
        "SELECT payload_json FROM ledger WHERE payload_canon = ? AND event_id IS NULL",
        (PRUNE_CANON,),
    ):
        record = _record(row["payload_json"])
        cutoff = record.get("cutoff_ms")
        if record.get("kind") == "prune" and type(cutoff) is int:
            ranges += [
                (span[0], span[1], cutoff)
                for span in record.get("event_ids") or []
                if isinstance(span, list) and len(span) == 2
            ]
    ranges.sort()
    starts = [lo for lo, _, _ in ranges]

    def lookup(event_id):
        if event_id is None:
            return None
        i = bisect.bisect_right(starts, event_id) - 1
        if i >= 0 and ranges[i][0] <= event_id <= ranges[i][1]:
            return ranges[i][2]
        return None

    return lookup


def _fail(result: VerifyResult, height: int, block_id: int, reason: str, detail: str) -> None:
    result.ok = False
    if result.first_bad_height is None:
        result.first_bad_height = height
    result.findings.append(Finding(height, block_id, reason, detail))


def _append_block(conn, ts_ms: int, event_id, payload_json: str, canon: str, digest: str) -> dict:
    row = conn.execute("SELECT hash FROM ledger ORDER BY block_id DESC LIMIT 1").fetchone()
    prev = row["hash"] if row else GENESIS_PREV

    # block_id is allocated by the table, so the header digest cannot be
    # computed until after the insert. Insert with a placeholder, then fill in
    # the real digest inside the same transaction.
    cur = conn.execute(
        """INSERT INTO ledger (ts_ms, event_id, payload_json, payload_canon,
                               log_hash, prev_hash, hash)
           VALUES (?,?,?,?,?,?,'')""",
        (ts_ms, event_id, payload_json, canon, digest, prev),
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


def append_record(conn, canon: str, record: dict, ts_ms: int) -> dict:
    """Chain a prune or reset record. Call inside the deleting transaction."""
    payload_json = json.dumps(record, sort_keys=True)
    digest = hashlib.sha256(payload_json.encode()).hexdigest()
    return _append_block(conn, ts_ms, None, payload_json, canon, digest)


def id_ranges(ids) -> list:
    """[3, 4, 5, 9] -> [[3, 5], [9, 9]]: a sweep removes mostly contiguous ids."""
    ranges = []
    for i in sorted(ids):
        if ranges and i == ranges[-1][1] + 1:
            ranges[-1][1] = i
        else:
            ranges.append([i, i])
    return ranges


def append(conn, event: dict, event_id: int, event_ts_ms: int, ts_ms: int) -> dict:
    """Append one event to the chain and return the new block.

    event_ts_ms is the value stored in events.ts_ms; ts_ms is when the block was
    appended. Both are hashed, so back-dating either breaks the digest.
    """
    payload = {**event, "id": event_id, "ts_ms": event_ts_ms}
    return _append_block(
        conn, ts_ms, event_id, canonical(payload), PAYLOAD_CANON, payload_hash(payload)
    )
