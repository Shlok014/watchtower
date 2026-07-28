"""Watchtower command line.

    python -m cli ledger verify
    python -m cli ledger tamper --event-id 42 --field message --value "nothing happened"
    python -m cli ledger show --limit 5

The tamper command exists to prove the ledger actually detects tampering. It
performs a raw SQL UPDATE that bypasses the application entirely — which is the
only honest way to demonstrate the property, because anything routed through the
app would re-chain the block and detect nothing.
"""

import argparse
import sys

import ledger
import store


def _verify(args) -> int:
    conn = store.db.connect()
    result = ledger.verify(conn)
    n = result.blocks_checked
    if n == 0:
        print("Ledger is empty — nothing to verify.")
        return 0

    if result.ok:
        print(f"✅ Chain verified — {n} blocks, every digest recomputed from the live event rows.")
        if result.pruned:
            print(
                f"   {result.pruned} block(s) reference events removed by retention; those "
                "were checked against the stored preimage."
            )
        return 0

    print(f"❌ TAMPER DETECTED — {len(result.findings)} finding(s) across {n} blocks.\n")
    for f in result.findings:
        print(f"  height {f.height} (block {f.block_id}): {f.reason}")
        print(f"    {f.detail}")
    print(f"\nFirst bad height: {result.first_bad_height}")
    return 1


def _tamper(args) -> int:
    conn = store.db.connect()
    row = conn.execute(
        f"SELECT id, {args.field} FROM events WHERE id = ?", (args.event_id,)
    ).fetchone()
    if row is None:
        print(f"No event with id {args.event_id}.", file=sys.stderr)
        return 2

    old = row[args.field]
    print("This performs a RAW SQL UPDATE, bypassing the application layer.")
    print("Nothing re-chains the block — that is the point of the demonstration.\n")
    print(f"  event {args.event_id}.{args.field}")
    print(f"    before: {old!r}")
    print(f"    after:  {args.value!r}")
    with store.write() as w:
        w.execute(f"UPDATE events SET {args.field} = ? WHERE id = ?", (args.value, args.event_id))
    print("\nDone. Now run:  python -m cli ledger verify")
    return 0


def _show(args) -> int:
    rows = store.repos.recent_blocks(args.limit)
    if not rows:
        print("Ledger is empty.")
        return 0
    for b in rows:
        print(
            f"  block {b['block_id']:>6}  event {str(b['log_id']):>6}  "
            f"payload {b['log_hash'][:12]}…  prev {b['prev_hash'][:12]}…  "
            f"hash {b['hash'][:12]}…"
        )
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="watchtower", description="Watchtower CLI")
    ap.add_argument("--db", help="path to the database file")
    sub = ap.add_subparsers(dest="group", required=True)

    led = sub.add_parser("ledger", help="audit ledger operations").add_subparsers(
        dest="cmd", required=True
    )

    led.add_parser("verify", help="recompute every digest and report any tampering")

    t = led.add_parser("tamper", help="deliberately corrupt one event, to demonstrate detection")
    t.add_argument("--event-id", type=int, required=True)
    t.add_argument(
        "--field",
        default="message",
        choices=["message", "ip", "user", "severity", "event", "source", "origin"],
        help="which column to modify",
    )
    t.add_argument("--value", required=True)

    sh = led.add_parser("show", help="list recent blocks")
    sh.add_argument("--limit", type=int, default=10)

    args = ap.parse_args(argv)
    if args.db:
        store.db.configure(args.db)

    return {"verify": _verify, "tamper": _tamper, "show": _show}[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
