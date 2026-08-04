"""Watchtower command line.

    python -m watchtower run
    python -m watchtower config
    python -m watchtower ledger verify
    python -m watchtower ledger tamper --event-id 42 --field message --value "nothing happened"
    python -m watchtower ledger show --limit 5

The tamper command exists to prove the ledger actually detects tampering. It
performs a raw SQL UPDATE that bypasses the application entirely — which is the
only honest way to demonstrate the property, because anything routed through the
app would re-chain the block and detect nothing.
"""

import argparse
import sys

from . import config, ledger
from .store import db, repos


# ─── run ──────────────────────────────────────────────────────────────────────
def _run(args) -> int:
    from .app import create_app, startup_banner

    if args.sources is not None:
        config.replace(sources=tuple(s.strip() for s in args.sources.split(",") if s.strip()))
    if args.port is not None:
        config.replace(port=args.port)
    if args.host is not None:
        config.replace(host=args.host)

    cfg = config.get()
    try:
        app = create_app()
    except Exception as exc:
        print(f"❌ {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(startup_banner())
    app.run(debug=False, host=cfg.host, port=cfg.port)
    return 0


def _config(args) -> int:
    cfg = config.get()
    print(f"  data_dir         {cfg.data_dir}")
    print(f"  db_path          {cfg.db_path}")
    print(f"  retention_hours  {cfg.retention_hours}")
    print(f"  alert_threshold  {cfg.alert_threshold}")
    print(f"  sources          {', '.join(cfg.sources) or '(none)'}")
    print(f"  cors_origins     {', '.join(cfg.cors_origins) or '(none)'}")
    print(f"  bind             {cfg.host}:{cfg.port}")
    return 0


# ─── ledger ───────────────────────────────────────────────────────────────────
def _verify(args) -> int:
    conn = db.connect()
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
    conn = db.connect()
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
    with db.write() as w:
        w.execute(f"UPDATE events SET {args.field} = ? WHERE id = ?", (args.value, args.event_id))
    print("\nDone. Now run:  python -m watchtower ledger verify")
    return 0


def _show(args) -> int:
    rows = repos.recent_blocks(args.limit)
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


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="watchtower", description="Watchtower CLI")
    ap.add_argument("--db", help="path to the database file")
    sub = ap.add_subparsers(dest="group", required=True)

    run = sub.add_parser(
        "run",
        help="start the API and the configured sources",
        epilog=(
            "sources: synthetic | syslog[:port] | file:<path> | "
            "replay:<hdfs|openssh>[@events-per-second]\n"
            "example: --sources synthetic,syslog,file:/var/log/system.log,replay:hdfs@25"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    run.add_argument(
        "--sources",
        help="comma-separated source list; see the examples at the end of --help",
    )
    run.add_argument("--port", type=int)
    run.add_argument("--host")
    run.set_defaults(_fn=_run)

    sub.add_parser("config", help="print the resolved configuration").set_defaults(_fn=_config)

    led = sub.add_parser("ledger", help="audit ledger operations").add_subparsers(
        dest="cmd", required=True
    )

    led.add_parser("verify", help="recompute every digest and report any tampering").set_defaults(
        _fn=_verify
    )

    t = led.add_parser("tamper", help="deliberately corrupt one event, to demonstrate detection")
    t.add_argument("--event-id", type=int, required=True)
    t.add_argument(
        "--field",
        default="message",
        choices=["message", "ip", "user", "severity", "event", "source", "origin"],
        help="which column to modify",
    )
    t.add_argument("--value", required=True)
    t.set_defaults(_fn=_tamper)

    sh = led.add_parser("show", help="list recent blocks")
    sh.add_argument("--limit", type=int, default=10)
    sh.set_defaults(_fn=_show)

    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.db:
        db.configure(args.db)
    return args._fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
