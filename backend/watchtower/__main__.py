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
import json
import os
import re
import sys
from pathlib import Path

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
def _read_ledger_snapshot(conn, height=None):
    """Keep verification and checkpoint lookup on the same SQLite snapshot."""
    conn.execute("BEGIN")
    try:
        result = ledger.verify(conn)
        tip = conn.execute(
            "SELECT block_id, hash FROM ledger ORDER BY block_id DESC LIMIT 1"
        ).fetchone()
        anchored = (
            conn.execute("SELECT hash FROM ledger WHERE block_id = ?", (height,)).fetchone()
            if height is not None
            else None
        )
        return result, tip, anchored
    finally:
        conn.execute("ROLLBACK")


def _load_checkpoint(path):
    with Path(path).open("rb") as source:
        data = source.read(4097)
    if len(data) > 4096:
        raise ValueError("checkpoint exceeds 4096 bytes")
    record = json.loads(data)
    if (
        not isinstance(record, dict)
        or type(record.get("version")) is not int
        or record["version"] != 1
        or type(record.get("height")) is not int
        or record["height"] < 1
        or not isinstance(record.get("hash"), str)
        or re.fullmatch(r"[0-9a-f]{64}", record["hash"]) is None
    ):
        raise ValueError("invalid checkpoint format")
    return record


def _checkpoint(args) -> int:
    result, tip, _ = _read_ledger_snapshot(db.connect())
    if tip is None:
        print("Cannot checkpoint an empty ledger.", file=sys.stderr)
        return 2
    if not result.ok:
        print("Cannot checkpoint a ledger that fails full verification.", file=sys.stderr)
        return 1
    record = {"version": 1, "height": tip["block_id"], "hash": tip["hash"]}
    # Exclusive creation and owner-only mode prevent accidental replacement or
    # disclosure. The operator must move this file outside DB-owner control.
    created = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(args.output, flags, 0o600)
        created = True
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(record, out, sort_keys=True)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
    except OSError as exc:
        if created:
            Path(args.output).unlink(missing_ok=True)
        print(f"Could not write checkpoint: {exc}", file=sys.stderr)
        return 2
    print(f"Checkpoint written: height {record['height']}, hash {record['hash']}")
    print("Keep this file outside the database owner's control.")
    return 0


def _verify(args) -> int:
    conn = db.connect()
    checkpoint = None
    if args.checkpoint:
        try:
            checkpoint = _load_checkpoint(args.checkpoint)
        except (OSError, ValueError, UnicodeError) as exc:
            print(f"Invalid checkpoint: {exc}", file=sys.stderr)
            return 2
    result, tip, anchored = _read_ledger_snapshot(
        conn, checkpoint["height"] if checkpoint else None
    )
    if checkpoint and (
        tip is None
        or tip["block_id"] < checkpoint["height"]
        or anchored is None
        or anchored["hash"] != checkpoint["hash"]
    ):
        print(
            f"❌ Checkpoint mismatch at height {checkpoint['height']}: "
            "the anchored block is missing or its hash changed."
        )
        return 1
    n = result.blocks_checked
    if n == 0:
        print("Ledger is empty — nothing to verify.")
        return 0

    if result.ok:
        print(f"✅ Chain verified — {n} blocks, every digest recomputed from the live event rows.")
        if checkpoint:
            print(f"   External checkpoint matched at height {checkpoint['height']}.")
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

    v = led.add_parser("verify", help="recompute every digest and report any tampering")
    v.add_argument("--checkpoint", help="compare with a trusted external checkpoint JSON file")
    v.set_defaults(_fn=_verify)

    cp = led.add_parser(
        "checkpoint", help="export the verified ledger tip for off-host safekeeping"
    )
    cp.add_argument(
        "--output", required=True, help="new checkpoint file; existing files are never replaced"
    )
    cp.set_defaults(_fn=_checkpoint)

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
