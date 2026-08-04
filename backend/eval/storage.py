"""Measure the storage and pipeline figures, and write docs/STORAGE.md.

    python -m eval.storage

The README used to carry three of these numbers hand-typed, measured once in
session 2 and never re-checked — through a blocklist lookup added ahead of
detection, the ledger moving earlier in the pipeline, `dropped` entering the
digest, and the SOAR response splitting into several transactions. Any of those
could have moved them, and one had: the write figure was understated by roughly
half.

A number that has to be remembered is a number that goes stale. This is the same
arrangement `eval.benchmark` uses for detection — the page is generated, and
`scripts/check_published_numbers.py` fails the build if the prose drifts from it.

Every figure below is wall-clock on the machine that ran it, against a temporary
database, with the environment recorded. They are not a benchmark of SQLite; they
are this pipeline's cost on this hardware, which is the only thing they claim.
"""

import json
import platform
import statistics
import sys
import tempfile
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
OUT_MD = ROOT / "docs" / "STORAGE.md"
OUT_JSON = ROOT / "docs" / "storage.json"

WRITERS = 4
PER_WRITER = 500
# The write figure moves with whatever else the machine is doing — 2,414 and
# 3,444 rows/sec on two runs minutes apart. Repeated and reported as a median,
# with the spread published, rather than quoting whichever run looked best.
WRITE_REPEATS = 3
BENIGN_EVENTS = 400
ALERTING_EVENTS = 60
STATS_SAMPLES = 50


def _raw(i: int, event: str = "normal_traffic") -> dict:
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "linux-server",
        "event": event,
        "ip": f"10.0.1.{i % 250}",
        "user": "root",
        "message": f"measurement event {i}",
        "log_format": "syslog",
        "origin": "synthetic",
    }


def _event_row(k: int, i: int) -> dict:
    ts = int(datetime.now(UTC).timestamp() * 1000)
    return {
        "ts_ms": ts,
        "ingested_ts_ms": ts,
        "timestamp": datetime.fromtimestamp(ts / 1000, UTC).isoformat(),
        "source": "linux-server",
        "event": "failed_login",
        "event_type": "authentication",
        "severity": "medium",
        "ip": f"10.0.0.{k}",
        "user": "root",
        "message": f"m{i}",
        "log_format": "syslog",
        "origin": "synthetic",
    }


def measure() -> dict:
    from watchtower import config

    # Two databases, deliberately. The ledger figure is the growth of the file
    # across a known number of blocks, and measuring it on the database the
    # write test just used gives 80 bytes/block instead of the true figure —
    # `reset_all` empties the tables but `auto_vacuum=INCREMENTAL` only returns
    # pages on request, so the new blocks land in an existing freelist and the
    # file does not grow at all. A fresh file is the only honest baseline.
    tmp = Path(tempfile.mkdtemp(prefix="watchtower-writes-"))
    config.replace(data_dir=tmp)

    from watchtower.store import db, repos

    db.configure(None)
    db.connect()

    # ── concurrent writers against a live reader ─────────────────────────────
    # The shape the original figure was measured in, kept so the two are
    # comparable: four writer threads contending for SQLite's single write lock
    # while a reader runs continuously. WAL is what makes the reader free.
    errors: list[str] = []

    def writer(k: int) -> None:
        try:
            for i in range(PER_WRITER):
                with db.write() as conn:
                    repos.insert_event(conn, _event_row(k, i), repos.now_ms())
        except Exception as exc:  # noqa: BLE001 - reported, not raised
            errors.append(f"{type(exc).__name__}: {exc}")

    def run_once() -> float:
        stop = threading.Event()

        def reader() -> None:
            while not stop.is_set():
                db.connect().execute("SELECT count(*) FROM events").fetchone()

        r = threading.Thread(target=reader, daemon=True)
        r.start()
        threads = [threading.Thread(target=writer, args=(k,)) for k in range(WRITERS)]
        t0 = time.perf_counter()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        seconds = time.perf_counter() - t0
        stop.set()
        r.join(timeout=2)
        return seconds

    rates = []
    for _ in range(WRITE_REPEATS):
        with db.write() as conn:
            repos.reset_all(conn)
        seconds = run_once()
        rates.append((WRITERS * PER_WRITER) / seconds)
    rates.sort()

    # ── the pipeline itself, on a FRESH database ─────────────────────────────
    # Not the one the write test just used: `reset_all` empties the tables but
    # `auto_vacuum=INCREMENTAL` only returns pages on request, so new blocks
    # land in the existing freelist and the file does not grow. Measured that
    # way the ledger reads 80 bytes/block instead of its real cost.
    db.close_all()
    fresh = Path(tempfile.mkdtemp(prefix="watchtower-pipeline-"))
    config.replace(data_dir=fresh)
    db.configure(None)
    db.connect()
    db.checkpoint()
    before_bytes = (fresh / "watchtower.db").stat().st_size

    from watchtower.pipeline.consumer import process_log

    t0 = time.perf_counter()
    for i in range(BENIGN_EVENTS):
        process_log(_raw(i))
    benign_seconds = time.perf_counter() - t0

    t0 = time.perf_counter()
    for i in range(ALERTING_EVENTS):
        process_log(_raw(i, "malware_detected"))
    alerting_seconds = time.perf_counter() - t0

    db.checkpoint()
    after_bytes = (fresh / "watchtower.db").stat().st_size
    blocks = db.connect().execute("SELECT count(*) FROM ledger").fetchone()[0]
    retained = db.connect().execute("SELECT count(*) FROM events").fetchone()[0]

    # ── the endpoint the dashboard polls twice a second ──────────────────────
    from watchtower.app import create_app

    app = create_app(start_sources=False)
    app.config.update(TESTING=True)
    with app.test_client() as client:
        for _ in range(5):  # warm the connection and the query planner
            client.get("/api/v1/stats")
        samples = []
        for _ in range(STATS_SAMPLES):
            t = time.perf_counter()
            client.get("/api/v1/stats")
            samples.append((time.perf_counter() - t) * 1000)

    return {
        "writes": {
            "writers": WRITERS,
            "rows": WRITERS * PER_WRITER,
            "repeats": WRITE_REPEATS,
            "rows_per_second": int(statistics.median(rates)),
            "rows_per_second_min": int(rates[0]),
            "rows_per_second_max": int(rates[-1]),
            "errors": errors,
        },
        "pipeline": {
            "benign_events": BENIGN_EVENTS,
            "benign_per_second": int(BENIGN_EVENTS / benign_seconds),
            "alerting_events": ALERTING_EVENTS,
            "alerting_per_second": int(ALERTING_EVENTS / alerting_seconds),
        },
        "stats_endpoint": {
            "samples": STATS_SAMPLES,
            "median_ms": round(statistics.median(samples), 2),
            "max_ms": round(max(samples), 2),
            "events_retained": retained,
        },
        "ledger": {
            "blocks": blocks,
            # Growth of the database file across a known number of blocks, after
            # a WAL checkpoint. Row content alone understates it by roughly half
            # — indices and page overhead are real bytes on a real disk.
            "bytes_per_block": int((after_bytes - before_bytes) / blocks) if blocks else 0,
        },
        "environment": {
            "python": sys.version.split()[0],
            "platform": f"{platform.system()} {platform.machine()}",
            "sqlite": db.connect().execute("SELECT sqlite_version()").fetchone()[0],
            "measured_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
    }


def write_markdown(r: dict) -> None:
    w, p, s, led, env = (
        r["writes"],
        r["pipeline"],
        r["stats_endpoint"],
        r["ledger"],
        r["environment"],
    )
    per_day = led["bytes_per_block"] * 25 * 86400 / 1024 / 1024 / 1024
    lines = [
        "# Storage and pipeline cost",
        "",
        "Generated by `python -m eval.storage` (`make perf`). Every number here is",
        "produced by that command — none is typed by hand.",
        "",
        "These are wall-clock measurements of *this pipeline on this hardware*. They",
        "are not a benchmark of SQLite, and they do not generalise to other machines.",
        "",
        "| | |",
        "|---|---|",
        f"| Concurrent writes | **{w['rows_per_second']:,} rows/sec** median of "
        f"{w['repeats']} runs ({w['rows_per_second_min']:,}–{w['rows_per_second_max']:,}) — "
        f"{w['writers']} writer threads against a live reader, {w['rows']:,} rows each, "
        f"**{len(w['errors'])} `database is locked`** |",
        f"| Pipeline, benign event | **{p['benign_per_second']:,} events/sec** — "
        "normalize, blocklist check, insert, ledger append, detect |",
        f"| Pipeline, alerting event | **{p['alerting_per_second']:,} events/sec** — "
        "the above plus the alert, the playbook, and its own transactions |",
        f"| `GET /api/v1/stats` | **{s['median_ms']} ms** median over {s['samples']} "
        f"calls ({s['max_ms']} ms max) at {s['events_retained']:,} events retained |",
        f"| Ledger growth | **{led['bytes_per_block']:,} bytes/block** over "
        f"{led['blocks']:,} blocks — about **{per_day:.1f} GB/day** at a 25 ev/s replay |",
        "",
        "### Reading these honestly",
        "",
        "- **The alerting path is an order of magnitude slower than the benign one,**",
        "  and that is the design working rather than a regression. The response runs",
        "  after the ingest transaction commits, writing its execution row before the",
        "  first action can have an effect and each step as it completes. That is",
        "  several transactions where a single one would be faster — and a single one",
        "  is what let a slow webhook hold the write lock, and what let a broken",
        "  playbook roll an event out of existence.",
        "- **Alerting events are a small fraction of any real stream.** The synthetic",
        "  generator alerts on roughly one event in six; a dataset replay alerts on",
        "  almost none, because a filesystem log contains no attacks.",
        "- **Ledger growth is a real constraint, not a footnote.** The ledger is",
        "  append-only and exempt from retention, because an audit ledger you",
        "  silently truncate is not an audit ledger. At a sustained 25 ev/s replay",
        f"  that is roughly {per_day:.1f} GB a day, and there is no policy for it yet.",
        "- The write figure is measured with four threads contending for SQLite's",
        "  single write lock. A single writer is faster; the number is quoted under",
        "  contention because that is the condition the WAL migration was for.",
        "",
        "## Environment",
        "",
        f"Python {env['python']} · SQLite {env['sqlite']} · {env['platform']} · "
        f"measured {env['measured_at']}",
        "",
        "```bash",
        "make perf",
        "```",
        "",
    ]
    OUT_MD.parent.mkdir(parents=True, exist_ok=True)
    OUT_MD.write_text("\n".join(lines))
    OUT_JSON.write_text(json.dumps(r, indent=2))


def main(argv=None) -> int:
    r = measure()
    write_markdown(r)
    print(f"\nWrote {OUT_MD} and {OUT_JSON}\n")
    print(f"  concurrent writes  {r['writes']['rows_per_second']:>7,} rows/sec "
          f"({len(r['writes']['errors'])} errors)")
    print(f"  pipeline benign    {r['pipeline']['benign_per_second']:>7,} events/sec")
    print(f"  pipeline alerting  {r['pipeline']['alerting_per_second']:>7,} events/sec")
    print(f"  GET /stats         {r['stats_endpoint']['median_ms']:>7} ms median")
    print(f"  ledger             {r['ledger']['bytes_per_block']:>7,} bytes/block")
    return 1 if r["writes"]["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
