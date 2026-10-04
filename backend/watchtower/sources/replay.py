"""Replay a real log file through the live pipeline.

This is the piece that makes the rest of the project defensible. Everything the
dashboard shows — the detection windows, the alerts, the SOAR selection, the
audit ledger — runs on *the same* ``process_log`` whether the line came from the
synthetic generator or from the 11.2-million-line HDFS_v1 benchmark. There is no
separate demo path, so nothing here can be true of the demo and false of the
real thing.

Two properties are load-bearing and easy to get wrong:

**Event time is the log's, ingest time is now.** A 2008 HDFS line keeps its 2008
timestamp in ``ts_ms``; ``ingested_ts_ms`` is when this process saw it. The
detection windows and the dashboard's timeline both key on ingest time — key
them on event time instead and a replay produces zero detections and a flat
timeline while the ingest counter climbs, which is silent and indistinguishable
from a quiet network.

**HDFS is a filesystem log, not a security log.** Nothing in it is an attack.
Lines carry their own level (INFO/WARN/ERROR/FATAL) and that is all the severity
they get; mapping "WARN" onto "suspicious_ip" would manufacture a threat
judgement the data never made. What replay demonstrates is that real volume
flows through real code — and any alert it raises comes from the correlation
windows, on real addresses, not from a lookup table of scary words.
"""

import re
import time
from datetime import UTC, datetime

from .. import config
from ..detect import stream
from . import sshd
from .base import ThreadedSource

# 081109 203615 148 INFO dfs.DataNode$PacketResponder: PacketResponder 1 for ...
#  ^date  ^time ^pid ^level ^component                  ^content
HDFS_LINE = re.compile(
    r"^(?P<date>\d{6})\s+(?P<time>\d{6})\s+(?P<pid>\d+)\s+(?P<level>\w+)\s+"
    r"(?P<component>[^:]+):\s*(?P<content>.*)$"
)

# Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186
OPENSSH_LINE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<tag>[^:]+):\s*(?P<content>.*)$"
)

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

LEVEL_TO_EVENT = {
    "TRACE": "log_debug",
    "DEBUG": "log_debug",
    "INFO": "log_info",
    "NOTICE": "log_notice",
    "WARN": "log_warning",
    "WARNING": "log_warning",
    "ERROR": "log_error",
    "SEVERE": "log_error",
    "CRITICAL": "log_critical",
    "FATAL": "log_critical",
}

MONTHS = {
    m: i
    for i, m in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
    )
}


class UnknownDataset(ValueError):
    pass


def _first_ip(text: str, fallback: str) -> str:
    """The first IPv4 literal in the line, or the fallback.

    Validated as four octets rather than trusted from the regex: HDFS content is
    full of ``blk_-1608999687919862906`` and version strings, and ``10.251.31.5``
    next to ``1.2.3.4.5`` in the same line is common enough to matter.
    """
    for candidate in IPV4.findall(text):
        parts = candidate.split(".")
        if all(
            p.isdigit() and 0 <= int(p) <= 255 and (p == "0" or not p.startswith("0"))
            for p in parts
        ):
            return candidate
    return fallback


def parse_hdfs(line: str) -> dict | None:
    """One HDFS_v1 line → a raw event, or None if it does not parse."""
    m = HDFS_LINE.match(line)
    if not m:
        return None
    g = m.groupdict()
    try:
        # HDFS timestamps are yymmdd hhmmss with no zone. Treated as UTC and
        # labelled as such rather than guessed at: the dataset does not say, and
        # inventing a zone would shift every event by hours.
        ts = datetime.strptime(g["date"] + g["time"], "%y%m%d%H%M%S").replace(tzinfo=UTC)
    except ValueError:
        return None
    content = g["content"]
    return {
        "timestamp": ts.isoformat(),
        # The real component that emitted the line, e.g. dfs.DataNode.
        "source": g["component"].strip().split("$")[0],
        "event": LEVEL_TO_EVENT.get(g["level"].upper(), "log_info"),
        # A real address out of the line where there is one. HDFS logs carry
        # RFC1918 datanode addresses, which the reputation lookup correctly
        # classifies as internal and scores 0.00 — an unlisted internal host is
        # not evidence of anything.
        "ip": _first_ip(content, "10.0.0.0"),
        "user": "unknown",
        "message": content,
        "log_format": "hdfs",
        "origin": "replay:hdfs",
    }


def parse_openssh(line: str) -> dict | None:
    """One OpenSSH_2k line → a raw event, or None."""
    m = OPENSSH_LINE.match(line)
    if not m:
        return None
    g = m.groupdict()
    month = MONTHS.get(g["month"])
    if not month:
        return None
    hh, mm, ss = (int(x) for x in g["time"].split(":"))
    # The dataset carries no year. 2016 is the year loghub records for this
    # capture; it is stated here rather than defaulted to "now", which would
    # make every replayed line look like it happened today.
    ts = datetime(2016, month, int(g["day"]), hh, mm, ss, tzinfo=UTC)
    content = g["content"]
    auth = sshd.parse(g["tag"], content)
    event = (
        auth[0]
        if auth
        else ("log_warning" if "break-in attempt" in content.lower() else "log_info")
    )
    return {
        "timestamp": ts.isoformat(),
        "source": g["host"],
        # Unlike HDFS, an sshd log genuinely *is* an authentication log, and
        # "Failed password for invalid user" is an authentication failure by the
        # daemon's own account of itself. Nothing is inferred beyond that: the
        # match is on the literal message sshd emits.
        "event": event,
        "ip": auth[1] if auth else "127.0.0.1",
        "user": auth[2] if auth else "unknown",
        "message": content,
        "log_format": "rfc3164",
        "origin": "replay:openssh",
    }


DATASETS = {
    "hdfs": ("HDFS_2k.log", parse_hdfs),
    "openssh": ("OpenSSH_2k.log", parse_openssh),
}


def resolve_path(dataset: str):
    """Prefer the full dataset if it has been downloaded, else the committed sample."""
    cfg = config.get()
    if dataset == "hdfs":
        full = cfg.datasets_dir / "HDFS.log"
        if full.exists():
            return full
    sample = cfg.samples_dir / DATASETS[dataset][0]
    if sample.exists():
        return sample
    raise FileNotFoundError(
        f"no log file for replay:{dataset} — expected {sample}"
        + (f" or {cfg.datasets_dir / 'HDFS.log'}" if dataset == "hdfs" else "")
    )


class ReplaySource(ThreadedSource):
    """Stream a real log file through the live pipeline at a fixed rate."""

    # A file has an end. Reaching it is success, and health says so rather than
    # reporting a permanent fault over a job that did what it was asked.
    finite = True

    def __init__(self, dataset: str = "hdfs", speed: float = 20.0, limit: int | None = None):
        super().__init__()
        if dataset not in DATASETS:
            raise UnknownDataset(
                f"unknown replay dataset {dataset!r} — known: {', '.join(sorted(DATASETS))}"
            )
        self.dataset = dataset
        self.name = f"replay:{dataset}"
        self.origin = f"replay:{dataset}"
        self.speed = max(speed, 0.1)
        self.limit = limit
        self.lines_read = 0
        self.events_emitted = 0
        self.skipped = 0

    def run(self, emit) -> None:
        path = resolve_path(self.dataset)
        _, parse = DATASETS[self.dataset]
        interval = 1.0 / self.speed
        next_at = time.monotonic()

        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if self.stopping:
                    return
                if self.limit is not None and self.events_emitted >= self.limit:
                    return
                self.lines_read += 1
                raw = parse(line.rstrip("\n"))
                if raw is None:
                    # Counted, not silently dropped: a masking or format change
                    # that stops every line parsing would otherwise look exactly
                    # like an empty file.
                    self.skipped += 1
                    continue

                # Pace against a monotonic schedule rather than sleeping a fixed
                # interval after each event. Sleeping after the work makes the
                # real rate (interval + processing time), so a replay asked for
                # 25 ev/s quietly delivers 18 and every throughput number taken
                # from it is wrong.
                next_at += interval
                delay = next_at - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                elif delay < -1.0:
                    # Fell more than a second behind: stop trying to catch up,
                    # or a slow disk turns into an unbounded burst.
                    next_at = time.monotonic()

                try:
                    emit(raw)
                    self.events_emitted += 1
                except Exception as exc:
                    print(f"⚠️  replay:{self.dataset} pipeline error: {type(exc).__name__}: {exc}")

                # Model scoring runs beside the pipeline, not inside it. The
                # trained detector classifies HDFS *blocks*; the pipeline
                # handles *events*. Folding a block-level probability into an
                # event row would put a number in a column that does not mean
                # what the column says.
                if self.dataset == "hdfs":
                    scorer = stream.get()
                    if scorer is not None:
                        try:
                            scorer.observe(raw["message"])
                        except Exception as exc:
                            print(f"⚠️  block scoring error: {type(exc).__name__}: {exc}")

        print(
            f"✅ replay:{self.dataset} finished — {self.events_emitted} events from "
            f"{self.lines_read} lines ({self.skipped} unparsed)"
        )

    def stats(self) -> dict:
        return {
            "dataset": self.dataset,
            "lines_read": self.lines_read,
            "events_emitted": self.events_emitted,
            "unparsed": self.skipped,
            "target_events_per_second": self.speed,
        }
