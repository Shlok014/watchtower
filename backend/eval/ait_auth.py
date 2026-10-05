"""Independent AIT auth-log evaluation; source files stay outside Git.

The ZIP is large because it includes many hosts and services. HTTP byte ranges
allow retrieving the directory and two exact members without fetching the
whole archive. A server that ignores ranges is rejected before it can return
the full file. The member hashes pin the bytes used for the published result.
"""

import hashlib
import io
import json
import os
import ssl
import tempfile
import urllib.request
import zipfile
from collections import Counter
from pathlib import Path
from unittest.mock import patch

import certifi

ARCHIVE_URL = "https://zenodo.org/records/19483937/files/russellmitchell_no-pcaps.zip?download=1"
ARCHIVE_SIZE = 522_084_364
WARDBECK_ARCHIVE_URL = "https://zenodo.org/records/19483937/files/wardbeck_no-pcaps.zip?download=1"
WARDBECK_ARCHIVE_SIZE = 818_462_147
RAW_MEMBER = "gather/intranet_server/logs/auth.log"
LABEL_MEMBER = "labels/intranet_server/logs/auth.log"
RAW_SHA256 = "091920347866802f42b869575c9b1139fa4fa783b83630a9ca1e0ce68a184e39"
LABEL_SHA256 = "a5c8c79f03471928f2e2cc2eadd6282ccf836f2ab4b5770c34ddf52e317d2bd2"
WARDBECK_RAW_SHA256 = "194bbc8319ab924de8236fd9c672674fcf20db0116e760a6ab0e5d0d55c0d746"
WARDBECK_LABEL_SHA256 = "7aee23a3d88ab724ec33233ab9658185d16a869ee42434c8340711e86dc87681"
# Exact archive sizes from the publisher API and member hashes from selective
# HTTPS reads. The eight-scenario set was fixed before replaying these files.
ADDITIONAL_SCENARIOS: dict[str, tuple[int, str, str | None]] = {
    "fox": (
        688_586_900,
        "ded3e39860960ed9dd3be998fcf634976eb49dea3d10ac627f2bf22320d100f7",
        "401d07d93d75219ac7dc4e77c1373a1c1381cb13d2194007452f37e1da8383cc",
    ),
    "harrison": (
        667_985_140,
        "8ae7338e0ba79512c1ffe7db6ee337fc79adea5332f8824825d7d68e0910d3e2",
        "cfe08997c24768f1e748202e50dee89eaf856007f3aec41246de4ec079bdc11a",
    ),
    "santos": (
        576_734_274,
        "e58e17ce592a3cbddf0a2280276642ffd19802b3e8265ff3d3fed961aebf52c7",
        "8dd9c6ae0e3dce0fbbc593374229e8feb630007e8385d8c1493b22dbf152ef7c",
    ),
    "shaw": (
        1_319_137_852,
        "9e48ed6d4fab14468b5ccd55c4915e2839983261687e8f758a12c96c0c69cf6d",
        None,
    ),
    "wheeler": (
        767_673_839,
        "75f780eb765eb34f946558c48d81177f40322280a64faec44bbfd6d4152bb341",
        "279dda9a3411294ce7a0a05d45ad867cc8bcb84dfd8552d71267d8afc1cea561",
    ),
    "wilson": (
        1_083_526_183,
        "aff486bcfcc77a7ee4eb969eafc0b4e8c92ec0ec86e79cbae4b37cbd43f7a912",
        "4a3780280aeed2dc0229b2d2281d9aff4ddf71cebdb6822326060f9535553685",
    ),
}
MAX_MEMBER_BYTES = 1 << 20


def _scenario(name: str) -> tuple[str, int, str, str | None]:
    if name == "russellmitchell":
        return ARCHIVE_URL, ARCHIVE_SIZE, RAW_SHA256, LABEL_SHA256
    if name == "wardbeck":
        return (
            WARDBECK_ARCHIVE_URL,
            WARDBECK_ARCHIVE_SIZE,
            WARDBECK_RAW_SHA256,
            WARDBECK_LABEL_SHA256,
        )
    if name in ADDITIONAL_SCENARIOS:
        size, raw_hash, label_hash = ADDITIONAL_SCENARIOS[name]
        url = f"https://zenodo.org/records/19483937/files/{name}_no-pcaps.zip?download=1"
        return url, size, raw_hash, label_hash
    raise ValueError(f"unknown AIT scenario {name!r}")


def http_range(
    start: int, end: int, *, url: str = ARCHIVE_URL, archive_size: int = ARCHIVE_SIZE
) -> bytes:
    """Fetch one exact inclusive range with TLS certificate verification."""
    request = urllib.request.Request(
        url,
        headers={"Range": f"bytes={start}-{end}"},
    )
    context = ssl.create_default_context(cafile=certifi.where())
    expected_range = f"bytes {start}-{end}/{archive_size}"
    for _ in range(3):
        with urllib.request.urlopen(request, context=context, timeout=30) as response:
            if response.status != 206 or response.headers.get("Content-Range") != expected_range:
                raise ValueError("server did not honor the exact byte range")
            data = response.read(end - start + 2)
        if len(data) == end - start + 1:
            return data
    raise ValueError("truncated or oversized byte range after three attempts")


class RangeReader(io.RawIOBase):
    """Seekable, bounded reader for Python's ZIP parser over HTTP ranges."""

    def __init__(self, size, fetch, *, block_size=1 << 20, max_network_bytes=32 << 20):
        self.size = size
        self.fetch = fetch
        self.block_size = block_size
        self.max_network_bytes = max_network_bytes
        self.pos = 0
        self.cache = {}
        self.bytes_fetched = 0

    def seekable(self):
        return True

    def readable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, offset, whence=os.SEEK_SET):
        new = (
            offset
            if whence == os.SEEK_SET
            else self.pos + offset
            if whence == os.SEEK_CUR
            else self.size + offset
            if whence == os.SEEK_END
            else -1
        )
        if new < 0 or new > self.size:
            raise ValueError("seek outside archive")
        self.pos = new
        return new

    def read(self, size=-1):
        if size < 0:
            size = self.size - self.pos
        end = min(self.pos + size, self.size)
        pieces = []
        while self.pos < end:
            index = self.pos // self.block_size
            if index not in self.cache:
                start = index * self.block_size
                stop = min(start + self.block_size, self.size) - 1
                if self.bytes_fetched + stop - start + 1 > self.max_network_bytes:
                    raise ValueError("selective ZIP read exceeded its network budget")
                block = self.fetch(start, stop)
                if len(block) != stop - start + 1:
                    raise ValueError("range reader received an incomplete block")
                self.cache[index] = block
                self.bytes_fetched += len(block)
            block = self.cache[index]
            offset = self.pos % self.block_size
            take = min(end - self.pos, len(block) - offset)
            pieces.append(block[offset : offset + take])
            self.pos += take
        return b"".join(pieces)


def _member(archive, name, expected_hash):
    info = archive.getinfo(name)
    if info.file_size > MAX_MEMBER_BYTES:
        raise ValueError(f"ZIP member {name} exceeds size limit")
    data = archive.read(info)
    if hashlib.sha256(data).hexdigest() != expected_hash:
        raise ValueError(f"SHA-256 mismatch for ZIP member {name}")
    return data


def extract_subset(archive, out_dir: Path, *, raw_hash=RAW_SHA256, label_hash=LABEL_SHA256):
    """Verify selected members, then create only their local cache files."""
    raw = _member(archive, RAW_MEMBER, raw_hash)
    if label_hash is None:
        if LABEL_MEMBER in archive.namelist():
            raise ValueError("unexpected label member in no-label scenario")
        labels = None
    else:
        labels = _member(archive, LABEL_MEMBER, label_hash)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = (out_dir / "auth.log", out_dir / "auth.labels.jsonl" if labels is not None else None)
    for path, data in zip(paths, (raw, labels), strict=True):
        if path is None:
            continue
        if path.is_symlink():
            raise ValueError(f"existing dataset path is a symlink: {path}")
        if path.exists():
            if path.read_bytes() != data:
                raise ValueError(f"existing dataset file differs: {path}")
            continue
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as target:
            target.write(data)
    return paths


def fetch_subset(out_dir: Path, *, scenario: str = "russellmitchell") -> tuple[Path, Path | None]:
    url, size, raw_hash, label_hash = _scenario(scenario)
    reader = RangeReader(
        size,
        lambda start, end: http_range(start, end, url=url, archive_size=size),
    )
    with zipfile.ZipFile(reader) as archive:
        return extract_subset(archive, out_dir, raw_hash=raw_hash, label_hash=label_hash)


def parse_labels(text: str, raw_lines: int) -> dict[int, tuple[str, ...]]:
    """Map the publisher's one-based line numbers to attack-step labels."""
    found = {}
    for record in text.splitlines():
        try:
            row = json.loads(record)
        except json.JSONDecodeError as exc:
            raise ValueError("invalid label JSONL") from exc
        if not isinstance(row, dict):
            raise ValueError("invalid label record")
        line = row.get("line")
        labels = row.get("labels")
        if (
            type(line) is not int
            or not 1 <= line <= raw_lines
            or line in found
            or not isinstance(labels, list)
            or not labels
            or any(not isinstance(label, str) or not label for label in labels)
        ):
            raise ValueError(f"invalid or duplicate label at line {line!r}")
        found[line] = tuple(labels)
    if not found:
        raise ValueError("label file contains no attack lines")
    return found


def labeled_runs(labels: set[int], alerted: set[int]) -> list[dict]:
    """Group adjacent publisher-labeled lines without calling them incidents."""
    groups = []
    for line in sorted(labels):
        if groups and line == groups[-1][1] + 1:
            groups[-1][1] = line
        else:
            groups.append([line, line])
    return [
        {
            "start_line": start,
            "end_line": end,
            "alert_line_numbers": sorted(line for line in alerted if start <= line <= end),
        }
        for start, end in groups
    ]


def publisher_rule_coverage(text: str, alerted: set[int]) -> dict[str, dict[str, int]]:
    """Count publisher-annotated lines hit by any alert on that exact line.

    The rule identifiers belong to the dataset publisher, not Watchtower's
    ruleset. One line can carry multiple identifiers, so columns overlap.
    """
    labeled = Counter()
    hits = Counter()
    for record in text.splitlines():
        try:
            row = json.loads(record)
        except json.JSONDecodeError as exc:
            raise ValueError("invalid publisher rule annotation JSONL") from exc
        if not isinstance(row, dict) or type(row.get("line")) is not int:
            raise ValueError("invalid publisher rule annotation line")
        annotations = row.get("rules", {})
        if not isinstance(annotations, dict) or any(
            not isinstance(name, str)
            or not isinstance(values, list)
            or any(not isinstance(value, str) or not value for value in values)
            for name, values in annotations.items()
        ):
            raise ValueError("invalid publisher rule annotation")
        for rule in {rule for values in annotations.values() for rule in values}:
            labeled[rule] += 1
            if row["line"] in alerted:
                hits[rule] += 1
    return {
        rule: {"labeled_lines": labeled[rule], "alerted_lines": hits[rule]}
        for rule in sorted(labeled)
    }


def evaluate(
    raw_path: Path,
    labels_path: Path | None,
    *,
    threshold: float = 0.45,
    scenario: str = "russellmitchell",
) -> dict:
    """Replay the pinned AIT auth log with the current file parser and rules.

    Each stored alert is joined to the original one-based source line that
    produced it. This is an exact-line evaluation of one testbed slice, not an
    incident-level or production measurement.
    """
    from watchtower import config, threatintel
    from watchtower.detect import live_shadow, rules
    from watchtower.pipeline import consumer
    from watchtower.sources.file_tailer import parse_line
    from watchtower.store import db, repos

    _, _, expected_raw, expected_labels = _scenario(scenario)
    if not 0 < threshold <= 1:
        raise ValueError("threshold must be in (0, 1]")
    raw_bytes = Path(raw_path).read_bytes()
    if hashlib.sha256(raw_bytes).hexdigest() != expected_raw:
        raise ValueError("raw auth.log SHA-256 differs from pinned source")
    if (labels_path is None) != (expected_labels is None):
        raise ValueError("label-file presence differs from pinned source")
    label_bytes = Path(labels_path).read_bytes() if labels_path is not None else None
    if label_bytes is not None and hashlib.sha256(label_bytes).hexdigest() != expected_labels:
        raise ValueError("auth labels SHA-256 differs from pinned source")
    lines = raw_bytes.decode("utf-8").splitlines()
    labels = (
        parse_labels(label_bytes.decode("utf-8"), len(lines)) if label_bytes is not None else {}
    )

    saved_config = config.get()
    saved_db_path = db.path()
    saved_profile = live_shadow._profile
    saved_reason = live_shadow._unavailable_reason
    saved_models_dir = live_shadow._models_dir
    events = Counter()
    labeled_events = Counter()
    alert_events = Counter()
    alert_lines = []
    parsed = 0
    try:
        with tempfile.TemporaryDirectory(prefix="watchtower-ait-auth-eval-") as directory:
            config.replace(data_dir=Path(directory), alert_threshold=threshold, retention_hours=24)
            db.configure(None)
            live_shadow.enable(config.get().models_dir)
            db.connect()
            unavailable = threatintel.Verdict(
                "unavailable", 0.0, (), "Threat feeds disabled for replay", False
            )
            with (
                patch.object(consumer, "run_response", return_value=None),
                patch.object(consumer, "housekeeping", return_value=None),
                patch.object(threatintel, "classify", return_value=unavailable),
            ):
                for line_number, line in enumerate(lines, 1):
                    raw = parse_line(line, str(raw_path))
                    if raw is None:
                        continue
                    parsed += 1
                    events[raw["event"]] += 1
                    if line_number in labels:
                        labeled_events[raw["event"]] += 1
                    at_ms = repos.from_iso(raw["timestamp"])
                    with patch.object(repos, "now_ms", return_value=at_ms):
                        stored = consumer.process_log(raw)
                    if (
                        db.connect()
                        .execute("SELECT 1 FROM alerts WHERE event_id = ?", (stored["id"],))
                        .fetchone()
                    ):
                        alert_lines.append(line_number)
                        alert_events[raw["event"]] += 1
            stored_count = db.connect().execute("SELECT count(*) FROM events").fetchone()[0]
            if stored_count != parsed:
                raise RuntimeError("replay parsed count differs from stored count")
            if sum(labeled_events.values()) != len(labels):
                raise ValueError("publisher label targets an unparsed auth-log line")
            version = rules.ruleset_version()
    finally:
        db.close_all()
        config.set_config(saved_config)
        db.configure(saved_db_path)
        live_shadow._profile = saved_profile
        live_shadow._unavailable_reason = saved_reason
        live_shadow._models_dir = saved_models_dir

    alerted = set(alert_lines)
    attack = set(labels)
    if label_bytes is None:
        confusion = {"tp": None, "fp": None, "fn": None, "tn": None}
        precision = recall = None
    else:
        tp = len(alerted & attack)
        fp = len(alerted - attack)
        fn = len(attack - alerted)
        tn = parsed - tp - fp - fn
        confusion = {"tp": tp, "fp": fp, "fn": fn, "tn": tn}
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / (tp + fn) if tp + fn else None
    runs = labeled_runs(attack, alerted)
    return {
        "protocol": f"ait_lds_v2_1_{scenario}_auth_line_replay_v1",
        "source": {
            "record": "https://zenodo.org/records/19483937",
            "scenario": scenario,
            "member": RAW_MEMBER,
            "sha256": expected_raw,
        },
        "labels": {
            "member": LABEL_MEMBER if expected_labels is not None else None,
            "sha256": expected_labels,
        },
        "raw_lines": len(lines),
        "parsed_events": parsed,
        "attack_lines": len(attack),
        "alerts": len(alert_lines),
        "alert_line_numbers": alert_lines,
        "event_counts": dict(sorted(events.items())),
        "labeled_event_counts": dict(sorted(labeled_events.items())),
        "alert_event_counts": dict(sorted(alert_events.items())),
        "confusion": confusion,
        "labeled_runs": runs,
        "labeled_run_hits": sum(bool(run["alert_line_numbers"]) for run in runs),
        "publisher_rule_coverage": (
            publisher_rule_coverage(label_bytes.decode("utf-8"), alerted)
            if label_bytes is not None
            else None
        ),
        "precision": precision,
        "recall": recall,
        "ruleset_version": version,
        "threshold": threshold,
        "replay_clock": "original_log_intervals",
        "response_actions": "disabled_for_replay",
        "threat_feeds": "disabled_for_replay",
        "label_source": (
            "publisher_attack_step_line_numbers_in_synthetic_testbed"
            if label_bytes is not None
            else "no_matching_publisher_label_member"
        ),
        "limits": [
            "One host's auth.log slice; attack labels concern privilege escalation, not SSH brute force.",
            "The publisher's testbed traffic is simulated, not production traffic.",
            "Exact-line alert attribution is not incident-level detection, and this slice does not estimate production precision or recall.",
            "BSD auth.log lines omit the year; the file parser uses the current year, while original line intervals are preserved.",
            "SOAR, threat feeds, and the live shadow profile are disabled to isolate rule behavior.",
        ],
    }
