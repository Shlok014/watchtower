"""Turn raw HDFS log lines into labelled feature vectors.

The representation is the standard one for this benchmark: one vector per HDFS
block id, counting how many times each mined template appeared in that block's
lifetime. A block is anomalous or not according to loghub's ground-truth labels.

Memory matters here — 11.2M lines, 575k blocks, on a laptop with 8 GB. The pass
below streams the file and holds one small ``Counter`` per block; keeping the
full event *sequence* per block instead would cost roughly an order of magnitude
more and is not needed for a count-vector model.

Two datasets are supported and the difference is always reported, never
smoothed over:

``full``    the 11.2M-line HDFS_v1 download, with loghub's 575,061 labels
``sample``  the 2,000-line HDFS_2k excerpt committed to this repository, with
            the labels for exactly the blocks that appear in it

A model fit on the sample is a model fit on a few hundred blocks, and every
number derived from it says so. Publishing a subset result as though it were the
benchmark is the specific failure this project exists to avoid.
"""

import csv
import hashlib
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from .. import config

FEATURE_SCHEMA = 3

BLK = re.compile(r"blk_-?\d+")

# HDFS lines look like:
#   081109 203615 148 INFO dfs.DataNode$PacketResponder: Received block blk_38 of size 67108864
# The first five fields are date, time, pid, level and component.
HEAD = re.compile(r"^\d{6}\s+\d{6}\s+\d+\s+\w+\s+[^:]+:\s*(.*)$")


@dataclass(frozen=True)
class Dataset:
    key: str
    label: str
    log_name: str
    labels_name: str
    in_samples: bool

    def log_path(self) -> Path:
        cfg = config.get()
        base = cfg.samples_dir if self.in_samples else cfg.datasets_dir
        return base / self.log_name

    def labels_path(self) -> Path:
        cfg = config.get()
        base = cfg.samples_dir if self.in_samples else cfg.datasets_dir
        return base / self.labels_name

    def available(self) -> bool:
        return self.log_path().exists() and self.labels_path().exists()


FULL = Dataset(
    key="full",
    label="loghub HDFS_v1 (full, 11.2M lines)",
    log_name="HDFS.log",
    labels_name="anomaly_label.csv",
    in_samples=False,
)
SAMPLE = Dataset(
    key="sample",
    label="loghub HDFS_2k excerpt (2,000 lines, committed to the repo)",
    log_name="HDFS_2k.log",
    labels_name="HDFS_2k_labels.csv",
    in_samples=True,
)
DATASETS = {d.key: d for d in (FULL, SAMPLE)}


def best_available() -> Dataset:
    """The full dataset if it has been downloaded, otherwise the committed sample."""
    if FULL.available():
        return FULL
    if SAMPLE.available():
        return SAMPLE
    raise FileNotFoundError(
        f"no HDFS data — expected {SAMPLE.log_path()} (committed) or "
        f"{FULL.log_path()} (run `python -m datasets.download --hdfs`)"
    )


def datasets_dir() -> Path:
    return config.get().datasets_dir


def file_sha256(path: Path) -> str:
    """Fingerprint source bytes, including changes that preserve size or mtime."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def miner_stream(dataset: Dataset) -> str:
    """The sample must not replace the full benchmark's parser state."""
    return "hdfs_sample" if dataset.key == "sample" else "hdfs"


def load_labels(dataset: Dataset = FULL) -> dict:
    labels = {}
    with open(dataset.labels_path(), newline="") as fh:
        for row in csv.DictReader(fh):
            labels[row["BlockId"]] = 1 if row["Label"].strip().lower() == "anomaly" else 0
    return labels


def build_matrix(
    parser, dataset: Dataset = FULL, limit: int | None = None, progress_every: int = 500_000
):
    """Stream the log and return (X, y, block_ids, template_ids, stats)."""
    labels = load_labels(dataset)
    per_block: dict[str, Counter] = defaultdict(Counter)
    seen_templates: set[int] = set()
    lines = matched = 0
    t0 = time.perf_counter()

    with open(dataset.log_path(), encoding="utf-8", errors="replace") as fh:
        for line in fh:
            lines += 1
            if limit and lines > limit:
                break
            m = HEAD.match(line)
            content = m.group(1) if m else line.strip()
            blocks = BLK.findall(content)
            if not blocks:
                continue
            cid, _ = parser.parse(content)
            seen_templates.add(cid)
            matched += 1
            for b in set(blocks):
                per_block[b][cid] += 1
            if progress_every and lines % progress_every == 0:
                print(
                    f"    {lines:>10,} lines, {len(per_block):>7,} blocks, "
                    f"{len(seen_templates)} templates",
                    flush=True,
                )

    # Keep only blocks we have a ground-truth label for.
    block_ids = [b for b in per_block if b in labels]
    template_ids = sorted(seen_templates)
    index = {t: i for i, t in enumerate(template_ids)}

    X = np.zeros((len(block_ids), len(template_ids)), dtype=np.float32)
    y = np.zeros(len(block_ids), dtype=np.int8)
    for row, b in enumerate(block_ids):
        for cid, n in per_block[b].items():
            X[row, index[cid]] = n
        y[row] = labels[b]

    stats = {
        "dataset": dataset.key,
        "dataset_label": dataset.label,
        "lines_read": lines if not limit else min(lines, limit),
        "lines_with_block_id": matched,
        "blocks": len(block_ids),
        "anomalous_blocks": int(y.sum()),
        "anomaly_rate": round(float(y.mean()), 5) if len(y) else 0.0,
        "templates": len(template_ids),
        "seconds": round(time.perf_counter() - t0, 2),
    }
    return X, y, block_ids, template_ids, stats


def build_matrix_holdout(parser, dataset: Dataset = FULL, progress_every: int = 500_000):
    """Fit templates on training blocks, then freeze them for held-out blocks.

    HDFS lines may mention more than one block. A line spanning the split is
    never used to fit the miner; it is matched for its held-out blocks only.
    The three streaming passes avoid retaining raw lines from the full dataset.
    """
    from .model import frozen_split

    labels = load_labels(dataset)
    block_ids: list[str] = []
    seen_blocks: set[str] = set()
    lines = lines_with_block_id = 0
    t0 = time.perf_counter()

    def parts(line: str):
        match = HEAD.match(line)
        content = match.group(1) if match else line.strip()
        return content, tuple(dict.fromkeys(BLK.findall(content)))

    with open(dataset.log_path(), encoding="utf-8", errors="replace") as fh:
        for line in fh:
            lines += 1
            _content, blocks = parts(line)
            if blocks:
                lines_with_block_id += 1
            for block in blocks:
                if block in labels and block not in seen_blocks:
                    seen_blocks.add(block)
                    block_ids.append(block)

    y = np.array([labels[block] for block in block_ids], dtype=np.int8)
    if len(y) == 0:
        raise ValueError("no labelled blocks — nothing to train on")
    if len(set(y.tolist())) < 2:
        raise ValueError(f"only one class present in {len(y)} labelled blocks — refusing to fit")
    train_idx, test_idx = frozen_split(y)
    train_blocks = {block_ids[int(i)] for i in train_idx}
    test_blocks = {block_ids[int(i)] for i in test_idx}
    per_block: dict[str, Counter] = defaultdict(Counter)
    seen_templates: set[int] = set()
    train_lines = held_out_lines = held_out_matched = held_out_unmatched = mixed = 0

    with open(dataset.log_path(), encoding="utf-8", errors="replace") as fh:
        for line_number, line in enumerate(fh, start=1):
            content, blocks = parts(line)
            labelled = set(blocks) & seen_blocks
            if not labelled or labelled & test_blocks:
                continue
            cid, _ = parser.parse(content)
            seen_templates.add(cid)
            train_lines += 1
            for block in labelled:
                per_block[block][cid] += 1
            if progress_every and line_number % progress_every == 0:
                print(
                    f"    mined {line_number:>10,} lines, {len(seen_templates)} templates",
                    flush=True,
                )

    with open(dataset.log_path(), encoding="utf-8", errors="replace") as fh:
        for line in fh:
            content, blocks = parts(line)
            present = set(blocks)
            test_in_line = present & test_blocks
            if not test_in_line:
                continue
            held_out_lines += 1
            if present & train_blocks:
                mixed += 1
            cid, _ = parser.match(content)
            if cid is None or cid not in seen_templates:
                held_out_unmatched += 1
                continue
            held_out_matched += 1
            for block in test_in_line:
                per_block[block][cid] += 1

    template_ids = sorted(seen_templates)
    index = {template: column for column, template in enumerate(template_ids)}
    X = np.zeros((len(block_ids), len(template_ids)), dtype=np.float32)
    for row, block in enumerate(block_ids):
        for cid, count in per_block[block].items():
            X[row, index[cid]] = count

    stats = {
        "dataset": dataset.key,
        "dataset_label": dataset.label,
        "feature_schema": FEATURE_SCHEMA,
        "split_method": "stratified block 50/50; train-only template mining",
        "lines_read": lines,
        "lines_with_block_id": lines_with_block_id,
        "blocks": len(block_ids),
        "anomalous_blocks": int(y.sum()),
        "anomaly_rate": round(float(y.mean()), 5),
        "templates": len(template_ids),
        "train_lines": train_lines,
        "held_out_lines": held_out_lines,
        "held_out_matched_lines": held_out_matched,
        "held_out_unmatched_lines": held_out_unmatched,
        "mixed_split_lines": mixed,
        "log_sha256": file_sha256(dataset.log_path()),
        "labels_sha256": file_sha256(dataset.labels_path()),
        "seconds": round(time.perf_counter() - t0, 2),
    }
    return X, y, block_ids, template_ids, stats


# ─── cache ───────────────────────────────────────────────────────────────────
# Parsing the full dataset takes ~170 seconds. Retraining on demand from an HTTP
# request cannot pay that, and re-parsing would also re-mine the templates, so
# the column space could shift under a model that is meant to be comparable to
# its predecessor. The matrix is therefore cached with the template ids that
# define its columns; the two are meaningless apart.
def cache_path(dataset: Dataset) -> Path:
    return config.get().data_dir / "processed" / f"hdfs_{dataset.key}_features.npz"


def save_cache(dataset: Dataset, X, y, block_ids, template_ids, stats) -> Path:
    path = cache_path(dataset)
    path.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(
        path,
        X=X,
        y=y,
        block_ids=np.array(block_ids),
        template_ids=np.array(template_ids),
        stats=np.array([__import__("json").dumps(stats)]),
    )
    return path


def load_cache(dataset: Dataset):
    """Return (X, y, block_ids, template_ids, stats) or None if not cached."""
    import json as _json

    path = cache_path(dataset)
    if not path.exists():
        return None
    try:
        with np.load(path, allow_pickle=False) as z:
            stats = _json.loads(str(z["stats"][0]))
            if stats.get("feature_schema") != FEATURE_SCHEMA:
                return None
            return (
                z["X"],
                z["y"],
                [str(b) for b in z["block_ids"]],
                [int(t) for t in z["template_ids"]],
                stats,
            )
    except (OSError, ValueError, KeyError) as exc:
        # A truncated cache is reported and ignored, never partially trusted: a
        # short feature matrix trains a model that looks fine and is not.
        print(f"⚠️  feature cache at {path} unusable ({exc}); rebuilding")
        return None
