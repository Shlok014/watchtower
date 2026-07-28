"""Turn raw HDFS log lines into labelled feature vectors.

The representation is the standard one for this benchmark: one vector per HDFS
block id, counting how many times each mined template appeared in that block's
lifetime. A block is anomalous or not according to loghub's ground-truth labels.

Memory matters here — 11.2M lines, 575k blocks, on a laptop with 8 GB. The pass
below streams the file and holds one small ``Counter`` per block; keeping the
full event *sequence* per block instead would cost roughly an order of magnitude
more and is not needed for a count-vector model.
"""

import csv
import re
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

DATA = Path(__file__).resolve().parent.parent / "data" / "datasets"
BLK = re.compile(r"blk_-?\d+")

# HDFS lines look like:
#   081109 203615 148 INFO dfs.DataNode$PacketResponder: Received block blk_38 of size 67108864
# The first five fields are date, time, pid, level and component.
HEAD = re.compile(r"^\d{6}\s+\d{6}\s+\d+\s+\w+\s+[^:]+:\s*(.*)$")


def load_labels() -> dict:
    labels = {}
    with open(DATA / "anomaly_label.csv", newline="") as fh:
        for row in csv.DictReader(fh):
            labels[row["BlockId"]] = 1 if row["Label"].strip().lower() == "anomaly" else 0
    return labels


def build_matrix(parser, limit: int | None = None, progress_every: int = 500_000):
    """Stream HDFS.log and return (X, y, block_ids, template_ids, stats)."""
    labels = load_labels()
    per_block: dict[str, Counter] = defaultdict(Counter)
    seen_templates: set[int] = set()
    lines = matched = 0

    with open(DATA / "HDFS.log", encoding="utf-8", errors="replace") as fh:
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
        "lines_read": lines if not limit else min(lines, limit),
        "lines_with_block_id": matched,
        "blocks": len(block_ids),
        "anomalous_blocks": int(y.sum()),
        "anomaly_rate": round(float(y.mean()), 5),
        "templates": len(template_ids),
    }
    return X, y, block_ids, template_ids, stats
