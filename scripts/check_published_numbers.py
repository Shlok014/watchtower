#!/usr/bin/env python3
"""Fail the build if a published figure drifts from the run that produced it.

`docs/metrics.json` is written by `python -m eval.benchmark` and is the only
source of measured results in this repository. `docs/METRICS.md` is generated
from it in the same call, so those two cannot disagree. **The README and the
handoff are hand-written**, and that is the gap this closes: a figure copied
into prose today is a figure nobody re-copies when the benchmark is re-run.

That is not hypothetical here. Unifying the frozen-split definition across the
project moved IsolationForest from 0.0775 to 0.0640 and parse throughput from
66,273 to 103,181 lines/sec. Both numbers appeared in three documents. Catching
that by rereading three files is exactly the job a script should have.

The check is deliberately dumb: every figure from metrics.json must appear
**as a literal string, formatted the way the document formats it**, in each
document that quotes it.

**Its one blind spot, found by testing it against a rolled-back metrics.json:**
a document that mentions a *superseded* value in prose still satisfies the
check for that value. `docs/HANDOFF.md` says "IsolationForest moved from
0.0775", so it would pass a check expecting 0.0775 even if every live figure in
it were stale. This verifies that a number is present, not that the sentence
around it is true — and a document narrating its own history is exactly where
that gap opens.

    python scripts/check_published_numbers.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
METRICS_JSON = ROOT / "docs" / "metrics.json"

# Which documents quote which figures. A document that does not quote a figure
# is not required to — this is not a completeness check.
README = "README.md"
METRICS = "docs/METRICS.md"
HANDOFF = "docs/HANDOFF.md"
ALL_THREE = (README, METRICS, HANDOFF)


def build_expectations(m: dict) -> list[tuple[str, str, tuple[str, ...]]]:
    """(label, literal, documents that must contain it)."""
    out: list[tuple[str, str, tuple[str, ...]]] = []
    d, p = m["dataset"], m["parsing"]

    for name in ("LogisticRegression", "DecisionTree", "IsolationForest"):
        mm = m["models"].get(name)
        if not mm:
            continue
        for metric in ("precision", "recall", "f1"):
            out.append((f"{name}.{metric}", f"{mm[metric]:.4f}", ALL_THREE))

    out += [
        ("dataset.lines_read", f"{d['lines_read']:,}", ALL_THREE),
        ("dataset.blocks", f"{d['blocks']:,}", ALL_THREE),
        ("dataset.templates", str(d["templates"]), (README, METRICS)),
        ("dataset.anomaly_rate", f"{d['anomaly_rate'] * 100:.2f}%", (README, METRICS)),
        ("parsing.lines_per_second", f"{p['lines_per_second']:,}", ALL_THREE),
        ("parsing.seconds", str(p["seconds"]), ALL_THREE),
    ]
    return out


def main(argv=None) -> int:
    if not METRICS_JSON.exists():
        print(
            f"{METRICS_JSON} is missing — run `make bench` to produce it.",
            file=sys.stderr,
        )
        return 1

    m = json.loads(METRICS_JSON.read_text())
    docs = {name: (ROOT / name).read_text() for name in ALL_THREE}

    failures = []
    checked = 0
    for label, literal, where in build_expectations(m):
        for doc in where:
            checked += 1
            if literal not in docs[doc]:
                failures.append(f"{doc}: {label} should read {literal!r} and does not")

    if failures:
        print(f"❌ {len(failures)} published figure(s) drifted:\n", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        print(
            "\ndocs/metrics.json is the source. Either the prose is stale — update it —\n"
            "or the benchmark was re-run and docs/METRICS.md was regenerated without\n"
            "the README and handoff being updated in the same commit.",
            file=sys.stderr,
        )
        return 1

    print(f"✅ {checked} published figures match docs/metrics.json.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
