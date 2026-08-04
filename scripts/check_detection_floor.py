#!/usr/bin/env python3
"""Fail the build if log parsing quietly gets worse.

Drain's masking configuration is the single most fragile thing in the detection
path: one regex changed, and every ``blk_-1608999687919862906`` spawns its own
template, the template count explodes, and the feature vectors become noise.
Nothing about that raises — the pipeline goes on running, the dashboard goes on
rendering, and the model's scores become meaningless.

This runs the parsing-accuracy eval against loghub's ground-truth templates on
the committed 2k samples and asserts a floor. It needs no downloads, which is
the reason the samples are in the repository.

Deliberately **not** checked here: the anomaly-detection F1. Training on 2,200
blocks produces an F1 around 0.06, which is the honest result for a
2,000-line excerpt and says nothing about the benchmark. A floor on that number
would either be so low as to be meaningless or would quietly turn a subset
result into a claim about the full dataset.

    python scripts/check_detection_floor.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# `backend/` on the path, anchored to this file rather than to the caller's cwd.
# Running a script directly does not put the working directory on sys.path — only
# `python -m` does — so without this the gate works from `backend/` and nowhere
# else, which is exactly the difference between a local run and a CI one.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

# Floors, not targets. Set below the measured values with room for library
# drift; they exist to catch a collapse, not to police the third decimal.
#
# Measured on this machine (drain3 0.9.11):
#   HDFS_2k     0.9975
#   OpenSSH_2k  0.7180
#
# OpenSSH is included precisely because Drain does markedly worse on it. A gate
# that only guarded the flattering dataset would miss a regression that shows up
# first on the harder one.
FLOORS = {
    "HDFS": 0.98,
    "OpenSSH": 0.65,
}

# A masking config that has stopped collapsing block ids shows up here first:
# the mined count runs away long before grouping accuracy bottoms out.
MAX_TEMPLATES = {
    "HDFS": 40,
    "OpenSSH": 60,
}


def main(argv=None) -> int:
    argparse.ArgumentParser(description="Detection regression floor.").parse_args(argv)

    from eval.parsing import evaluate

    failures = []
    for name, floor in FLOORS.items():
        try:
            row = evaluate(name)
        except FileNotFoundError as exc:
            failures.append(f"{name}: sample missing ({exc})")
            continue

        acc = row["grouping_accuracy"]
        mined = row["mined_templates"]
        ok = acc >= floor and mined <= MAX_TEMPLATES[name]
        mark = "✅" if ok else "❌"
        print(
            f"  {mark} {name:<10} grouping accuracy {acc:.4f} (floor {floor:.2f}) · "
            f"{mined} templates mined vs {row['true_templates']} true "
            f"(cap {MAX_TEMPLATES[name]})"
        )
        if acc < floor:
            failures.append(f"{name}: grouping accuracy {acc:.4f} below floor {floor:.2f}")
        if mined > MAX_TEMPLATES[name]:
            failures.append(
                f"{name}: mined {mined} templates, cap is {MAX_TEMPLATES[name]} — "
                "the masking config has probably stopped collapsing identifiers"
            )

    if failures:
        print("\n❌ detection regression:\n", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        print(
            "\nIf this is a deliberate change, re-measure with `make bench` and move "
            "the floor in this file — in the same commit, with the new number.",
            file=sys.stderr,
        )
        return 1

    print("\n✅ parsing accuracy holds on both samples.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
