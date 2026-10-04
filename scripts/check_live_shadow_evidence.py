#!/usr/bin/env python3
"""Regenerate or check deterministic synthetic live-shadow evidence.

Runtime timing is excluded: it measures the machine, not detector quality.
The snapshot is a reproducibility guard, not a production-accuracy gate.
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from eval import live, live_pipeline  # noqa: E402

SNAPSHOT = ROOT / "docs" / "live-shadow-eval.json"
METRICS = ROOT / "docs" / "METRICS.md"
START = "<!-- live-shadow-metrics:start -->"
END = "<!-- live-shadow-metrics:end -->"


def evidence() -> dict:
    proxy = live.evaluate()
    proxy.pop("runtime")
    return {
        "schema_version": 1,
        "feature_proxy": proxy,
        "raw_event_replay": live_pipeline.evaluate(),
    }


def summary(data: dict) -> str:
    proxy = data["feature_proxy"]["test"]
    replay = data["raw_event_replay"]["test"]

    def cells(result: dict) -> str:
        c = result["confusion"]
        return f"{c['tp']} | {c['fp']} | {c['fn']} | {c['tn']}"

    return "\n".join(
        [
            START,
            "| Synthetic test | TP | FP | FN | TN |",
            "|---|---:|---:|---:|---:|",
            f"| Direct feature proxy, shadow | {cells(proxy)} |",
            f"| Raw-event replay, rules | {cells(replay['rules'])} |",
            f"| Raw-event replay, shadow | {cells(replay['shadow'])} |",
            "",
            f"The raw-event replay has **{replay['events']} generated events**; labels are assigned by its scenario generator. "
            "Its validation/test IPs and sources are disjoint from training, but the scenarios share a generator. "
            "These figures do not estimate production precision or false-alarm rate. "
            "SOAR actions are disabled during evaluation, and shadow verdicts never trigger alerts.",
            END,
        ]
    )


def replace_summary(document: str, replacement: str) -> str:
    if document.count(START) != 1 or document.count(END) != 1:
        raise ValueError("METRICS.md must contain exactly one live-shadow evidence section")
    before, rest = document.split(START, 1)
    _, after = rest.split(END, 1)
    return before + replacement + after


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="regenerate the frozen evidence")
    args = parser.parse_args()
    actual = evidence()
    encoded = json.dumps(actual, indent=2, sort_keys=True) + "\n"
    document = METRICS.read_text()
    expected_document = replace_summary(document, summary(actual))
    if args.write:
        SNAPSHOT.write_text(encoded)
        METRICS.write_text(expected_document)
        print(f"Wrote {SNAPSHOT} and live-shadow section of {METRICS}")
        return 0
    if not SNAPSHOT.exists() or SNAPSHOT.read_text() != encoded:
        print(
            "Live-shadow evidence drifted; run scripts/check_live_shadow_evidence.py --write",
            file=sys.stderr,
        )
        return 1
    if document != expected_document:
        print("Live-shadow METRICS section drifted from generated evidence", file=sys.stderr)
        return 1
    print("Live-shadow synthetic evidence matches both evaluators and METRICS.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
