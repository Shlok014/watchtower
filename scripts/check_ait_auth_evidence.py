#!/usr/bin/env python3
"""Replay the pinned AIT auth-log slice and compare its frozen evidence."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from eval import ait_auth  # noqa: E402

DATA_ROOT = ROOT / "backend" / "data" / "datasets"
SCENARIOS = ("russellmitchell", "wardbeck")
SNAPSHOT = ROOT / "docs" / "ait-auth-eval.json"
METRICS = ROOT / "docs" / "METRICS.md"
START = "<!-- ait-auth-metrics:start -->"
END = "<!-- ait-auth-metrics:end -->"


def summary(data: dict) -> str:
    rows = []
    hit_counts = []
    signal_counts = []
    false_alerts = 0
    for name in SCENARIOS:
        result = data["scenarios"][name]
        counts = result["confusion"]
        hit_counts.append(f"{counts['tp']}/{result['attack_lines']}")
        signal_counts.append(str(result["event_counts"].get("privilege_escalation", 0)))
        false_alerts += counts["fp"]
        rows.append(
            f"| {name} `intranet_server/auth.log` | {result['parsed_events']} | "
            f"{result['attack_lines']} | {result['alerts']} | {counts['tp']} | "
            f"{counts['fp']} | {counts['fn']} | {counts['tn']} |"
        )
    return "\n".join(
        [
            START,
            "| AIT-LDS v2.1 scenario | Parsed lines | Publisher-labeled attack lines | Alerted lines | TP | FP | FN | TN |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
            *rows,
            "",
            "The file parser classifies "
            f"{signal_counts[0]} and {signal_counts[1]} lines as privilege-escalation "
            "signals in the respective scenarios. Exact-line hits on publisher-labeled "
            f"attack lines are {hit_counts[0]} and {hit_counts[1]}. Across both small "
            f"slices, {false_alerts} alerts fell on unlabeled lines; this does not "
            "establish a production false-alarm rate.",
            "",
            "The [AIT-LDS v2.1 publisher](https://zenodo.org/records/19483937) "
            "assigns attack-step labels by original line number. Its enterprise "
            "traffic is simulated in a testbed. These are two auth-log slices "
            "from separate scenarios in the same testbed family. The rule was "
            "written before `wardbeck` label content was inspected and was not "
            "changed after its replay. Each replay uses the existing file parser, "
            "normalization, SQL windows, alert path, and a temporary SQLite store "
            "with original log intervals. SOAR, threat feeds, and the shadow model "
            "are disabled. These counts do not estimate production precision, "
            "production recall, or incident-level detection.",
            END,
        ]
    )


def replace_summary(document: str, replacement: str) -> str:
    if document.count(START) != 1 or document.count(END) != 1:
        raise ValueError("METRICS.md must contain exactly one AIT auth section")
    before, rest = document.split(START, 1)
    _, after = rest.split(END, 1)
    return before + replacement + after


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch", action="store_true", help="download only the pinned ZIP members")
    parser.add_argument("--write", action="store_true", help="regenerate frozen JSON and metrics")
    args = parser.parse_args()
    results = {}
    for name in SCENARIOS:
        directory = DATA_ROOT / f"ait-{name}-auth"
        if args.fetch:
            ait_auth.fetch_subset(directory, scenario=name)
        raw, labels = directory / "auth.log", directory / "auth.labels.jsonl"
        if not raw.exists() or not labels.exists():
            print(f"AIT {name} files missing; rerun with --fetch", file=sys.stderr)
            return 2
        results[name] = ait_auth.evaluate(raw, labels, scenario=name)
    actual = {"protocol": "ait_lds_v2_1_auth_scenario_comparison_v1", "scenarios": results}
    encoded = json.dumps(actual, indent=2, sort_keys=True) + "\n"
    document = METRICS.read_text()
    expected_document = replace_summary(document, summary(actual))
    if args.write:
        SNAPSHOT.write_text(encoded)
        METRICS.write_text(expected_document)
        print(f"Wrote {SNAPSHOT} and AIT section of {METRICS}")
        return 0
    if not SNAPSHOT.exists() or SNAPSHOT.read_text() != encoded:
        print("AIT auth evidence drifted; regenerate with --write", file=sys.stderr)
        return 1
    if document != expected_document:
        print("AIT auth METRICS section drifted", file=sys.stderr)
        return 1
    print("AIT auth replay matches frozen evidence and METRICS.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
