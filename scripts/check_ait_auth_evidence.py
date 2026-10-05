#!/usr/bin/env python3
"""Replay all eight pinned AIT auth-log slices and compare frozen evidence."""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from eval import ait_auth  # noqa: E402

DATA_ROOT = ROOT / "backend" / "data" / "datasets"
SCENARIOS = (
    "fox",
    "harrison",
    "russellmitchell",
    "santos",
    "shaw",
    "wardbeck",
    "wheeler",
    "wilson",
)
SNAPSHOT = ROOT / "docs" / "ait-auth-eval.json"
METRICS = ROOT / "docs" / "METRICS.md"
START = "<!-- ait-auth-metrics:start -->"
END = "<!-- ait-auth-metrics:end -->"


def summary(data: dict) -> str:
    rows = []
    false_alerts = 0
    labeled_lines = 0
    run_hits = 0
    total_runs = 0
    labeled_types = Counter()
    alert_types = Counter()
    for name in SCENARIOS:
        result = data["scenarios"][name]
        counts = result["confusion"]
        has_labels = result["labels"]["member"] is not None
        runs = len(result["labeled_runs"])
        run_display = f"{result['labeled_run_hits']}/{runs}" if runs else "n/a"
        if has_labels:
            false_alerts += counts["fp"]
        labeled_lines += result["attack_lines"]
        run_hits += result["labeled_run_hits"]
        total_runs += runs
        labeled_types.update(result["labeled_event_counts"])
        alert_types.update(result["alert_event_counts"])
        rows.append(
            f"| {name} | {'present' if has_labels else 'absent'} | {result['parsed_events']} | "
            f"{result['attack_lines'] if has_labels else 'n/a'} | {result['alerts']} | "
            f"{counts['tp'] if has_labels else 'n/a'} | "
            f"{counts['fp'] if has_labels else 'n/a'} | "
            f"{counts['fn'] if has_labels else 'n/a'} | "
            f"{counts['tn'] if has_labels else 'n/a'} | {run_display} |"
        )
    return "\n".join(
        [
            START,
            "| AIT-LDS v2.1 scenario | Auth label member | Parsed lines | Labeled lines | Alerts | TP | FP | FN | TN | Labeled runs hit |",
            "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
            *rows,
            "",
            f"Across the publisher's eight scenario archives, {labeled_lines} auth-log lines "
            f"carry attack labels and {run_hits}/{total_runs} contiguous labeled runs contain "
            f"an alert. {false_alerts} alerts fell on unlabeled lines in the seven "
            "label-bearing slices. Labeled lines were "
            "parsed as "
            + ", ".join(f"`{event}` {count}" for event, count in sorted(labeled_types.items()))
            + ". Alert event types were "
            + ", ".join(f"`{event}` {count}" for event, count in sorted(alert_types.items()))
            + ". A run is consecutive labeled line numbers in one file, not an "
            "independently labeled incident. Run coverage does not mean every attack "
            f"step was recognized: {labeled_types.get('log_info', 0)} labeled lines "
            "remained `log_info`. Exact-line alert counts and run hits answer different "
            "questions; neither is incident recall.",
            "",
            "The [AIT-LDS v2.1 publisher](https://zenodo.org/records/19483937) "
            "assigns attack-step labels by original line number. Its enterprise traffic "
            "is simulated in a testbed. Each row is only `intranet_server/auth.log`, not "
            "all hosts or log types in that scenario. `shaw` has no matching publisher "
            "label member; its confusion counts are undefined, not proof that no attack "
            "activity existed. `russellmitchell`, `santos`, and `wardbeck` had been "
            "examined earlier; the other five were included as the remaining publisher "
            "scenarios before their contents were inspected. The detector was not "
            "changed for this comparison. The replay uses the existing file parser, "
            "normalization, SQL windows, alert path, and temporary SQLite with original "
            "log intervals. SOAR, threat feeds, and the shadow model are disabled. "
            "These small same-family slices do not estimate production precision, "
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
        raw, labels_file = directory / "auth.log", directory / "auth.labels.jsonl"
        _, _, _, expected_labels = ait_auth._scenario(name)
        labels = labels_file if expected_labels is not None else None
        if expected_labels is None and (labels_file.exists() or labels_file.is_symlink()):
            print(f"AIT {name} unexpectedly has a cached label file", file=sys.stderr)
            return 2
        if not raw.exists() or (labels is not None and not labels.exists()):
            print(f"AIT {name} files missing; rerun with --fetch", file=sys.stderr)
            return 2
        results[name] = ait_auth.evaluate(raw, labels, scenario=name)
    actual = {"protocol": "ait_lds_v2_1_all_auth_scenarios_v2", "scenarios": results}
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
