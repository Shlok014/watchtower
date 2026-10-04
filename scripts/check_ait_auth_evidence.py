#!/usr/bin/env python3
"""Replay the pinned AIT auth-log slice and compare its frozen evidence."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from eval import ait_auth  # noqa: E402

DATA = ROOT / "backend" / "data" / "datasets" / "ait-russellmitchell-auth"
SNAPSHOT = ROOT / "docs" / "ait-auth-eval.json"
METRICS = ROOT / "docs" / "METRICS.md"
START = "<!-- ait-auth-metrics:start -->"
END = "<!-- ait-auth-metrics:end -->"


def summary(data: dict) -> str:
    counts = data["confusion"]
    precision = (
        "undefined because the detector emitted no alerts"
        if data["precision"] is None
        else f"{data['precision']:.3f} on this exact-line slice"
    )
    return "\n".join(
        [
            START,
            "| Source slice | Parsed lines | Publisher-labeled attack lines | Alerted lines | TP | FP | FN | TN |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
            f"| AIT-LDS v2.1 `russellmitchell/intranet_server/auth.log` | {data['parsed_events']} | "
            f"{data['attack_lines']} | {data['alerts']} | {counts['tp']} | {counts['fp']} | "
            f"{counts['fn']} | {counts['tn']} |",
            "",
            f"The current file parser classifies {data['event_counts'].get('log_info', 0)} "
            f"of {data['parsed_events']} lines as `log_info`; the live rules alert on "
            f"**{counts['tp']} of {data['attack_lines']}** publisher-labeled "
            f"privilege-escalation lines. Exact-line recall is {data['recall']:.3f}; "
            f"precision is {precision}. {counts['fp']} false positives on this slice do not "
            "establish a production false-alarm rate.",
            "",
            "The [AIT-LDS v2.1 publisher](https://zenodo.org/records/19483937) "
            "assigns attack-step labels by original line number. Its enterprise "
            f"traffic is simulated in a testbed, and this is one {data['raw_lines']}-line auth-log "
            "slice from one host. The replay uses the existing file parser, "
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
    if args.fetch:
        ait_auth.fetch_subset(DATA)
    raw, labels = DATA / "auth.log", DATA / "auth.labels.jsonl"
    if not raw.exists() or not labels.exists():
        print("AIT files missing; rerun with --fetch", file=sys.stderr)
        return 2
    actual = ait_auth.evaluate(raw, labels)
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
