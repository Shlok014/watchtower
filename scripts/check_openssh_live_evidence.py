#!/usr/bin/env python3
"""Check the frozen real-log alert-burden comparison against a fresh replay."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from eval import openssh_live  # noqa: E402

SNAPSHOT = ROOT / "docs" / "openssh-live-replay.json"
METRICS = ROOT / "docs" / "METRICS.md"
START = "<!-- openssh-live-metrics:start -->"
END = "<!-- openssh-live-metrics:end -->"


def summary(data: dict) -> str:
    with_cooldown = data["with_cooldown"]
    without = data["without_cooldown"]
    return "\n".join(
        [
            START,
            "| Replay policy | Parsed events | Alerts | Alerted IPs |",
            "|---|---:|---:|---:|",
            f"| No cooldown | {data['parsed_events']:,} | {without['alerts']} | {without['alerted_ips']} |",
            f"| {with_cooldown['policy']} | {data['parsed_events']:,} | {with_cooldown['alerts']} | {with_cooldown['alerted_ips']} |",
            "",
            f"The same {data['source']['lines']:,} OpenSSH log lines produced "
            f"**{without['alerts'] - with_cooldown['alerts']} fewer repeated alerts** "
            "with the cooldown. The alerted IP set is identical in both runs, "
            "checked by its digest in the frozen JSON. "
            "The source has no independent incident labels, so these counts measure "
            "alert burden, not precision, recall, or false-alarm rate.",
            END,
        ]
    )


def replace_summary(document: str, replacement: str) -> str:
    if document.count(START) != 1 or document.count(END) != 1:
        raise ValueError("METRICS.md must contain exactly one OpenSSH live section")
    before, rest = document.split(START, 1)
    _, after = rest.split(END, 1)
    return before + replacement + after


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="regenerate the frozen evidence")
    args = parser.parse_args()
    actual = openssh_live.compare()
    encoded = json.dumps(actual, indent=2, sort_keys=True) + "\n"
    document = METRICS.read_text()
    expected_document = replace_summary(document, summary(actual))
    if args.write:
        SNAPSHOT.write_text(encoded)
        METRICS.write_text(expected_document)
        print(f"Wrote {SNAPSHOT} and OpenSSH section of {METRICS}")
        return 0
    if not SNAPSHOT.exists() or SNAPSHOT.read_text() != encoded:
        print("OpenSSH live evidence drifted; regenerate with --write", file=sys.stderr)
        return 1
    if document != expected_document:
        print("OpenSSH live METRICS section drifted", file=sys.stderr)
        return 1
    print("OpenSSH live replay matches frozen evidence and METRICS.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
