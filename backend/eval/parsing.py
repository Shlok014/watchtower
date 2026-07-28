"""Measure log-parsing accuracy against loghub's ground-truth templates.

The metric is **grouping accuracy**, the one the logparser benchmark reports: a
line counts as correct when the set of lines sharing its predicted template is
exactly the set of lines sharing its true template. It is deliberately strict —
splitting one true template into two predicted ones marks every line in it
wrong, and so does merging two.

Both an easy dataset (HDFS) and a harder one (OpenSSH) are reported. Publishing
only the flattering number would be the same species of dishonesty this project
is built to remove.
"""

import csv
from collections import defaultdict
from pathlib import Path

from detection.parser import LogParser

DATA = Path(__file__).resolve().parent.parent / "data" / "datasets"


def load_ground_truth(name: str):
    """Return (messages, true_event_ids) from loghub's *_structured.csv."""
    path = DATA / f"{name}_2k.log_structured.csv"
    messages, truth = [], []
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            messages.append(row["Content"])
            truth.append(row["EventId"])
    return messages, truth


def grouping_accuracy(predicted, truth) -> float:
    """Fraction of lines whose predicted group exactly equals its true group."""
    by_pred, by_true = defaultdict(set), defaultdict(set)
    for i, (p, t) in enumerate(zip(predicted, truth, strict=False)):
        by_pred[p].add(i)
        by_true[t].add(i)
    correct = 0
    for group in by_true.values():
        # Every line in a true group must share one predicted group, and that
        # predicted group must contain nothing else.
        preds = {predicted[i] for i in group}
        if len(preds) == 1 and by_pred[next(iter(preds))] == group:
            correct += len(group)
    return correct / len(truth)


def evaluate(name: str) -> dict:
    messages, truth = load_ground_truth(name)
    parser = LogParser(stream=f"eval_{name.lower()}", persist=False)
    predicted = [parser.parse(m)[0] for m in messages]
    return {
        "dataset": f"{name}_2k",
        "lines": len(messages),
        "true_templates": len(set(truth)),
        "mined_templates": len(set(predicted)),
        "grouping_accuracy": round(grouping_accuracy(predicted, truth), 4),
    }


def main() -> int:
    rows = []
    for name in ("HDFS", "OpenSSH"):
        if not (DATA / f"{name}_2k.log_structured.csv").exists():
            print(f"  ! {name}_2k missing — run: python -m datasets.download --samples")
            continue
        r = evaluate(name)
        rows.append(r)
        print(
            f"  {r['dataset']:12} lines={r['lines']:>5} "
            f"true={r['true_templates']:>3} mined={r['mined_templates']:>3} "
            f"grouping_accuracy={r['grouping_accuracy']:.4f}"
        )
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
