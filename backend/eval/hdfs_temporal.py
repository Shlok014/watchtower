"""Time-disjoint HDFS evaluation, separate from the saved dashboard model."""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import sklearn
from sklearn.linear_model import LogisticRegression

from watchtower.detect import features, model
from watchtower.detect.parser import LogParser

START = "<!-- hdfs-temporal:start -->"
END = "<!-- hdfs-temporal:end -->"
ROOT = Path(__file__).resolve().parent.parent.parent
SNAPSHOT = ROOT / "docs" / "hdfs-temporal-eval.json"
METRICS = ROOT / "docs" / "METRICS.md"


def run(dataset=None) -> dict:
    """Rebuild from raw log and labels without touching the production model."""
    dataset = dataset or features.FULL
    parser = LogParser(persist=False)
    X, y, _block_ids, template_ids, stats = features.build_matrix_holdout(
        parser, dataset=dataset, progress_every=0, split_method="time_disjoint"
    )
    train_count = stats["train_blocks"]
    scores = evaluate_matrix(X, y, train_count)
    return {
        "protocol": "hdfs_time_disjoint_source_midpoint_v1",
        "source": {
            "dataset": dataset.label,
            "log_sha256": stats["log_sha256"],
            "labels_sha256": stats["labels_sha256"],
            "raw_lines": stats["lines_read"],
        },
        "split": {
            "method": stats["split_method"],
            "cutoff_line": stats["cutoff_line"],
            "train_blocks": train_count,
            "train_anomalies": int(y[:train_count].sum()),
            "test_blocks": stats["test_blocks"],
            "test_anomalies": int(y[train_count:].sum()),
            "excluded_crossing_blocks": stats["excluded_crossing_blocks"],
        },
        "parsing": {
            "templates_mined_from_train": len(template_ids),
            "held_out_lines": stats["held_out_lines"],
            "held_out_matched_lines": stats["held_out_matched_lines"],
            "held_out_unmatched_lines": stats["held_out_unmatched_lines"],
        },
        "model": {
            "name": "LogisticRegression",
            "params": {"max_iter": 2000, "class_weight": "balanced", "random_state": model.SEED},
            "sklearn": sklearn.__version__,
            "confusion": {key: scores[key] for key in ("tp", "fp", "fn", "tn")},
            "precision": scores["precision"],
            "recall": scores["recall"],
            "f1": scores["f1"],
            "roc_auc": scores["roc_auc"],
        },
        "vector_overlap": vector_overlap(X, y, train_count),
        "limits": [
            "One HDFS corpus and its publisher block labels; no production intrusion labels.",
            "Complete blocks wholly before or after the source-line midpoint; spanning blocks excluded.",
            "Training templates are mined only from pre-cutoff blocks; later lines only match them.",
            "Exact count-vector overlap means this is not a test of wholly new feature patterns.",
            "Live partial-block scoring and the dashboard rule detector are different tasks.",
        ],
    }


def evaluate_matrix(X, y, train_count: int) -> dict:
    if X.ndim != 2 or len(X) != len(y) or not 0 < train_count < len(X):
        raise ValueError("expected a non-empty two-part feature matrix and aligned labels")
    if len(np.unique(y[:train_count])) != 2:
        raise ValueError("training half needs both label classes")
    estimator = LogisticRegression(max_iter=2000, class_weight="balanced", random_state=model.SEED)
    estimator.fit(X[:train_count], y[:train_count])
    return model.evaluate(estimator, X[train_count:], y[train_count:])


def replace_metrics_section(document: str, section: str) -> str:
    block = f"{START}\n{section.rstrip()}\n{END}"
    if START in document or END in document:
        if document.count(START) != 1 or document.count(END) != 1:
            raise ValueError("METRICS.md has an incomplete or duplicate HDFS temporal section")
        before, _, rest = document.partition(START)
        _, _, after = rest.partition(END)
        return before + block + after
    marker = "## HDFS benchmark"
    if document.count(marker) != 1:
        raise ValueError("METRICS.md needs one HDFS benchmark heading")
    before, _, after = document.partition(marker)
    return before.rstrip() + "\n\n" + block + "\n\n" + marker + after


def vector_overlap(X, y, train_count: int) -> dict:
    """Count exact count-vector repeats across the boundary, never infer labels."""
    if X.ndim != 2 or len(X) != len(y) or not 0 < train_count < len(X):
        raise ValueError("expected a non-empty two-part feature matrix and aligned labels")
    rows = np.ascontiguousarray(X).view(np.dtype((np.void, X.dtype.itemsize * X.shape[1]))).ravel()
    _, inverse = np.unique(rows, return_inverse=True)
    train_groups = np.unique(inverse[:train_count])
    test_groups = np.unique(inverse[train_count:])
    seen = np.isin(inverse[train_count:], train_groups)
    test_y = y[train_count:]
    return {
        "distinct_vectors": int(inverse.max()) + 1,
        "train_distinct_vectors": len(train_groups),
        "test_distinct_vectors": len(test_groups),
        "test_rows_seen_in_train": int(seen.sum()),
        "test_positive_seen_in_train": int(seen[test_y == 1].sum()),
        "test_negative_seen_in_train": int(seen[test_y == 0].sum()),
    }


def render_section(result: dict) -> str:
    split = result["split"]
    parsing = result["parsing"]
    score = result["model"]
    confusion = score["confusion"]
    overlap = result["vector_overlap"]
    return "\n".join(
        [
            "## Time-disjoint HDFS validation",
            "",
            "`python -m eval.hdfs_temporal` rebuilds [the frozen result](hdfs-temporal-eval.json) "
            "from the full HDFS log and publisher labels. It does not load or save the "
            "dashboard model or its miner state.",
            "",
            f"The source-line midpoint is line {split['cutoff_line']:,}. "
            f"{split['train_blocks']:,} blocks end before it ({split['train_anomalies']:,} "
            f"anomalous); {split['test_blocks']:,} blocks start after it "
            f"({split['test_anomalies']:,} anomalous). "
            f"{split['excluded_crossing_blocks']:,} blocks span the boundary and are "
            "excluded from both sides. The parser mines templates only on training "
            "lines; later lines may match those templates but cannot create new ones.",
            "",
            "| Model | Precision | Recall | F1 | ROC-AUC | TP | FP | FN | TN |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
            f"| LogisticRegression | {score['precision']:.4f} | {score['recall']:.4f} | "
            f"{score['f1']:.4f} | {score['roc_auc'] if score['roc_auc'] is not None else 'n/a'} | "
            f"{confusion['tp']:,} | {confusion['fp']:,} | {confusion['fn']:,} | "
            f"{confusion['tn']:,} |",
            "",
            f"The training-only miner created {parsing['templates_mined_from_train']} templates. "
            f"Of {parsing['held_out_lines']:,} later log lines, "
            f"{parsing['held_out_matched_lines']:,} matched existing templates and "
            f"{parsing['held_out_unmatched_lines']:,} did not. "
            f"{overlap['test_rows_seen_in_train']:,} of {split['test_blocks']:,} test "
            "blocks have an exact count vector also present in training "
            f"({overlap['test_positive_seen_in_train']:,} of "
            f"{split['test_anomalies']:,} anomalous test blocks). This is a time-separated "
            "block evaluation, not a new-pattern generalization claim.",
            "",
            "The published stratified random-block result below uses a different split "
            "and should not be read as a production estimate. Both runs use complete "
            "HDFS blocks and their publisher labels; neither measures the live partial-block "
            "scorer or the dashboard rule detector.",
        ]
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="freeze JSON and METRICS section")
    args = parser.parse_args(argv)
    if not features.FULL.available():
        print(
            "full HDFS log and labels missing; run python -m datasets.download --hdfs",
            file=sys.stderr,
        )
        return 2
    actual = run(features.FULL)
    encoded = json.dumps(actual, indent=2, sort_keys=True) + "\n"
    expected_document = replace_metrics_section(METRICS.read_text(), render_section(actual))
    if args.write:
        SNAPSHOT.write_text(encoded)
        METRICS.write_text(expected_document)
        print(f"Wrote {SNAPSHOT} and time-disjoint HDFS section of {METRICS}")
        return 0
    if not SNAPSHOT.exists() or SNAPSHOT.read_text() != encoded:
        print("HDFS time-disjoint evidence drifted; regenerate with --write", file=sys.stderr)
        return 1
    if METRICS.read_text() != expected_document:
        print("HDFS time-disjoint METRICS section drifted", file=sys.stderr)
        return 1
    print("HDFS time-disjoint replay matches frozen evidence and METRICS.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
