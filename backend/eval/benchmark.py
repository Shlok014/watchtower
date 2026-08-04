"""Train and evaluate anomaly detectors on HDFS_v1, and write docs/METRICS.md.

    python -m eval.benchmark                 # full dataset
    python -m eval.benchmark --limit 2000000 # a subset, honestly labelled as one

Every number in the README comes from here. Nothing is typed by hand.

Three models are reported, including one that does noticeably worse:

  LogisticRegression   supervised. Labels exist; refusing to use them would be
                       theatre.
  DecisionTree         supervised, and near-perfect on this benchmark — which is
                       a known property of HDFS count vectors, not evidence of
                       anything clever here.
  IsolationForest      unsupervised, evaluated against the same labels. This is
                       the honest analogue of the live stream, where no labels
                       exist, and it scores much worse. Publishing that is the
                       point: a table where the unsupervised model quietly
                       matched the supervised ones would be a reason to distrust
                       the whole thing.
"""

import argparse
import contextlib
import json
import platform
import sys
import time
from pathlib import Path

import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier

from watchtower import config
from watchtower.detect.features import build_matrix
from watchtower.detect.parser import LogParser

ROOT = Path(__file__).resolve().parent.parent.parent
OUT_MD = ROOT / "docs" / "METRICS.md"
OUT_JSON = ROOT / "docs" / "metrics.json"
SEED = 42


def _scores(y_true, y_pred, y_score=None) -> dict:
    p, r, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    out = {
        "precision": round(float(p), 4),
        "recall": round(float(r), 4),
        "f1": round(float(f1), 4),
        "tp": int(tp),
        "fp": int(fp),
        "fn": int(fn),
        "tn": int(tn),
    }
    if y_score is not None:
        try:
            out["roc_auc"] = round(float(roc_auc_score(y_true, y_score)), 4)
        except ValueError:
            out["roc_auc"] = None
    return out


def run(limit=None) -> dict:
    print("Parsing HDFS.log with Drain3 …", flush=True)
    t0 = time.perf_counter()
    parser = LogParser(stream="hdfs", persist=False)
    X, y, _blocks, template_ids, stats = build_matrix(parser, limit=limit)
    parse_s = time.perf_counter() - t0
    print(
        f"  {stats['blocks']:,} blocks, {stats['templates']} templates, "
        f"{stats['anomaly_rate'] * 100:.2f}% anomalous, {parse_s:.1f}s"
    )

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.5, random_state=SEED, stratify=y)
    results = {}

    print("Training …", flush=True)
    t = time.perf_counter()
    lr = LogisticRegression(max_iter=2000, class_weight="balanced", random_state=SEED)
    lr.fit(Xtr, ytr)
    results["LogisticRegression"] = {
        "supervised": True,
        "fit_seconds": round(time.perf_counter() - t, 2),
        **_scores(yte, lr.predict(Xte), lr.predict_proba(Xte)[:, 1]),
    }

    t = time.perf_counter()
    dt = DecisionTreeClassifier(random_state=SEED)
    dt.fit(Xtr, ytr)
    results["DecisionTree"] = {
        "supervised": True,
        "fit_seconds": round(time.perf_counter() - t, 2),
        **_scores(yte, dt.predict(Xte), dt.predict_proba(Xte)[:, 1]),
    }

    t = time.perf_counter()
    iso = IsolationForest(
        n_estimators=100, contamination=float(max(y.mean(), 1e-4)), random_state=SEED
    )
    iso.fit(Xtr[ytr == 0])  # fit on normal blocks only, as an unsupervised baseline
    pred = (iso.predict(Xte) == -1).astype(int)
    results["IsolationForest"] = {
        "supervised": False,
        "fit_seconds": round(time.perf_counter() - t, 2),
        **_scores(yte, pred, -iso.score_samples(Xte)),
    }

    # Throughput of the parse+featurise stage, which is the real pipeline cost.
    eps = stats["lines_read"] / parse_s if parse_s else 0
    return {
        "dataset": {
            "name": "loghub HDFS_v1",
            "subset": "full" if limit is None else f"first {limit:,} lines",
            **stats,
        },
        "split": {
            "method": "stratified 50/50",
            "seed": SEED,
            "train": int(len(ytr)),
            "test": int(len(yte)),
        },
        "parsing": {"seconds": round(parse_s, 1), "lines_per_second": int(eps)},
        "models": results,
        "environment": {
            "python": sys.version.split()[0],
            "sklearn": sklearn.__version__,
            "numpy": np.__version__,
            "platform": f"{platform.system()} {platform.machine()}",
        },
    }


def write_markdown(r: dict, parsing_rows: list) -> None:
    OUT_MD.parent.mkdir(parents=True, exist_ok=True)
    d, sp = r["dataset"], r["split"]
    lines = [
        "# Measured results",
        "",
        "Generated by `python -m eval.benchmark`. Every number on this page is",
        "produced by that command — none is typed by hand.",
        "",
        "## Log parsing",
        "",
        "Grouping accuracy against loghub's ground-truth templates: a line counts",
        "as correct only when the set of lines sharing its predicted template is",
        "exactly the set sharing its true template.",
        "",
        "| Dataset | Lines | True templates | Mined | Grouping accuracy |",
        "|---|---:|---:|---:|---:|",
    ]
    for p in parsing_rows:
        lines.append(
            f"| {p['dataset']} | {p['lines']:,} | {p['true_templates']} | "
            f"{p['mined_templates']} | **{p['grouping_accuracy']:.4f}** |"
        )
    lines += [
        "",
        "OpenSSH is included deliberately. Drain does markedly worse on it, and a",
        "table showing only the flattering dataset would misrepresent how general",
        "this is.",
        "",
        "## Anomaly detection",
        "",
        f"**Dataset:** {d['name']} ({d['subset']}) — {d['lines_read']:,} lines, "
        f"{d['blocks']:,} labelled blocks, {d['anomalous_blocks']:,} anomalous "
        f"({d['anomaly_rate'] * 100:.2f}%), {d['templates']} mined templates.",
        "",
        f"**Split:** {sp['method']}, seed {sp['seed']} — "
        f"{sp['train']:,} train / {sp['test']:,} held out.",
        "",
        "| Model | Supervised | Precision | Recall | F1 | ROC-AUC | Fit (s) |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for name, m in r["models"].items():
        lines.append(
            f"| {name} | {'yes' if m['supervised'] else 'no'} | {m['precision']:.4f} | "
            f"{m['recall']:.4f} | **{m['f1']:.4f}** | "
            f"{m.get('roc_auc') if m.get('roc_auc') is not None else '—'} | "
            f"{m['fit_seconds']} |"
        )
    best = max(r["models"].items(), key=lambda kv: kv[1]["f1"])
    lines += [
        "",
        f"Confusion matrix for {best[0]} on the held-out half: "
        f"TP {best[1]['tp']:,} · FP {best[1]['fp']:,} · "
        f"FN {best[1]['fn']:,} · TN {best[1]['tn']:,}",
        "",
        "### Reading these numbers honestly",
        "",
        "- HDFS is a **near-separable benchmark**. Supervised scores above 0.95 are",
        "  the expected result for template count vectors on this dataset, not",
        "  evidence of anything novel here. The published loglizer baselines are in",
        "  the same range.",
        "- The IsolationForest row is the one that matters for the live dashboard,",
        "  where no labels exist. It scores substantially worse, and that gap is the",
        "  honest cost of not having ground truth.",
        "- These results describe **HDFS**, not the synthetic stream the dashboard",
        "  shows by default. The two are separate: the dashboard's detection is a",
        "  rule engine, and this page does not claim otherwise.",
        "",
        "## Pipeline",
        "",
        f"| Parse + featurise | {r['parsing']['lines_per_second']:,} lines/sec "
        f"({r['parsing']['seconds']}s for {d['lines_read']:,} lines) |",
        "|---|---|",
        "",
        "## Environment",
        "",
        f"Python {r['environment']['python']} · scikit-learn {r['environment']['sklearn']} · "
        f"numpy {r['environment']['numpy']} · {r['environment']['platform']}",
        "",
        "Reproduce:",
        "",
        "```bash",
        "cd backend",
        "python -m datasets.download --samples --hdfs",
        "python -m eval.benchmark",
        "```",
        "",
    ]
    OUT_MD.write_text("\n".join(lines))
    OUT_JSON.write_text(json.dumps(r, indent=2))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=None, help="only read the first N lines")
    args = ap.parse_args(argv)

    from eval.parsing import evaluate

    parsing_rows = []
    for name in ("HDFS", "OpenSSH"):
        with contextlib.suppress(FileNotFoundError):
            parsing_rows.append(evaluate(name))

    hdfs = config.get().datasets_dir / "HDFS.log"
    if not hdfs.exists():
        print("HDFS.log not present — run: python -m datasets.download --hdfs", file=sys.stderr)
        print("Writing the parsing-only section.", file=sys.stderr)
        write_markdown(
            {
                "dataset": {
                    "name": "loghub HDFS_v1",
                    "subset": "NOT DOWNLOADED",
                    "lines_read": 0,
                    "blocks": 0,
                    "anomalous_blocks": 0,
                    "anomaly_rate": 0,
                    "templates": 0,
                },
                "split": {"method": "—", "seed": SEED, "train": 0, "test": 0},
                "parsing": {"seconds": 0, "lines_per_second": 0},
                "models": {},
                "environment": {
                    "python": sys.version.split()[0],
                    "sklearn": sklearn.__version__,
                    "numpy": np.__version__,
                    "platform": f"{platform.system()} {platform.machine()}",
                },
            },
            parsing_rows,
        )
        return 1

    r = run(limit=args.limit)
    write_markdown(r, parsing_rows)
    print(f"\nWrote {OUT_MD} and {OUT_JSON}")
    for name, m in r["models"].items():
        print(f"  {name:22} P={m['precision']:.4f} R={m['recall']:.4f} F1={m['f1']:.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
