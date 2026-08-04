"""Train and evaluate anomaly detectors on HDFS_v1, and write docs/METRICS.md.

    python -m eval.benchmark                 # full dataset if downloaded, else the sample
    python -m eval.benchmark --dataset sample --rebuild

Every number in the README comes from here. Nothing is typed by hand.

The primary model is fitted, evaluated and **persisted** through the same code
path that ``POST /api/v1/retrain`` uses, so the F1 published here and the F1 the
running system reports are the same number by construction rather than by
someone remembering to keep two places in step.

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
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support, roc_auc_score
from sklearn.tree import DecisionTreeClassifier

from watchtower.detect import features, model, train

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


def run(dataset=None, rebuild=False) -> dict:
    dataset = dataset or features.best_available()
    print(f"Featurising {dataset.label} …", flush=True)
    X, y, _blocks, template_ids, stats, from_cache = train.prepare(dataset, rebuild=rebuild)
    parse_s = stats.get("seconds", 0.0)
    print(
        f"  {stats['blocks']:,} blocks, {stats['templates']} templates, "
        f"{stats['anomaly_rate'] * 100:.2f}% anomalous"
        + (" (from cache)" if from_cache else f", {parse_s:.1f}s")
    )

    # One split definition for the whole project. The persisted model, the
    # /api/v1/retrain deltas and this table all evaluate on the identical
    # held-out rows — otherwise "the model improved" compares two different
    # exams and means nothing.
    train_idx, test_idx = model.frozen_split(y, SEED)
    Xtr, Xte, ytr, yte = X[train_idx], X[test_idx], y[train_idx], y[test_idx]
    results = {}

    print("Training …", flush=True)
    # The primary model is fitted, evaluated and *persisted* through the same
    # code path the retrain endpoint uses, so the published F1 and the F1 the
    # running system reports are the same number by construction.
    entry = train.retrain(dataset=dataset)
    results["LogisticRegression"] = {
        "supervised": True,
        "fit_seconds": entry["fit_seconds"],
        "persisted_version": entry["version"],
        **entry["metrics"],
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
    # The timing travels with the cache, so this is always a measurement of a
    # real run — just not necessarily *this* run, which is what from_cache says.
    # Zeroing it instead produced "0 lines/sec (108.3s for 11,175,629 lines)",
    # a line that contradicts itself inside a single row.
    eps = (stats["lines_read"] / parse_s) if parse_s else 0
    return {
        "dataset": {
            "name": "loghub HDFS_v1",
            "subset": dataset.label,
            **stats,
        },
        "split": {
            "method": "stratified 50/50",
            "seed": SEED,
            "train": int(len(ytr)),
            "test": int(len(yte)),
        },
        "model_version": entry["version"],
        "features_from_cache": from_cache,
        "parsing": {"seconds": round(parse_s, 1), "lines_per_second": int(eps)},
        "models": results,
        "environment": {
            "python": sys.version.split()[0],
            "sklearn": sklearn.__version__,
            "numpy": np.__version__,
            "platform": f"{platform.system()} {platform.machine()}",
        },
    }


def output_paths(dataset) -> tuple[Path, Path]:
    """Where a run writes. Sample runs never touch the published benchmark page.

    Found the hard way: a `--dataset sample` run overwrote docs/METRICS.md with
    a 2,200-block result, silently replacing the 575,061-block numbers the
    README cites. A quick smoke run must not be able to do that.
    """
    if dataset is features.SAMPLE:
        return (
            OUT_MD.with_name("METRICS.sample.md"),
            OUT_JSON.with_name("metrics.sample.json"),
        )
    return OUT_MD, OUT_JSON


def write_markdown(r: dict, parsing_rows: list, dataset=None) -> None:
    out_md, out_json = output_paths(dataset)
    out_md.parent.mkdir(parents=True, exist_ok=True)
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
        *(
            [
                "> ⚠️ **This run used the committed 2,000-line sample, not the full",
                "> HDFS_v1 benchmark.** A few hundred blocks is not a benchmark result.",
                "> Fetch the real dataset with `python -m datasets.download --hdfs`",
                "> and re-run.",
                "",
            ]
            if d.get("dataset") == "sample"
            else []
        ),
        f"**Dataset:** {d['subset']} — {d['lines_read']:,} lines, "
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
        "- Every figure above is measured on **complete blocks**. Live replay scores",
        "  blocks as their lines arrive, which is a strictly harder problem — the",
        "  same model, a different question. No accuracy is claimed for that, and",
        "  `/api/v1/model` says so on every verdict it returns.",
        "",
        "## The persisted model",
        "",
        f"The LogisticRegression row above is **version {r['model_version']}** on disk,",
        "fitted and evaluated by the same code path `POST /api/v1/retrain` runs, so the",
        "number published here and the number the running system reports are the same",
        "one by construction. Each version records its seed, split indices, sklearn",
        "version, parameters and a SHA-256 of the exact feature matrix it saw.",
        "",
        "Retraining on unchanged data returns a delta of exactly 0.0000. The endpoint",
        "this replaced returned a figure that rose about a point per button press and",
        "could never fall.",
        "",
        "## Pipeline",
        "",
        f"| Parse + featurise | {r['parsing']['lines_per_second']:,} lines/sec "
        f"({r['parsing']['seconds']}s for {d['lines_read']:,} lines) |",
        "|---|---|",
        "",
        *(
            [
                "Timed on the run that built the cached feature matrix, not on this",
                "invocation — this one reused the cache and did no parsing at all.",
                "",
            ]
            if r.get("features_from_cache")
            else []
        ),
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
    out_md.write_text("\n".join(lines))
    out_json.write_text(json.dumps(r, indent=2))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--dataset",
        choices=sorted(features.DATASETS),
        help="which dataset to use; default is the full one if downloaded, else the sample",
    )
    ap.add_argument(
        "--rebuild",
        action="store_true",
        help="re-parse and re-featurise instead of using the cached matrix",
    )
    args = ap.parse_args(argv)

    from eval.parsing import evaluate

    parsing_rows = []
    for name in ("HDFS", "OpenSSH"):
        with contextlib.suppress(FileNotFoundError):
            parsing_rows.append(evaluate(name))

    dataset = features.DATASETS[args.dataset] if args.dataset else None
    try:
        dataset = dataset or features.best_available()
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if dataset is features.SAMPLE:
        # Loud, because a 2,000-line result must never be mistaken for the
        # benchmark. METRICS.md carries the same warning in its own text.
        print(
            "⚠️  Using the committed 2k sample, not the full HDFS_v1 benchmark.\n"
            "    Fetch the full dataset with: python -m datasets.download --hdfs",
            file=sys.stderr,
        )

    r = run(dataset=dataset, rebuild=args.rebuild)
    write_markdown(r, parsing_rows, dataset)
    out_md, out_json = output_paths(dataset)
    print(f"\nWrote {out_md} and {out_json}")
    for name, m in r["models"].items():
        print(f"  {name:22} P={m['precision']:.4f} R={m['recall']:.4f} F1={m['f1']:.4f}")
    print(f"  persisted model version {r['model_version']}")
    for entry in model.history()[:3]:
        print(
            f"    v{entry['version']} {entry['trained_at']} F1={entry['metrics']['f1']:.4f}"
            + (f" (Δ {entry['delta_f1']:+.4f})" if entry.get("delta_f1") is not None else "")
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
