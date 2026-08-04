"""The trained detector: fit it, version it, persist it, load it back.

Two things this module exists to prevent.

**A model that cannot be reproduced.** Every saved version carries the seed, the
split indices, the sklearn version, the digest of the feature matrix it was fit
on, and the ordered template ids that define its columns. A joblib file on its
own is an opaque blob; a joblib file plus that manifest entry is a claim someone
else can check.

**A model scored on template ids it never saw.** The columns are Drain template
ids from the ``hdfs`` miner, and they are only meaningful relative to *that*
miner's state. At inference the parser must ``match()`` — classify against
existing templates — and never ``parse()``, which mints a new template for an
unseen line and hands the model a column index that means nothing. The saved
``template_ids`` list is the contract between the two, and loading a bundle
whose miner has drifted is detected rather than silently scored.

Metrics here are always computed on the frozen held-out split, never on training
data. The split indices are persisted with the model for exactly that reason:
"retrained and improved" is only meaningful if both numbers came from the same
held-out set.
"""

import hashlib
import json
import platform
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from .. import config

SEED = 42
MANIFEST_NAME = "manifest.json"
MODEL_PREFIX = "detector-v"


class ModelUnavailable(RuntimeError):
    """No model has been trained yet, or the saved one cannot be loaded."""


def models_dir() -> Path:
    return config.get().models_dir


def manifest_path() -> Path:
    return models_dir() / MANIFEST_NAME


def load_manifest() -> dict:
    try:
        data = json.loads(manifest_path().read_text())
    except (OSError, ValueError):
        return {"schema": 1, "versions": []}
    if not isinstance(data, dict) or "versions" not in data:
        return {"schema": 1, "versions": []}
    return data


def save_manifest(manifest: dict) -> None:
    d = models_dir()
    d.mkdir(parents=True, exist_ok=True)
    manifest["schema"] = 1
    tmp = d / f".{MANIFEST_NAME}.tmp"
    tmp.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    tmp.replace(manifest_path())


def matrix_digest(X: np.ndarray, y: np.ndarray) -> str:
    """A digest of the exact data a version was fit on.

    ``X.tobytes()`` rather than a hash of the file: the same log parsed with a
    different masking config produces a different matrix from an identical file,
    and it is the matrix the model actually saw.
    """
    h = hashlib.sha256()
    h.update(np.ascontiguousarray(X).tobytes())
    h.update(np.ascontiguousarray(y).tobytes())
    h.update(str(X.shape).encode())
    return h.hexdigest()


# ─── training ────────────────────────────────────────────────────────────────
def frozen_split(y: np.ndarray, seed: int = SEED):
    """Stratified 50/50 indices. Same seed and same y ⇒ same split, always."""
    from sklearn.model_selection import train_test_split

    idx = np.arange(len(y))
    train_idx, test_idx = train_test_split(idx, test_size=0.5, random_state=seed, stratify=y)
    return np.sort(train_idx), np.sort(test_idx)


def evaluate(estimator, X_test, y_test) -> dict:
    from sklearn.metrics import (
        confusion_matrix,
        precision_recall_fscore_support,
        roc_auc_score,
    )

    pred = estimator.predict(X_test)
    p, r, f1, _ = precision_recall_fscore_support(y_test, pred, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_test, pred, labels=[0, 1]).ravel()
    out = {
        "precision": round(float(p), 4),
        "recall": round(float(r), 4),
        "f1": round(float(f1), 4),
        "tp": int(tp),
        "fp": int(fp),
        "fn": int(fn),
        "tn": int(tn),
    }
    try:
        out["roc_auc"] = round(
            float(roc_auc_score(y_test, estimator.predict_proba(X_test)[:, 1])), 4
        )
    except (ValueError, AttributeError):
        # A single-class held-out set has no ROC-AUC. Reported as null rather
        # than as a number that would have to be invented.
        out["roc_auc"] = None
    return out


def fit(X, y, seed: int = SEED):
    """Fit the primary supervised model on the frozen training half."""
    from sklearn.linear_model import LogisticRegression

    train_idx, test_idx = frozen_split(y, seed)
    est = LogisticRegression(max_iter=2000, class_weight="balanced", random_state=seed)
    t0 = time.perf_counter()
    est.fit(X[train_idx], y[train_idx])
    fit_seconds = round(time.perf_counter() - t0, 3)
    metrics = evaluate(est, X[test_idx], y[test_idx])
    return est, metrics, train_idx, test_idx, fit_seconds


# ─── persistence ─────────────────────────────────────────────────────────────
@dataclass
class Bundle:
    version: int
    estimator: object
    template_ids: list[int]
    metrics: dict
    meta: dict = field(default_factory=dict)

    @property
    def n_features(self) -> int:
        return len(self.template_ids)


def next_version() -> int:
    versions = [v["version"] for v in load_manifest()["versions"]]
    return (max(versions) + 1) if versions else 1


def save(
    estimator,
    template_ids: list[int],
    metrics: dict,
    *,
    dataset: dict,
    train_idx,
    test_idx,
    fit_seconds: float,
    data_sha256: str,
    seed: int = SEED,
    prev_metrics: dict | None = None,
) -> dict:
    """Persist a fitted model and append its manifest entry. Returns the entry."""
    import joblib
    import sklearn

    d = models_dir()
    d.mkdir(parents=True, exist_ok=True)
    version = next_version()
    path = d / f"{MODEL_PREFIX}{version}.joblib"

    joblib.dump(
        {
            "estimator": estimator,
            # Column order IS the contract. Stored inside the artefact as well
            # as in the manifest, so a bundle separated from its manifest is
            # still self-describing rather than a silently mis-indexed model.
            "template_ids": list(template_ids),
            "version": version,
        },
        path,
    )
    # Split indices, not just their sizes: "retrained and improved" is only
    # meaningful if the before and after numbers came from the same held-out
    # rows, and that has to be checkable after the fact.
    np.savez_compressed(
        d / f"{MODEL_PREFIX}{version}-split.npz",
        train_idx=np.asarray(train_idx),
        test_idx=np.asarray(test_idx),
    )

    entry = {
        "version": version,
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "estimator": type(estimator).__name__,
        "params": {k: _jsonable(v) for k, v in estimator.get_params().items()},
        "fit_seconds": fit_seconds,
        "metrics": metrics,
        "prev_metrics": prev_metrics,
        "delta_f1": (round(metrics["f1"] - prev_metrics["f1"], 4) if prev_metrics else None),
        "dataset": dataset,
        "data_sha256": data_sha256,
        "seed": seed,
        "n_features": len(template_ids),
        "train_rows": int(len(train_idx)),
        "test_rows": int(len(test_idx)),
        "sklearn": sklearn.__version__,
        "numpy": np.__version__,
        "python": sys.version.split()[0],
        "platform": f"{platform.system()} {platform.machine()}",
        "artifact": path.name,
    }
    manifest = load_manifest()
    manifest["versions"].append(entry)
    save_manifest(manifest)
    return entry


def _jsonable(value):
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def latest_entry() -> dict | None:
    versions = load_manifest()["versions"]
    return max(versions, key=lambda v: v["version"]) if versions else None


def load_latest() -> Bundle:
    entry = latest_entry()
    if entry is None:
        raise ModelUnavailable(
            "no trained model — run `python -m eval.benchmark` or POST /api/v1/retrain"
        )
    import joblib

    path = models_dir() / entry["artifact"]
    try:
        blob = joblib.load(path)
    except Exception as exc:
        raise ModelUnavailable(
            f"model {entry['version']} at {path} could not be loaded: {exc}"
        ) from exc

    if len(blob["template_ids"]) != entry["n_features"]:
        # The manifest and the artefact disagree about the column space. Scoring
        # anyway would produce numbers, which is worse than producing none.
        raise ModelUnavailable(
            f"model {entry['version']} has {len(blob['template_ids'])} columns but its "
            f"manifest says {entry['n_features']} — refusing to score"
        )
    return Bundle(
        version=entry["version"],
        estimator=blob["estimator"],
        template_ids=list(blob["template_ids"]),
        metrics=entry["metrics"],
        meta=entry,
    )


def history() -> list[dict]:
    """Every version, newest first, with the numbers each one actually scored."""
    return sorted(load_manifest()["versions"], key=lambda v: v["version"], reverse=True)
