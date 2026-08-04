"""Build the feature matrix, fit the detector, persist a version.

Shared by ``eval.benchmark`` (which also reports the comparison models) and by
``POST /api/v1/retrain`` (which does not). Both go through here so that a model
trained from an HTTP request and a model trained from the command line are the
same artefact, produced the same way, recorded in the same manifest.

The endpoint used to be this, in full:

    prev_acc = round(0.90 + (version - 2) * 0.01 + random.uniform(0, 0.02), 4)

— an accuracy that rose about a point per button press and could never fall.
What replaces it can, and does, return a delta of exactly 0.0000 when nothing
changed, because that is the honest answer to retraining on identical data.
"""

import time

from . import features, model


def prepare(dataset: features.Dataset | None = None, rebuild: bool = False):
    """Return (X, y, block_ids, template_ids, stats, from_cache).

    Parsing the full dataset takes ~170 seconds, which an HTTP request cannot
    pay. More importantly, re-parsing re-mines the templates, so the column
    space could shift underneath two models that are meant to be comparable.
    The cache holds the matrix and the template ids together for that reason.
    """
    dataset = dataset or features.best_available()
    if not rebuild:
        cached = features.load_cache(dataset)
        if cached is not None:
            X, y, block_ids, template_ids, stats = cached
            return X, y, block_ids, template_ids, stats, True

    # reset=True: a fresh miner. Continuing from a previous run's state mines
    # templates on top of templates and the column count drifts between runs.
    from .parser import LogParser

    miner = LogParser(stream="hdfs", persist=True, reset=True)
    X, y, block_ids, template_ids, stats = features.build_matrix(miner, dataset=dataset)
    # The miner state IS the column space. Persisting it is what lets live
    # scoring later ask match() the same question the training run asked parse().
    miner.save("benchmark")
    features.save_cache(dataset, X, y, block_ids, template_ids, stats)
    return X, y, block_ids, template_ids, stats, False


def retrain(dataset: features.Dataset | None = None, rebuild: bool = False) -> dict:
    """Fit, evaluate on the frozen held-out half, persist, return the entry."""
    t0 = time.perf_counter()
    X, y, _blocks, template_ids, stats, from_cache = prepare(dataset, rebuild)

    if len(y) == 0:
        raise ValueError("no labelled blocks — nothing to train on")
    if len(set(y.tolist())) < 2:
        # One class is not a classification problem. Fitting anyway produces a
        # model with perfect apparent accuracy and no ability to discriminate.
        raise ValueError(f"only one class present in {len(y)} labelled blocks — refusing to fit")

    prev = model.latest_entry()
    estimator, metrics, train_idx, test_idx, fit_seconds = model.fit(X, y)
    entry = model.save(
        estimator,
        template_ids,
        metrics,
        dataset={
            "key": stats.get("dataset"),
            "label": stats.get("dataset_label"),
            "lines_read": stats.get("lines_read"),
            "blocks": stats.get("blocks"),
            "anomalous_blocks": stats.get("anomalous_blocks"),
            "anomaly_rate": stats.get("anomaly_rate"),
            "templates": stats.get("templates"),
        },
        train_idx=train_idx,
        test_idx=test_idx,
        fit_seconds=fit_seconds,
        data_sha256=model.matrix_digest(X, y),
        prev_metrics=prev["metrics"] if prev else None,
    )
    entry["features_from_cache"] = from_cache
    entry["total_seconds"] = round(time.perf_counter() - t0, 2)
    return entry
