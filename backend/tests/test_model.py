"""The trained detector: versioning, persistence, and the retrain contract.

The endpoint these back used to be, in full:

    prev_acc = round(0.90 + (version - 2) * 0.01 + random.uniform(0, 0.02), 4)

so the tests that matter most here are the ones that would fail if a number
started improving on its own.
"""

import json

import numpy as np
import pytest

from watchtower.app import API_PREFIX, create_app
from watchtower.detect import features, model, stream, train


@pytest.fixture()
def tiny_data():
    """A small separable problem: three columns, the third predicts the label."""
    rng = np.random.default_rng(0)
    n = 400
    X = rng.integers(0, 5, size=(n, 3)).astype(np.float32)
    y = (X[:, 2] > 2).astype(np.int8)
    # Guarantee both classes survive the stratified split.
    y[:20] = 1
    y[20:40] = 0
    return X, y


# ─── the split ───────────────────────────────────────────────────────────────
def test_the_split_is_frozen(tiny_data):
    """Same seed, same y ⇒ same held-out rows, or 'improved' compares two exams."""
    _, y = tiny_data
    a_train, a_test = model.frozen_split(y)
    b_train, b_test = model.frozen_split(y)
    assert np.array_equal(a_train, b_train)
    assert np.array_equal(a_test, b_test)
    assert set(a_train.tolist()) & set(a_test.tolist()) == set(), "train and test overlap"
    assert len(a_train) + len(a_test) == len(y)


def test_metrics_come_from_held_out_rows_only(tiny_data):
    X, y = tiny_data
    est, metrics, train_idx, test_idx, _ = model.fit(X, y)
    # Recomputing on the same held-out rows must reproduce the numbers exactly.
    assert model.evaluate(est, X[test_idx], y[test_idx]) == metrics


# ─── persistence ─────────────────────────────────────────────────────────────
def _save(X, y, template_ids=(0, 1, 2), prev=None):
    est, metrics, train_idx, test_idx, fit_s = model.fit(X, y)
    return model.save(
        est,
        list(template_ids),
        metrics,
        dataset={"key": "test", "label": "unit test", "blocks": len(y)},
        train_idx=train_idx,
        test_idx=test_idx,
        fit_seconds=fit_s,
        data_sha256=model.matrix_digest(X, y),
        prev_metrics=prev,
    )


def test_no_model_is_an_error_not_a_zero():
    """'No model' must be distinguishable from 'a model that scores 0'."""
    with pytest.raises(model.ModelUnavailable, match="no trained model"):
        model.load_latest()
    assert model.latest_entry() is None


def test_saving_then_loading_round_trips(tiny_data):
    X, y = tiny_data
    est, metrics, train_idx, test_idx, fit_s = model.fit(X, y)
    before = est.predict(X).tolist()
    model.save(
        est,
        [0, 1, 2],
        metrics,
        dataset={"key": "test", "label": "unit test", "blocks": len(y)},
        train_idx=train_idx,
        test_idx=test_idx,
        fit_seconds=fit_s,
        data_sha256=model.matrix_digest(X, y),
    )

    bundle = model.load_latest()
    assert bundle.version == 1
    assert bundle.template_ids == [0, 1, 2]
    assert bundle.metrics == metrics
    # The estimator that comes back off disk makes the identical predictions.
    # A bundle that loads but scores differently is the failure mode worth
    # catching, and it is invisible to a "did it load" assertion.
    assert bundle.estimator.predict(X).tolist() == before


def test_versions_increment_and_keep_their_own_numbers(tiny_data):
    X, y = tiny_data
    first = _save(X, y)
    second = _save(X, y, prev=first["metrics"])
    assert (first["version"], second["version"]) == (1, 2)
    assert [e["version"] for e in model.history()] == [2, 1]
    assert model.load_latest().version == 2


def test_retraining_on_identical_data_reports_a_zero_delta(tiny_data):
    """The single most important assertion in this file.

    The endpoint this replaced returned an accuracy that rose about a point per
    button press and could never fall.
    """
    X, y = tiny_data
    first = _save(X, y)
    second = _save(X, y, prev=first["metrics"])
    assert second["delta_f1"] == 0.0
    assert second["metrics"] == first["metrics"]


def test_every_version_records_what_would_be_needed_to_check_it(tiny_data):
    X, y = tiny_data
    entry = _save(X, y)
    for key in (
        "seed",
        "data_sha256",
        "sklearn",
        "params",
        "train_rows",
        "test_rows",
        "n_features",
    ):
        assert entry.get(key) is not None, f"manifest entry lost {key}"
    # And the split indices are on disk, not merely their sizes.
    split = np.load(model.models_dir() / f"{model.MODEL_PREFIX}1-split.npz")
    assert len(split["train_idx"]) == entry["train_rows"]
    assert len(split["test_idx"]) == entry["test_rows"]


def test_matrix_digest_changes_when_the_data_does(tiny_data):
    X, y = tiny_data
    other = X.copy()
    other[0, 0] += 1
    assert model.matrix_digest(X, y) != model.matrix_digest(other, y)


def test_a_manifest_that_disagrees_with_its_artifact_refuses_to_score(tiny_data):
    """Scoring with the wrong column count produces numbers, which is worse than none."""
    X, y = tiny_data
    _save(X, y)
    manifest = model.load_manifest()
    manifest["versions"][0]["n_features"] = 99
    model.save_manifest(manifest)
    with pytest.raises(model.ModelUnavailable, match="refusing to score"):
        model.load_latest()


# ─── training refusals ───────────────────────────────────────────────────────
def test_training_refuses_a_single_class(monkeypatch):
    """One class is not a classification problem; a fit on it looks perfect and isn't.

    Driven through ``train.retrain`` rather than ``model.fit`` so the message
    the API returns is the one under test — sklearn's own error names a
    parameter, which is not something an operator can act on.
    """
    X = np.ones((50, 3), dtype=np.float32)
    y = np.zeros(50, dtype=np.int8)
    monkeypatch.setattr(
        train, "prepare", lambda dataset=None, rebuild=False: (X, y, [], [0, 1, 2], {}, True)
    )
    with pytest.raises(ValueError, match="only one class"):
        train.retrain()


def test_training_refuses_an_empty_dataset(monkeypatch):
    empty = np.zeros((0, 3), dtype=np.float32)
    monkeypatch.setattr(
        train,
        "prepare",
        lambda dataset=None, rebuild=False: (
            empty,
            np.zeros(0, dtype=np.int8),
            [],
            [0, 1, 2],
            {},
            True,
        ),
    )
    with pytest.raises(ValueError, match="nothing to train on"):
        train.retrain()


# ─── the sample dataset ──────────────────────────────────────────────────────
def test_the_committed_sample_is_trainable_with_no_downloads():
    """A clean clone must be able to produce a model, however weak."""
    assert features.SAMPLE.available(), "the 2k sample and its labels must be committed"
    entry = train.retrain(dataset=features.SAMPLE, rebuild=True)
    assert entry["version"] == 1
    assert entry["dataset"]["key"] == "sample"
    assert entry["dataset"]["blocks"] > 100
    # Deliberately not asserting a good score. 2,200 blocks and 16 templates is
    # not the benchmark, and a threshold here would quietly turn it into one.
    assert 0.0 <= entry["metrics"]["f1"] <= 1.0


def test_sample_results_never_overwrite_the_published_benchmark_page():
    """A `--dataset sample` run once replaced the 575,061-block METRICS.md."""
    from eval.benchmark import output_paths

    full_md, full_json = output_paths(features.FULL)
    sample_md, sample_json = output_paths(features.SAMPLE)
    assert full_md.name == "METRICS.md"
    assert sample_md.name == "METRICS.sample.md"
    assert sample_json != full_json


# ─── live block scoring ──────────────────────────────────────────────────────
class _FakeParser:
    """Returns a known template id, or None for 'matched nothing'."""

    def __init__(self, cid=0):
        self.cid = cid

    def match(self, message):
        return (self.cid, "t") if self.cid is not None else (None, None)


def _bundle(n_features=3):
    est, _, _, _, _ = model.fit(
        np.array([[0, 0, 1], [0, 0, 4], [1, 0, 0], [3, 0, 0]] * 40, dtype=np.float32),
        np.array([1, 1, 0, 0] * 40, dtype=np.int8),
    )
    return model.Bundle(version=1, estimator=est, template_ids=list(range(n_features)), metrics={})


HDFS = "081109 203615 148 INFO dfs.DataNode: Received block blk_123 of size 67108864"


def test_scorer_accumulates_per_block():
    scorer = stream.BlockScorer(_bundle(), _FakeParser(cid=0))
    scorer.observe(HDFS)
    verdicts = scorer.observe(HDFS)
    assert verdicts[0]["block"] == "blk_123"
    assert verdicts[0]["lines"] == 2
    assert 0.0 <= verdicts[0]["probability"] <= 1.0


def test_every_verdict_states_it_is_a_partial_block():
    """The published F1 was measured on complete blocks and must not be borrowed."""
    scorer = stream.BlockScorer(_bundle(), _FakeParser(cid=0))
    v = scorer.observe(HDFS)[0]
    assert "partial block" in v["basis"]


def test_unmatched_lines_are_counted_not_dropped():
    """A rising unmatched rate is the honest signal that the miner has drifted."""
    scorer = stream.BlockScorer(_bundle(), _FakeParser(cid=None))
    scorer.observe(HDFS)
    assert scorer.unmatched == 1
    assert scorer.stats()["unmatched_lines"] == 1


def test_a_template_outside_the_models_columns_is_reported_separately():
    """'Matched nothing' and 'matched something the model never saw' differ."""
    scorer = stream.BlockScorer(_bundle(n_features=3), _FakeParser(cid=999))
    scorer.observe(HDFS)
    assert scorer.out_of_vocabulary == 1
    assert scorer.unmatched == 0


def test_block_tracking_is_bounded():
    """575,061 blocks would be a leak that looks like a working detector."""
    scorer = stream.BlockScorer(_bundle(), _FakeParser(cid=0), max_blocks=5)
    for i in range(20):
        scorer.observe(HDFS.replace("blk_123", f"blk_{i}"))
    assert len(scorer._blocks) == 5
    assert scorer.evicted == 15


def test_lines_without_a_block_id_produce_no_verdict():
    scorer = stream.BlockScorer(_bundle(), _FakeParser(cid=0))
    assert scorer.observe("081109 203615 148 INFO dfs.FSNamesystem: nothing here") == []


# ─── the API ─────────────────────────────────────────────────────────────────
@pytest.fixture()
def client():
    app = create_app(start_sources=False)
    app.config.update(TESTING=True)
    with app.test_client() as c:
        yield c


def test_model_endpoint_says_untrained_before_anything_is_trained(client):
    body = client.get(f"{API_PREFIX}/model").get_json()
    assert body["trained"] is False
    assert body["current"] is None
    assert body["live_scoring"] is None
    # And it distinguishes the rule engine from the model, in words.
    assert "rule set" in body["rules"]["note"]


def test_retrain_returns_measured_numbers_and_a_real_delta(client, tiny_data):
    r = client.post(f"{API_PREFIX}/retrain")
    assert r.status_code == 200, r.get_json()
    first = r.get_json()
    assert first["status"] == "trained"
    assert first["dataset"]["key"] == "sample"
    assert first["prev_metrics"] is None

    second = client.post(f"{API_PREFIX}/retrain").get_json()
    assert second["version"] == first["version"] + 1
    # The whole point: identical data, identical result, zero improvement.
    assert second["delta_f1"] == 0.0
    assert second["metrics"] == first["metrics"]
    # No fabricated fields from the endpoint this replaced.
    for gone in ("previous_accuracy", "new_accuracy", "improvement", "epochs"):
        assert gone not in second


def test_retrain_output_is_json_serialisable(client):
    """sklearn params are not, and a 500 here would read as 'retrain failed'."""
    body = client.post(f"{API_PREFIX}/retrain").get_json()
    json.dumps(body)
    assert isinstance(body["params"], dict)
