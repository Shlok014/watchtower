"""Time-disjoint HDFS evidence must expose repeated feature patterns."""

import json

import numpy as np

from eval.hdfs_temporal import (
    METRICS,
    ROOT,
    SNAPSHOT,
    evaluate_matrix,
    render_section,
    replace_metrics_section,
    run,
    vector_overlap,
)


def test_vector_overlap_counts_seen_test_rows_by_label():
    X = np.array(
        [[1, 0], [0, 1], [1, 0], [1, 0], [2, 0], [0, 1], [2, 0]],
        dtype=np.float32,
    )
    y = np.array([0, 1, 0, 1, 1, 0, 0], dtype=np.int8)

    assert vector_overlap(X, y, train_count=3) == {
        "distinct_vectors": 3,
        "train_distinct_vectors": 2,
        "test_distinct_vectors": 3,
        "test_rows_seen_in_train": 2,
        "test_positive_seen_in_train": 1,
        "test_negative_seen_in_train": 1,
    }


def test_time_holdout_scores_later_labels_without_training_on_them():
    X = np.array([[0.0]] * 10 + [[1.0]] * 10 + [[0.0], [1.0]], dtype=np.float32)
    y = np.array([0] * 10 + [1] * 10 + [1, 0], dtype=np.int8)

    result = evaluate_matrix(X, y, train_count=20)

    assert result["tp"] == 0
    assert result["fp"] == 1
    assert result["fn"] == 1
    assert result["tn"] == 0
    assert result["f1"] == 0.0


def test_temporal_section_replacement_preserves_other_results():
    original = (
        "# Measured results\n\n## AIT replay\n\nuntouched\n\n## HDFS benchmark\n\nold benchmark\n"
    )

    first = replace_metrics_section(original, "new temporal evidence")
    second = replace_metrics_section(first, "updated temporal evidence")

    assert second.count("updated temporal evidence") == 1
    assert "new temporal evidence" not in second
    assert "## AIT replay\n\nuntouched" in second
    assert "## HDFS benchmark\n\nold benchmark" in second


def test_published_temporal_figures_match_frozen_result():
    frozen = json.loads(SNAPSHOT.read_text())
    document = METRICS.read_text()
    readme = (ROOT / "README.md").read_text()

    assert replace_metrics_section(document, render_section(frozen)) == document
    assert f"{frozen['model']['f1']:.4f} F1" in readme
    assert f"{frozen['split']['train_blocks']:,} blocks" in readme
    assert f"{frozen['split']['test_blocks']:,} blocks" in readme
    assert f"{frozen['vector_overlap']['test_rows_seen_in_train']:,} test" in readme


def test_temporal_runner_excludes_crossing_blocks_and_does_not_save_model(
    tmp_path, monkeypatch, isolated_config
):
    from watchtower.detect import features, model

    names = [
        "blk_1",
        "blk_2",
        "blk_1",
        "blk_2",
        "blk_3",
        "blk_4",
        "blk_3",
        "blk_4",
        "blk_5",
        "blk_6",
        "blk_5",
        "blk_6",
    ]
    path = tmp_path / "hdfs.log"
    path.write_text(
        "".join(
            f"081109 203615 148 INFO dfs.DataNode: step{index} {block}\n"
            for index, block in enumerate(names, 1)
        )
    )

    class TinyDataset:
        key = "tiny"
        label = "tiny integration fixture"

        def log_path(self):
            return path

        def labels_path(self):
            return features.SAMPLE.labels_path()

    monkeypatch.setattr(
        features,
        "load_labels",
        lambda _dataset: {f"blk_{i}": i % 2 for i in range(1, 7)},
    )

    result = run(TinyDataset())

    assert result["split"]["cutoff_line"] == 6
    assert result["split"]["train_blocks"] == 2
    assert result["split"]["test_blocks"] == 2
    assert result["split"]["excluded_crossing_blocks"] == 2
    assert result["source"]["log_sha256"] == features.file_sha256(path)
    counts = result["model"]["confusion"]
    assert sum(counts.values()) == 2
    assert counts["tp"] + counts["fn"] == 1
    assert model.latest_entry() is None
