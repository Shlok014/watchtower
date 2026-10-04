"""The offline report must preserve a genuinely held-out synthetic split."""

from eval import live
from watchtower import config
from watchtower.detect import live_profile


def test_synthetic_groups_are_disjoint_and_training_is_normal_only():
    splits = live.build_scenarios(seed=41)
    group_sets = [
        {row["group"] for row in splits[name]} for name in ("train", "validation", "test")
    ]
    assert all(group_sets)
    assert group_sets[0].isdisjoint(group_sets[1])
    assert group_sets[0].isdisjoint(group_sets[2])
    assert group_sets[1].isdisjoint(group_sets[2])
    for identity in ("source_group", "ip_group"):
        identities = [{row[identity] for row in splits[name]} for name in splits]
        assert identities[0].isdisjoint(identities[1])
        assert identities[0].isdisjoint(identities[2])
        assert identities[1].isdisjoint(identities[2])
    assert {row["label"] for row in splits["train"]} == {0}
    assert {row["label"] for row in splits["test"]} == {0, 1}
    assert all("label" not in row["features"] for group in splits.values() for row in group)


def test_evaluation_is_seed_reproducible_excluding_wall_clock():
    first = live.evaluate(seed=41)
    second = live.evaluate(seed=41)
    first.pop("runtime")
    second.pop("runtime")
    assert first == second
    assert first["profile"]["normal_windows"] == first["split"]["train_windows"]
    assert first["test"]["confusion"]["tp"] + first["test"]["confusion"]["fn"] > 0
    assert first["test"]["misses"]  # Subtle synthetic attacks remain undetected.


def test_report_metrics_use_confusion_denominators():
    report = live.evaluate(seed=41)
    test = report["test"]
    counts = test["confusion"]
    assert test["windows"] == sum(counts.values())
    assert test["precision"] == counts["tp"] / (counts["tp"] + counts["fp"])
    assert test["recall"] == counts["tp"] / (counts["tp"] + counts["fn"])
    assert test["false_positive_rate"] == counts["fp"] / (counts["fp"] + counts["tn"])
    assert report["runtime"]["total_seconds"] >= 0
    assert report["runtime"]["scored_windows"] == (
        report["split"]["validation_windows"] + report["split"]["test_windows"]
    )


def test_demo_profile_can_be_installed_with_reproducible_identity(isolated_config):
    profile = live.fit_demo_profile()
    path = config.get().models_dir / "live-profile.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    live_profile.save_profile(profile, path)
    loaded = live_profile.load_profile(path)
    assert loaded.digest == live.evaluate()["profile"]["digest"]
    assert loaded.source_hash == profile.source_hash
