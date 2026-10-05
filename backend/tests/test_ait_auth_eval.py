"""Source fidelity and line-label checks for the AIT auth-log replay."""

import hashlib
import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from eval import ait_auth
from watchtower import config
from watchtower.store import db


def _zip_bytes(members):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in members.items():
            archive.writestr(name, value)
    return stream.getvalue()


def test_range_reader_extracts_only_pinned_members(tmp_path):
    raw = b"Jan 24 04:37:40 host su: test\n"
    labels = b'{"line":1,"labels":["escalate"]}\n'
    data = _zip_bytes(
        {
            ait_auth.RAW_MEMBER: raw,
            ait_auth.LABEL_MEMBER: labels,
            "gather/other/private.txt": b"do not extract",
        }
    )
    requested = []

    def fetch(start, end):
        requested.append((start, end))
        return data[start : end + 1]

    reader = ait_auth.RangeReader(len(data), fetch, block_size=64)
    with zipfile.ZipFile(reader) as archive:
        paths = ait_auth.extract_subset(
            archive,
            tmp_path,
            raw_hash=hashlib.sha256(raw).hexdigest(),
            label_hash=hashlib.sha256(labels).hexdigest(),
        )
    assert [path.read_bytes() for path in paths] == [raw, labels]
    assert sorted(path.name for path in tmp_path.iterdir()) == ["auth.labels.jsonl", "auth.log"]
    assert requested


def test_subset_rejects_wrong_hash_and_existing_replacement(tmp_path):
    raw = b"raw"
    labels = b"labels"
    data = _zip_bytes({ait_auth.RAW_MEMBER: raw, ait_auth.LABEL_MEMBER: labels})
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        with pytest.raises(ValueError, match="SHA-256"):
            ait_auth.extract_subset(archive, tmp_path, raw_hash="0" * 64, label_hash="0" * 64)
        (tmp_path / "auth.log").write_bytes(b"replaced")
        with pytest.raises(ValueError, match="existing"):
            ait_auth.extract_subset(
                archive,
                tmp_path,
                raw_hash=hashlib.sha256(raw).hexdigest(),
                label_hash=hashlib.sha256(labels).hexdigest(),
            )


def test_subset_rejects_oversized_member(tmp_path):
    raw = b"x" * (ait_auth.MAX_MEMBER_BYTES + 1)
    data = _zip_bytes({ait_auth.RAW_MEMBER: raw, ait_auth.LABEL_MEMBER: b"labels"})
    with (
        zipfile.ZipFile(io.BytesIO(data)) as archive,
        pytest.raises(ValueError, match="size limit"),
    ):
        ait_auth.extract_subset(
            archive,
            tmp_path,
            raw_hash=hashlib.sha256(raw).hexdigest(),
            label_hash=hashlib.sha256(b"labels").hexdigest(),
        )


def test_no_label_scenario_extracts_only_raw_and_rejects_unexpected_labels(tmp_path):
    raw = b"Jan 24 04:37:40 host app: routine event\n"
    raw_hash = hashlib.sha256(raw).hexdigest()
    raw_only = _zip_bytes({ait_auth.RAW_MEMBER: raw})
    with zipfile.ZipFile(io.BytesIO(raw_only)) as archive:
        paths = ait_auth.extract_subset(archive, tmp_path, raw_hash=raw_hash, label_hash=None)
    assert paths == (tmp_path / "auth.log", None)
    assert sorted(path.name for path in tmp_path.iterdir()) == ["auth.log"]

    mislabeled = _zip_bytes({ait_auth.RAW_MEMBER: raw, ait_auth.LABEL_MEMBER: b"unexpected"})
    with (
        zipfile.ZipFile(io.BytesIO(mislabeled)) as archive,
        pytest.raises(ValueError, match="unexpected label member"),
    ):
        ait_auth.extract_subset(archive, tmp_path, raw_hash=raw_hash, label_hash=None)


def test_range_request_rejects_server_that_ignores_range(monkeypatch):
    class Response:
        status = 200
        headers = {"Content-Range": ""}

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def read(self, size):
            return b"x" * size

    monkeypatch.setattr(ait_auth.urllib.request, "urlopen", lambda *args, **kwargs: Response())
    with pytest.raises(ValueError, match="range"):
        ait_auth.http_range(0, 15)


def test_range_request_retries_transient_short_body(monkeypatch):
    bodies = iter((b"too short", b"x" * 16))

    class Response:
        status = 206
        headers = {"Content-Range": f"bytes 0-15/{ait_auth.ARCHIVE_SIZE}"}

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def read(self, size):
            return next(bodies)

    monkeypatch.setattr(ait_auth.urllib.request, "urlopen", lambda *args, **kwargs: Response())
    assert ait_auth.http_range(0, 15) == b"x" * 16


@pytest.mark.parametrize(
    "labels",
    [
        '{"line":1,"labels":["escalate"]}\n{"line":1,"labels":["escalate"]}\n',
        '{"line":11,"labels":["escalate"]}\n',
        '{"line":true,"labels":["escalate"]}\n',
        '{"line":1,"labels":[]}\n',
    ],
)
def test_label_lines_must_be_unique_in_range_and_nonempty(labels):
    with pytest.raises(ValueError, match="label"):
        ait_auth.parse_labels(labels, 10)


def test_replay_matches_alerts_to_original_line_numbers(tmp_path, monkeypatch):
    raw = "".join(
        f"Jan 24 04:37:40 intranet-server CRON[{i}]: session opened\n" for i in range(1, 11)
    ).encode()
    labels = (json.dumps({"line": 9, "labels": ["attack_step"]}) + "\n").encode()
    raw_path = tmp_path / "auth.log"
    labels_path = tmp_path / "auth.labels.jsonl"
    raw_path.write_bytes(raw)
    labels_path.write_bytes(labels)
    monkeypatch.setattr(ait_auth, "RAW_SHA256", hashlib.sha256(raw).hexdigest())
    monkeypatch.setattr(ait_auth, "LABEL_SHA256", hashlib.sha256(labels).hexdigest())

    before_config = config.get()
    before_path = db.path()
    result = ait_auth.evaluate(raw_path, labels_path, threshold=0.1)
    assert result["raw_lines"] == result["parsed_events"] == 10
    assert result["attack_lines"] == 1
    assert result["alerts"] == 1
    assert result["confusion"] == {"tp": 1, "fp": 0, "fn": 0, "tn": 9}
    assert result["labeled_event_counts"] == {"log_info": 1}
    assert result["alert_event_counts"] == {"log_info": 1}
    assert result["precision"] == result["recall"] == 1.0
    assert result["alert_line_numbers"] == [9]
    assert result["publisher_rule_coverage"] == {}
    assert config.get() is before_config
    assert db.path() == before_path


def test_replay_rejects_unpinned_source(tmp_path):
    raw = tmp_path / "auth.log"
    labels = tmp_path / "auth.labels.jsonl"
    raw.write_text("not the publisher's file\n")
    labels.write_text('{"line":1,"labels":["attack"]}\n')
    with pytest.raises(ValueError, match="SHA-256"):
        ait_auth.evaluate(raw, labels)


def test_no_label_replay_reports_undefined_recall(tmp_path, monkeypatch):
    raw = b"Jan 24 04:37:40 host app: routine event\n"
    raw_path = tmp_path / "auth.log"
    raw_path.write_bytes(raw)
    monkeypatch.setattr(
        ait_auth,
        "_scenario",
        lambda _: ("https://zenodo.org/example.zip", 1, hashlib.sha256(raw).hexdigest(), None),
    )

    result = ait_auth.evaluate(raw_path, None, scenario="shaw")
    assert result["attack_lines"] == 0
    assert result["labels"] == {"member": None, "sha256": None}
    assert result["confusion"] == {"tp": None, "fp": None, "fn": None, "tn": None}
    assert result["labeled_event_counts"] == {}
    assert result["alert_event_counts"] == {}
    assert result["recall"] is None
    assert result["label_source"] == "no_matching_publisher_label_member"
    assert result["publisher_rule_coverage"] is None


def test_replay_rejects_label_on_unparsed_line(tmp_path, monkeypatch):
    raw = b"\nJan 24 04:37:40 host app: routine event\n"
    labels = b'{"line":1,"labels":["attack_step"]}\n'
    raw_path = tmp_path / "auth.log"
    labels_path = tmp_path / "auth.labels.jsonl"
    raw_path.write_bytes(raw)
    labels_path.write_bytes(labels)
    monkeypatch.setattr(ait_auth, "RAW_SHA256", hashlib.sha256(raw).hexdigest())
    monkeypatch.setattr(ait_auth, "LABEL_SHA256", hashlib.sha256(labels).hexdigest())

    with pytest.raises(ValueError, match="unparsed"):
        ait_auth.evaluate(raw_path, labels_path)


def test_labeled_runs_group_consecutive_lines_and_count_alert_hits():
    assert ait_auth.labeled_runs({2, 3, 5, 6}, {3, 9}) == [
        {"start_line": 2, "end_line": 3, "alert_line_numbers": [3]},
        {"start_line": 5, "end_line": 6, "alert_line_numbers": []},
    ]


def test_publisher_rule_coverage_deduplicates_rules_per_line():
    labels = "\n".join(
        [
            json.dumps(
                {
                    "line": 2,
                    "labels": ["escalate", "change_user"],
                    "rules": {
                        "escalate": [
                            "attacker.escalate.su.login",
                            "attacker.escalate.sudo.command",
                        ],
                        "change_user": ["attacker.escalate.su.login"],
                    },
                }
            ),
            json.dumps(
                {
                    "line": 3,
                    "labels": ["escalate"],
                    "rules": {"escalate": ["attacker.escalate.su.login"]},
                }
            ),
        ]
    )

    assert ait_auth.publisher_rule_coverage(labels, {2}) == {
        "attacker.escalate.su.login": {"labeled_lines": 2, "alerted_lines": 1},
        "attacker.escalate.sudo.command": {"labeled_lines": 1, "alerted_lines": 1},
    }


def test_publisher_rule_coverage_rejects_malformed_annotations():
    labels = '{"line":2,"labels":["escalate"],"rules":{"escalate":"not a list"}}'
    with pytest.raises(ValueError, match="rule annotation"):
        ait_auth.publisher_rule_coverage(labels, {2})


def test_frozen_ait_summary_can_be_checked_without_raw_dataset():
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, str(root / "scripts" / "check_ait_auth_evidence.py"), "--snapshot-only"],
        cwd=root,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "frozen evidence" in result.stdout


def test_separate_scenario_has_its_own_source_pins_and_identity(tmp_path, monkeypatch):
    raw = b"Jan 24 04:37:40 host su[1]: Successful su for alice by www-data\n"
    labels = b'{"line":1,"labels":["escalate"]}\n'
    raw_path = tmp_path / "auth.log"
    labels_path = tmp_path / "auth.labels.jsonl"
    raw_path.write_bytes(raw)
    labels_path.write_bytes(labels)
    monkeypatch.setattr(ait_auth, "WARDBECK_RAW_SHA256", hashlib.sha256(raw).hexdigest())
    monkeypatch.setattr(ait_auth, "WARDBECK_LABEL_SHA256", hashlib.sha256(labels).hexdigest())

    result = ait_auth.evaluate(raw_path, labels_path, scenario="wardbeck")
    assert result["source"]["scenario"] == "wardbeck"
    assert result["source"]["sha256"] == hashlib.sha256(raw).hexdigest()
    assert result["labels"]["sha256"] == hashlib.sha256(labels).hexdigest()
    assert result["confusion"]["tp"] == 1
    with pytest.raises(ValueError, match="unknown AIT scenario"):
        ait_auth.evaluate(raw_path, labels_path, scenario="made_up")
