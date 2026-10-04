"""Source fidelity and line-label checks for the AIT auth-log replay."""

import hashlib
import io
import json
import zipfile

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
    assert result["precision"] == result["recall"] == 1.0
    assert result["alert_line_numbers"] == [9]
    assert config.get() is before_config
    assert db.path() == before_path


def test_replay_rejects_unpinned_source(tmp_path):
    raw = tmp_path / "auth.log"
    labels = tmp_path / "auth.labels.jsonl"
    raw.write_text("not the publisher's file\n")
    labels.write_text('{"line":1,"labels":["attack"]}\n')
    with pytest.raises(ValueError, match="SHA-256"):
        ait_auth.evaluate(raw, labels)
