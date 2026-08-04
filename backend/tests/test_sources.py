"""The real ingestion sources.

Each test below pins a property that would otherwise fail silently. A source
that parses nothing, attributes events to the wrong address, or stamps replayed
history with today's date does not raise — it produces a dashboard that looks
calm.
"""

import os
import socket
import time
from datetime import UTC, datetime

import pytest

from watchtower import runtime
from watchtower.pipeline.consumer import process_log
from watchtower.sources import file_tailer, replay, syslog_server
from watchtower.store import db, repos

# ─── replay ───────────────────────────────────────────────────────────────────

HDFS_LINE = (
    "081109 203615 148 INFO dfs.DataNode$PacketResponder: "
    "PacketResponder 1 for block blk_38865049064139660 terminating"
)
HDFS_WITH_IP = (
    "081109 204005 35 INFO dfs.FSNamesystem: BLOCK* NameSystem.addStoredBlock: "
    "blockMap updated: 10.251.73.220:50010 is added to blk_7128370237687728475 size 67108864"
)


def test_replay_keeps_the_logs_own_timestamp():
    """A 2008 line must stay in 2008. The whole ts_ms/ingested_ts_ms split rests on it."""
    raw = replay.parse_hdfs(HDFS_LINE)
    assert raw is not None
    assert datetime.fromisoformat(raw["timestamp"]).year == 2008
    assert raw["origin"] == "replay:hdfs"


def test_replay_extracts_a_real_address_from_the_line():
    raw = replay.parse_hdfs(HDFS_WITH_IP)
    assert raw["ip"] == "10.251.73.220"


def test_replay_does_not_mistake_a_block_id_for_an_address():
    """`blk_-1608999687919862906` is full of digits and dots live nearby."""
    raw = replay.parse_hdfs(HDFS_LINE)
    assert raw["ip"] == "10.0.0.0"  # the documented fallback, not a mangled block id


def test_replay_maps_level_to_level_not_to_a_threat():
    """WARN is a log level. Calling it 'suspicious_ip' would invent a judgement."""
    warn = HDFS_LINE.replace(" INFO ", " WARN ")
    assert replay.parse_hdfs(warn)["event"] == "log_warning"
    assert replay.parse_hdfs(HDFS_LINE)["event"] == "log_info"


def test_replay_rejects_a_line_it_cannot_parse():
    assert replay.parse_hdfs("this is not an HDFS line") is None


def test_openssh_replay_reads_authentication_outcomes_literally():
    line = "Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186"
    raw = replay.parse_openssh(line)
    assert raw["event"] == "failed_login"
    assert raw["ip"] == "173.234.31.186"
    assert raw["user"] == "webmaster"
    assert raw["source"] == "LabSZ"
    assert raw["origin"] == "replay:openssh"


def test_openssh_replay_recognises_success():
    line = "Dec 10 09:32:20 LabSZ sshd[24680]: Accepted password for fztu from 119.137.62.142 port 47154"
    assert replay.parse_openssh(line)["event"] == "login_success"


def test_replay_through_the_pipeline_separates_event_time_from_ingest_time():
    """The trap: window the detector on event time and a replay detects nothing."""
    raw = replay.parse_hdfs(HDFS_WITH_IP)
    process_log(raw)

    row = db.connect().execute("SELECT ts_ms, ingested_ts_ms, origin FROM events").fetchone()
    now_ms = int(datetime.now(UTC).timestamp() * 1000)
    assert row["ts_ms"] < now_ms - 10 * 365 * 24 * 3600 * 1000  # genuinely 2008
    assert abs(row["ingested_ts_ms"] - now_ms) < 60_000  # ingested just now
    assert row["origin"] == "replay:hdfs"


def test_replay_source_streams_the_committed_sample():
    """No download required: the 2k samples are in the repository."""
    src = replay.ReplaySource(dataset="hdfs", speed=500.0, limit=25)
    seen = []
    src.run(seen.append)
    assert len(seen) == 25
    assert all(e["origin"] == "replay:hdfs" for e in seen)
    assert src.skipped == 0, "every line of the sample should parse"


def test_replay_rejects_an_unknown_dataset_by_name():
    with pytest.raises(replay.UnknownDataset, match="hdfs"):
        replay.ReplaySource(dataset="nonesuch")


# ─── syslog ───────────────────────────────────────────────────────────────────


def test_syslog_pri_decodes_to_facility_and_severity():
    # 34 = auth.crit  (facility 4 * 8 + severity 2)
    assert syslog_server.decode_pri(34) == ("auth", 2)
    # 13 = user.notice
    assert syslog_server.decode_pri(13) == ("user", 5)


def test_rfc3164_is_parsed_with_its_tag_and_pid():
    payload = "<34>Oct 11 22:14:15 mymachine su[1234]: 'su root' failed for lonvick"
    raw = syslog_server.parse_syslog(payload, "192.0.2.10")
    assert raw["log_format"] == "rfc3164"
    assert raw["event"] == "log_critical"  # severity 2
    assert raw["source"] == "mymachine"
    assert "su[1234]" in raw["message"]


def test_rfc5424_is_parsed():
    payload = (
        "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 "
        '[exampleSDID@32473 iut="3"] BOMAn application event log entry...'
    )
    raw = syslog_server.parse_syslog(payload, "192.0.2.10")
    assert raw["log_format"] == "rfc5424"
    assert raw["event"] == "log_notice"  # 165 = local4.notice
    assert datetime.fromisoformat(raw["timestamp"]).year == 2003


def test_syslog_attributes_to_the_socket_peer_not_the_claimed_hostname():
    """HOSTNAME is whatever the sender wrote. The peer address is a fact."""
    payload = "<13>Oct 11 22:14:15 i-am-definitely-your-firewall app: hello"
    raw = syslog_server.parse_syslog(payload, "198.51.100.7")
    assert raw["ip"] == "198.51.100.7"
    assert raw["source"] == "i-am-definitely-your-firewall"  # kept, but not trusted as the address


def test_unparseable_datagram_is_ingested_rather_than_dropped():
    """A misconfigured sender must not produce silence that looks like health."""
    raw = syslog_server.parse_syslog("total gibberish, no PRI at all", "127.0.0.1")
    assert raw["log_format"] == "raw"
    assert raw["message"] == "total gibberish, no PRI at all"
    assert raw["origin"] == "syslog"


def test_syslog_server_receives_a_real_datagram():
    src = syslog_server.SyslogSource(port=0)  # let the OS choose a free port
    received = []
    src.start(received.append)
    assert src.wait_ready(3.0), "listener did not bind"
    port = src.bound_port()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"<13>Oct 11 22:14:15 testhost watchtower: end to end", ("127.0.0.1", port))
        sock.close()
        for _ in range(40):
            if received:
                break
            time.sleep(0.05)
    finally:
        src.stop()

    assert received, "no datagram reached the pipeline"
    assert received[0]["message"].startswith("watchtower:")
    assert received[0]["ip"] == "127.0.0.1"


# ─── file tailer ──────────────────────────────────────────────────────────────


def test_file_line_parses_the_bsd_syslog_shape():
    raw = file_tailer.parse_line(
        "Aug  4 21:09:20 mymac sshd[501]: Connection closed by 10.0.0.9\n", "/var/log/system.log"
    )
    assert raw["source"] == "mymac"
    assert raw["ip"] == "10.0.0.9"
    assert raw["origin"] == "file"
    assert "sshd[501]" in raw["message"]


def test_file_line_without_an_address_is_attributed_to_this_host():
    raw = file_tailer.parse_line("Aug  4 21:09:20 mymac kernel: something happened\n", "x")
    assert raw["ip"] == "127.0.0.1"


def test_file_line_classification_is_literal():
    err = file_tailer.parse_line("Aug  4 21:09:20 m app: connection refused\n", "x")
    assert err["event"] == "log_error"
    info = file_tailer.parse_line("Aug  4 21:09:20 m app: all good\n", "x")
    assert info["event"] == "log_info"


def _tail_until(src, seen, count, timeout=5.0):
    deadline = time.monotonic() + timeout
    while len(seen) < count and time.monotonic() < deadline:
        time.sleep(0.05)
    return len(seen) >= count


def test_tailer_follows_appends(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("Aug  4 21:09:20 host app: first\n")
    src = file_tailer.FileTailSource(str(log), poll_interval=0.05)
    seen = []
    src.start(seen.append)
    time.sleep(0.2)  # let it seek to the end
    try:
        with open(log, "a") as fh:
            fh.write("Aug  4 21:09:21 host app: second\n")
            fh.flush()
        assert _tail_until(src, seen, 1), "append was never picked up"
        assert "second" in seen[0]["message"]
        # It started at EOF, so the pre-existing line must NOT be replayed.
        assert all("first" not in e["message"] for e in seen)
    finally:
        src.stop()


def test_tailer_survives_rotation_by_inode(tmp_path):
    """logrotate renames and recreates. A path-watching tailer goes deaf here."""
    log = tmp_path / "app.log"
    log.write_text("Aug  4 21:09:20 host app: before\n")
    src = file_tailer.FileTailSource(str(log), poll_interval=0.05)
    seen = []
    src.start(seen.append)
    time.sleep(0.2)
    try:
        os.rename(log, tmp_path / "app.log.1")
        log.write_text("Aug  4 21:09:22 host app: after rotation\n")
        assert _tail_until(src, seen, 1), "nothing was read after rotation"
        assert any("after rotation" in e["message"] for e in seen)
        assert src.rotations >= 1
    finally:
        src.stop()


def test_tailer_survives_truncation_in_place(tmp_path):
    """`cp /dev/null file` keeps the inode; only a shrinking size gives it away."""
    log = tmp_path / "app.log"
    log.write_text("Aug  4 21:09:20 host app: " + "x" * 500 + "\n")
    src = file_tailer.FileTailSource(str(log), poll_interval=0.05)
    seen = []
    src.start(seen.append)
    time.sleep(0.2)
    try:
        with open(log, "w") as fh:
            fh.write("Aug  4 21:09:25 host app: after truncate\n")
        assert _tail_until(src, seen, 1), "nothing was read after truncation"
        assert any("after truncate" in e["message"] for e in seen)
    finally:
        src.stop()


def test_tailer_refuses_a_missing_file_loudly(tmp_path):
    src = file_tailer.FileTailSource(str(tmp_path / "nope.log"))
    with pytest.raises(FileNotFoundError):
        src.run(lambda raw: None)


# ─── source specs ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "spec,cls",
    [
        ("synthetic", "SyntheticSource"),
        ("syslog", "SyslogSource"),
        ("syslog:5999", "SyslogSource"),
        ("file:/tmp/x.log", "FileTailSource"),
        ("replay:hdfs", "ReplaySource"),
        ("replay:openssh@5", "ReplaySource"),
    ],
)
def test_specs_build_the_right_source(spec, cls):
    assert type(runtime.build(spec)).__name__ == cls


def test_replay_spec_carries_the_rate():
    assert runtime.build("replay:hdfs@7.5").speed == 7.5


def test_unknown_spec_raises_rather_than_being_ignored():
    """A requested source that silently does not start looks like a quiet network."""
    with pytest.raises(runtime.UnknownSource, match="unknown source"):
        runtime.build("carrier-pigeon")


def test_malformed_spec_says_what_was_wrong():
    with pytest.raises(runtime.UnknownSource, match="port must be a number"):
        runtime.build("syslog:not-a-port")
    with pytest.raises(runtime.UnknownSource, match="needs a path"):
        runtime.build("file:")


def test_every_source_lands_in_the_same_store_with_its_own_origin():
    """One pipeline, many origins — that is the whole reason replay is credible."""
    process_log(replay.parse_hdfs(HDFS_WITH_IP))
    process_log(syslog_server.parse_syslog("<13>Oct 11 22:14:15 h app: x", "192.0.2.1"))
    process_log(file_tailer.parse_line("Aug  4 21:09:20 h app: y\n", "/tmp/x"))

    origins = dict(
        db.connect().execute("SELECT origin, count(*) FROM events GROUP BY origin").fetchall()
    )
    assert origins == {"replay:hdfs": 1, "syslog": 1, "file": 1}
    # And every one of them got a ledger block.
    assert repos.counters()["blocks"] == 3
