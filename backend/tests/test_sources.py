"""The real ingestion sources.

Each test below pins a property that would otherwise fail silently. A source
that parses nothing, attributes events to the wrong address, or stamps replayed
history with today's date does not raise — it produces a dashboard that looks
calm.
"""

import os
import socket
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from watchtower import config, ledger, runtime
from watchtower.app import create_app
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
    assert raw["event"] == "auth_invalid_user"
    assert raw["ip"] == "173.234.31.186"
    assert raw["user"] == "webmaster"
    assert raw["source"] == "LabSZ"
    assert raw["origin"] == "replay:openssh"


def test_openssh_replay_recognises_success():
    line = "Dec 10 09:32:20 LabSZ sshd[24680]: Accepted password for fztu from 119.137.62.142 port 47154"
    assert replay.parse_openssh(line)["event"] == "login_success"


def test_openssh_replay_does_not_classify_a_broken_actor_address():
    line = "Dec 10 06:55:46 LabSZ sshd[24200]: Failed password for root from 203.0.113.8.9 port 22 ssh2"
    raw = replay.parse_openssh(line)
    assert raw["event"] == "log_info"
    assert raw["ip"] == "127.0.0.1"


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


def test_remote_udp_peer_cannot_be_trusted_for_ssh_actor_enforcement():
    with pytest.raises(ValueError, match="loopback"):
        config.replace(trusted_syslog_peers=("198.51.100.7",))


def test_trusted_local_sshd_message_attributes_actor_separately():
    payload = "<34>Oct 11 22:14:15 ssh-box sshd[99]: Failed password for root from 203.0.113.8 port 22 ssh2"
    raw = syslog_server.parse_syslog(payload, "127.0.0.1", trusted_peers=("127.0.0.1",))
    assert (raw["event"], raw["ip"], raw["transport_peer_ip"]) == (
        "failed_login",
        "203.0.113.8",
        "127.0.0.1",
    )


def test_trusted_local_rfc5424_ssh_ipv6_actor():
    payload = "<34>1 2026-10-04T10:00:00Z ssh-box sshd 99 - - Accepted publickey for root from 2001:db8::8 port 22 ssh2"
    raw = syslog_server.parse_syslog(payload, "::1", trusted_peers=("::1",))
    assert (raw["event"], raw["ip"], raw["transport_peer_ip"]) == (
        "login_success",
        "2001:db8::8",
        "::1",
    )


def test_untrusted_sshd_message_cannot_redirect_attribution():
    payload = "<34>Oct 11 22:14:15 ssh-box sshd[99]: Failed password for root from 203.0.113.8 port 22 ssh2"
    raw = syslog_server.parse_syslog(payload, "127.0.0.1")
    assert (raw["event"], raw["ip"], raw["transport_peer_ip"]) == (
        "log_critical",
        "127.0.0.1",
        "127.0.0.1",
    )


def test_parser_never_trusts_a_remote_udp_peer_even_if_caller_lists_it():
    payload = "<34>Oct 11 22:14:15 ssh-box sshd[99]: Failed password for root from 203.0.113.8 port 22 ssh2"
    raw = syslog_server.parse_syslog(payload, "198.51.100.7", trusted_peers=("198.51.100.7",))
    assert (raw["event"], raw["ip"]) == ("log_critical", "198.51.100.7")


def test_trusted_sshd_event_persists_actor_and_peer_in_api_and_ledger():
    payload = "<34>Oct 11 22:14:15 ssh-box sshd[99]: Failed password for root from 203.0.113.8 port 22 ssh2"
    process_log(syslog_server.parse_syslog(payload, "127.0.0.1", trusted_peers=("127.0.0.1",)))
    with create_app(start_sources=False).test_client() as client:
        event = client.get("/api/v1/logs?limit=1").get_json()[0]
    assert (event["ip"], event["transport_peer_ip"]) == ("203.0.113.8", "127.0.0.1")
    conn = db.connect()
    assert ledger.verify(conn).ok
    with db.write() as write_conn:
        write_conn.execute("UPDATE events SET transport_peer_ip='::1' WHERE id=?", (event["id"],))
    assert not ledger.verify(conn).ok


def test_v3_database_migrates_without_rewriting_legacy_ledger(isolated_config):
    path = isolated_config.db_path
    path.parent.mkdir(parents=True, exist_ok=True)
    old = {
        "id": 1,
        "ts_ms": 1,
        "source": "old",
        "event": "log_info",
        "event_type": "application",
        "severity": "low",
        "ip": "192.0.2.10",
        "user": "unknown",
        "message": "legacy",
        "log_format": "rfc3164",
        "origin": "syslog",
        "dropped": 0,
    }
    digest = ledger.payload_hash(old, ledger.chain.CANON_V2)
    header = ledger.block_hash(1, 1, ledger.GENESIS_PREV, digest)
    with sqlite3.connect(path) as legacy:
        legacy.executescript((Path(__file__).parent / "fixtures" / "schema_v3.sql").read_text())
        legacy.execute("INSERT INTO schema_meta VALUES ('schema_version', '3')")
        legacy.execute(
            """INSERT INTO events (id, ts_ms, ingested_ts_ms, source, event, event_type,
               severity, ip, user, message, log_format, origin, rep_verdict,
               rep_score, rep_sources, rep_checked, rep_detail, dropped)
               VALUES (1,1,1,'old','log_info','application','low','192.0.2.10',
               'unknown','legacy','rfc3164','syslog','unavailable',0,'[]',0,'',0)"""
        )
        legacy.execute(
            """INSERT INTO ledger (block_id, ts_ms, event_id, payload_json,
               payload_canon, log_hash, prev_hash, hash)
               VALUES (1,1,1,?,?,?,?,?)""",
            (
                ledger.canonical(old, ledger.chain.CANON_V2),
                ledger.chain.CANON_V2,
                digest,
                ledger.GENESIS_PREV,
                header,
            ),
        )
    db.configure(path)
    conn = db.connect()
    assert (
        conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0]
        == "5"
    )
    assert repos.recent_events()[0]["transport_peer_ip"] is None
    assert ledger.verify(conn).ok


@pytest.mark.parametrize(
    "body",
    [
        "Failed password for root from 999.1.2.3 port 22 ssh2",
        "Failed password for root from 203.0.113.8 port 0 ssh2",
        "Failed password for root from 203.0.113.8 port 22 ssh2 injected",
        "pam_unix(sshd:auth): authentication failure; rhost=203.0.113.8",
    ],
)
def test_trusted_local_malformed_auth_message_stays_generic(body):
    raw = syslog_server.parse_syslog(
        f"<34>Oct 11 22:14:15 ssh-box sshd[99]: {body}",
        "127.0.0.1",
        trusted_peers=("127.0.0.1",),
    )
    assert (raw["event"], raw["ip"]) == ("log_critical", "127.0.0.1")


def test_trusted_local_failed_logins_raise_actor_alert_without_blocking_collector():
    payload = "<34>Oct 11 22:14:15 ssh-box sshd[99]: Failed password for root from 203.0.113.8 port 22 ssh2"
    for _ in range(9):
        process_log(syslog_server.parse_syslog(payload, "127.0.0.1", trusted_peers=("127.0.0.1",)))
    conn = db.connect()
    assert repos.failed_logins_in_window(conn, "203.0.113.8", 0) >= 5
    assert any(alert["ip"] == "203.0.113.8" for alert in repos.recent_alerts())
    assert repos.blocked_entry(conn, "127.0.0.1") is None


def test_invalid_user_and_failed_password_count_as_one_failed_attempt():
    prefix = "<34>Oct 11 22:14:15 ssh-box sshd[99]: "
    for body in (
        "Invalid user root from 203.0.113.8",
        "Failed password for invalid user root from 203.0.113.8 port 22 ssh2",
    ):
        process_log(
            syslog_server.parse_syslog(prefix + body, "127.0.0.1", trusted_peers=("127.0.0.1",))
        )
    conn = db.connect()
    assert repos.failed_logins_in_window(conn, "203.0.113.8", 0) == 1


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


def test_tailer_waits_for_the_newline_before_emitting(tmp_path):
    """readline() returns a partial line at EOF, newline or not.

    Catching a writer mid-line split one log line into two events: the first
    with whatever address was in the first half and a severity classified from
    half a message, the second unparseable and attributed to loopback. Both were
    chained into the ledger as facts.
    """
    log = tmp_path / "app.log"
    log.write_text("")
    src = file_tailer.FileTailSource(str(log), poll_interval=0.05)
    seen = []
    src.start(seen.append)
    time.sleep(0.2)
    try:
        with open(log, "a") as fh:
            fh.write("Aug  4 21:09:20 host app: connection from 10.0.0.9 ")
            fh.flush()
        time.sleep(0.4)
        assert seen == [], "a partial line was emitted as a finished event"

        with open(log, "a") as fh:
            fh.write("closed cleanly\n")
            fh.flush()
        assert _tail_until(src, seen, 1), "the completed line never arrived"
        assert len(seen) == 1, "one log line must produce exactly one event"
        assert "connection from 10.0.0.9 closed cleanly" in seen[0]["message"]
        assert seen[0]["ip"] == "10.0.0.9"
    finally:
        src.stop()


def test_a_stale_partial_line_is_dropped_not_spliced(tmp_path):
    """The fix for partial lines made a worse bug possible, and this pins it shut.

    `copytruncate` truncates in place while an unterminated line is held. If the
    writer refills past the old offset before the next poll, the size check
    cannot see it, and appending would glue the head of the old file's last line
    onto the tail of the new file's first line — producing one well-formed,
    attributed, severity-classified record whose text never existed in any file.
    Strictly worse than the two broken fragments it replaced.

    A held fragment therefore expires. Losing it is a counted loss; fabricating
    a convincing record is not.
    """
    log = tmp_path / "app.log"
    log.write_text("")
    src = file_tailer.FileTailSource(str(log), poll_interval=0.05, pending_timeout=0.3)
    seen = []
    src.start(seen.append)
    time.sleep(0.2)
    try:
        with open(log, "a") as fh:
            fh.write("Aug  4 21:09:20 web01 sshd[1]: partial from OLD file")
            fh.flush()
        time.sleep(0.8)  # past pending_timeout
        assert seen == [], "the fragment was emitted as a finished event"
        assert src.discarded_partials == 1, "the fragment was not dropped"

        # What arrives next must stand alone, not be glued onto the fragment.
        with open(log, "a") as fh:
            fh.write("ation failure for root\n")
            fh.flush()
        assert _tail_until(src, seen, 1)
        assert "partial from OLD file" not in seen[0]["message"], "two files were spliced"
    finally:
        src.stop()


def test_a_writer_that_never_emits_a_newline_cannot_exhaust_memory(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("")
    src = file_tailer.FileTailSource(
        str(log), poll_interval=0.05, pending_timeout=30, max_pending_bytes=2048
    )
    seen = []
    src.start(seen.append)
    time.sleep(0.2)
    try:
        with open(log, "a") as fh:
            fh.write("x" * 5000)
            fh.flush()
        deadline = time.monotonic() + 3
        while src.discarded_partials == 0 and time.monotonic() < deadline:
            time.sleep(0.05)
        assert src.discarded_partials >= 1, "the buffer grew past its cap unchecked"
        assert seen == []
    finally:
        src.stop()
