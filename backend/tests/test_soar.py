"""SOAR enforcement: the closed loop, and the status that has to be earned.

The version this replaces set ``alert["status"] = "mitigated"`` on the line
after selecting a playbook, and "selecting" only built a dict. Every alert in
the system claimed to have been remediated the instant it was raised.

``test_blocked_address_produces_no_further_alerts`` is the proof the loop is
real. If it ever passes vacuously — because detection stopped running, or
because nothing was ever blocked — the assertions on drop counts and hit counts
alongside it will fail.
"""

import http.server
import json
import threading
import time
from datetime import UTC, datetime

import pytest
import yaml

from watchtower.app import API_PREFIX, create_app
from watchtower.pipeline.consumer import process_log
from watchtower.soar import actions, engine, playbooks
from watchtower.store import db, repos

ATTACKER = "203.0.113.77"


def _raw(ip=ATTACKER, event="brute_force", user="root", message=None):
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "firewall-01",
        "event": event,
        "ip": ip,
        "user": user,
        "message": message or f"{event} from {ip}",
        "log_format": "cef",
        "origin": "synthetic",
    }


@pytest.fixture(autouse=True)
def fresh_playbooks():
    playbooks.all_playbooks(reload=True)
    yield
    playbooks.all_playbooks(reload=True)


# ─── the closed loop ─────────────────────────────────────────────────────────
def test_blocked_address_produces_no_further_alerts():
    """detect → respond → enforce → observe, with nothing simulated in between."""
    # One brute_force event is enough: the event weight alone clears 0.45.
    process_log(_raw())
    conn = db.connect()

    entry = repos.blocked_entry(conn, ATTACKER)
    assert entry is not None, "the playbook's block_ip step did not run"
    alerts_after_first = repos.counters()["alerts"]
    assert alerts_after_first == 1

    for _ in range(10):
        process_log(_raw())

    # 1. No new alerts. The address is genuinely silenced.
    assert repos.counters()["alerts"] == alerts_after_first

    # 2. Ten events really were dropped, and the block that caused it says so.
    dropped = conn.execute("SELECT count(*) FROM events WHERE dropped = 1").fetchone()[0]
    assert dropped == 10
    assert repos.blocked_entry(conn, ATTACKER)["hits"] == 10
    assert repos.blocklist_totals()["events_dropped_lifetime"] == 10

    # 3. And they are still in the store, and still in the ledger. An audit
    #    ledger that omits what a response action silenced has a hole exactly
    #    where the interesting traffic is.
    assert conn.execute("SELECT count(*) FROM events").fetchone()[0] == 11
    assert repos.counters()["blocks"] == 11


def test_dropping_does_not_silence_other_addresses():
    """A block is per-address. Over-enforcement is the failure nobody notices."""
    process_log(_raw())
    other = "203.0.113.99"
    process_log(_raw(ip=other))

    conn = db.connect()
    assert repos.blocked_entry(conn, other) is not None  # it earned its own block
    assert repos.counters()["alerts"] == 2


def test_dropped_events_do_not_feed_the_detection_windows():
    """Counting suppressed events would make the windows disagree with the alerts."""
    process_log(_raw(event="failed_login"))  # below threshold, no block
    conn = db.connect()
    with db.write() as w:
        repos.block_ip(w, ip=ATTACKER, reason="test", alert_id=None, ttl_seconds=60)
    for _ in range(6):
        process_log(_raw(event="failed_login"))

    assert repos.failed_logins_in_window(conn, ATTACKER, 0) == 1


def test_the_ledger_covers_the_dropped_flag():
    """Flipping `dropped` with raw SQL must be detected, not shrugged at.

    `dropped` is the record of which traffic a response action suppressed. In a
    system whose claim is that enforcement is real, that is exactly the field
    worth protecting.
    """
    from watchtower import ledger

    process_log(_raw())
    process_log(_raw())
    assert ledger.verify(db.connect()).ok

    with db.write() as w:
        w.execute("UPDATE events SET dropped = 0 WHERE dropped = 1")
    result = ledger.verify(db.connect())
    assert not result.ok
    assert result.findings[0].reason == "payload_mismatch"


def test_expired_blocks_stop_applying_immediately():
    """Enforcement ends at the TTL, not when a sweep next happens to run."""
    conn = db.connect()
    with db.write() as w:
        repos.block_ip(w, ip=ATTACKER, reason="test", alert_id=None, ttl_seconds=1)
        # Reach in and expire it, rather than sleeping.
        w.execute("UPDATE blocklist SET expires_ts_ms = ? WHERE ip = ?", (1, ATTACKER))
    assert repos.blocked_entry(conn, ATTACKER) is None

    process_log(_raw(event="port_scan"))
    assert conn.execute("SELECT count(*) FROM events WHERE dropped = 1").fetchone()[0] == 0


def test_reblocking_extends_and_never_shortens():
    conn = db.connect()
    with db.write() as w:
        repos.block_ip(w, ip=ATTACKER, reason="first", alert_id=None, ttl_seconds=3600)
        long_expiry = repos.blocked_entry(w, ATTACKER)["expires_ts_ms"]
        repos.record_block_hit(w, ATTACKER)
        repos.block_ip(w, ip=ATTACKER, reason="second", alert_id=None, ttl_seconds=10)

    row = repos.blocked_entry(conn, ATTACKER)
    assert row["expires_ts_ms"] == long_expiry, "a shorter re-block shortened a running one"
    # One row, and the hit count survived. Two rows would halve every
    # "N events dropped from X" figure the dashboard shows.
    assert conn.execute("SELECT count(*) FROM blocklist").fetchone()[0] == 1
    assert row["hits"] == 1


def test_unblock_restores_traffic():
    process_log(_raw())
    with db.write() as w:
        assert repos.unblock(w, ATTACKER) is True
    db.close_all()
    db.configure(None)
    process_log(_raw())
    assert repos.counters()["alerts"] == 2


# ─── status lifecycle ────────────────────────────────────────────────────────
def test_status_is_contained_when_enforcement_actually_ran():
    process_log(_raw())
    row = db.connect().execute("SELECT status FROM alerts").fetchone()
    assert row["status"] == "contained"


def test_status_is_never_mitigated_by_notification_alone():
    """A playbook that only told someone has not fixed anything."""
    process_log(_raw(event="privilege_escalation"))
    row = db.connect().execute("SELECT status FROM alerts").fetchone()
    assert row["status"] != "mitigated"


def test_a_failing_required_step_makes_the_alert_action_failed(monkeypatch):
    def broken(ctx):
        return actions.Outcome(actions.FAILED, "blocklist write refused")

    monkeypatch.setitem(actions.ACTIONS, "block_ip", broken)
    process_log(_raw())
    row = db.connect().execute("SELECT status FROM alerts").fetchone()
    assert row["status"] == "action_failed"


def test_an_optional_step_failing_does_not_sink_the_response(monkeypatch):
    def broken(ctx):
        return actions.Outcome(actions.FAILED, "webhook refused")

    monkeypatch.setitem(actions.ACTIONS, "webhook", broken)
    process_log(_raw())
    row = db.connect().execute("SELECT status FROM alerts").fetchone()
    assert row["status"] == "contained"


def test_an_action_that_raises_is_recorded_not_propagated(monkeypatch):
    def explodes(ctx):
        raise RuntimeError("boom")

    monkeypatch.setitem(actions.ACTIONS, "notify", explodes)
    process_log(_raw())  # must not raise
    soar = repos.recent_soar(1)[0]
    notify_step = [s for s in soar["execution_steps"] if s["action"] == "notify"][0]
    assert notify_step["status"] == "failed"
    assert "RuntimeError" in notify_step["detail"]


# ─── individual actions ──────────────────────────────────────────────────────
def test_webhook_without_configuration_is_skipped_not_failed(monkeypatch):
    """'Nothing is configured' and 'it was tried and broke' are different facts."""
    monkeypatch.delenv("WATCHTOWER_WEBHOOK_URL", raising=False)
    ctx = actions.Context(conn=db.connect(), alert={"id": 1, "ip": "1.2.3.4"}, step_params={})
    out = actions.webhook(ctx)
    assert out.status == actions.SKIPPED
    assert "no webhook configured" in out.detail


def test_webhook_to_a_closed_port_fails_truthfully():
    """A notifier that silently drops alerts is worse than no notifier."""
    ctx = actions.Context(
        conn=db.connect(),
        alert={"id": 1, "ip": "1.2.3.4", "event": "brute_force"},
        # Port 1 on loopback, reserved and never listening.
        step_params={"url": "http://127.0.0.1:1/hook"},
    )
    out = actions.run("webhook", ctx)
    assert out.status == actions.FAILED
    assert "127.0.0.1:1" not in out.detail


def test_webhook_posts_for_real():
    received = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            received.append(json.loads(self.rfile.read(n)))
            self.send_response(202)
            self.end_headers()

        def log_message(self, *a):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.handle_request, daemon=True).start()
    try:
        ctx = actions.Context(
            conn=db.connect(),
            alert={"id": 7, "ip": ATTACKER, "event": "brute_force", "severity": "critical"},
            step_params={"url": f"http://127.0.0.1:{server.server_address[1]}/secret-path"},
        )
        out = actions.run("webhook", ctx)
    finally:
        server.server_close()

    assert out.status == actions.EXECUTED
    assert "HTTP 202" in out.detail
    assert "secret-path" not in out.detail
    assert received and received[0]["alert_id"] == 7
    assert received[0]["ip"] == ATTACKER


def test_incident_report_writes_real_files_with_ledger_coverage(isolated_config):
    process_log(_raw())
    directory = isolated_config.incidents_dir
    reports = sorted(directory.glob("INC-*.md"))
    assert len(reports) == 1, "brute_force requires an incident_report step"

    record = json.loads(reports[0].with_suffix(".json").read_text())
    assert record["ip"] == ATTACKER
    assert record["evidence_event_ids"], "a report with no evidence is a press release"
    assert record["covering_ledger_blocks"], "the evidence must point at verifiable blocks"

    body = reports[0].read_text()
    assert "python -m watchtower ledger verify" in body
    # And it says plainly what it did not do.
    assert "not a remediation" in body


def test_incident_report_ids_increment_within_a_day():
    process_log(_raw())
    process_log(_raw(ip="203.0.113.88"))
    from watchtower import config

    reports = sorted(p.name for p in config.get().incidents_dir.glob("INC-*.md"))
    assert len(reports) == 2
    assert reports[0].endswith("-001.md") and reports[1].endswith("-002.md")


# ─── playbooks as data ───────────────────────────────────────────────────────
def test_shipped_playbooks_all_load_and_validate():
    books = playbooks.load_all()
    assert "brute_force" in books
    assert playbooks.WILDCARD in books, "a default playbook must exist"
    for pb in books.values():
        assert pb.steps
        assert pb.priority in playbooks.VALID_PRIORITIES


def test_an_unknown_action_is_rejected_at_load_time(tmp_path):
    """A typo'd action is a step that never runs, and nothing would report it."""
    (tmp_path / "bad.yaml").write_text(
        yaml.safe_dump(
            {"name": "x", "trigger": "y", "actions": [{"action": "blokc_ip", "required": True}]}
        )
    )
    with pytest.raises(playbooks.PlaybookError, match="unknown action"):
        playbooks.load_all(tmp_path)


def test_two_playbooks_cannot_claim_one_trigger(tmp_path):
    for name in ("a.yaml", "b.yaml"):
        (tmp_path / name).write_text(
            yaml.safe_dump(
                {"name": name, "trigger": "brute_force", "actions": [{"action": "notify"}]}
            )
        )
    with pytest.raises(playbooks.PlaybookError, match="already defined"):
        playbooks.load_all(tmp_path)


def test_a_malformed_playbook_names_its_file(tmp_path):
    (tmp_path / "broken.yaml").write_text("name: x\ntrigger: y\n")  # no actions
    with pytest.raises(playbooks.PlaybookError, match="broken.yaml"):
        playbooks.load_all(tmp_path)


def test_events_without_a_playbook_fall_back_to_notify_only():
    """Inventing containment for an unplanned event is how a SOAR runs amok."""
    pb = playbooks.for_event("something_nobody_wrote_policy_for")
    assert pb.is_default
    assert [s.action for s in pb.steps] == ["notify"]


def test_malware_playbook_does_not_block_as_a_substitute_for_isolation():
    """It cannot isolate a host, so it records the incident and says so."""
    pb = playbooks.for_event("malware_detected")
    assert "block_ip" not in [s.action for s in pb.steps]


# ─── the API ─────────────────────────────────────────────────────────────────
@pytest.fixture()
def client():
    app = create_app(start_sources=False)
    app.config.update(TESTING=True)
    with app.test_client() as c:
        yield c


def test_blocklist_endpoint_reports_real_drops(client):
    """Driven by a fixed event, not by the random attack generator.

    This used to POST /simulate-attack and assert a block existed. A brute_force
    burst draws each of its 10-18 events at random from a pool that is two
    thirds `failed_login`, and `failed_login` has no playbook — it falls to the
    default, which only notifies. Measured over 20,000 bursts, **0.54% contain
    no brute_force event at all**, and in those the test failed. I saw it fail
    exactly once and the three "no playbook is defined for this event type"
    lines in that run were what gave it away.

    A test that fails one run in two hundred teaches people to re-run it.
    """
    process_log(_raw())
    body = client.get(f"{API_PREFIX}/blocklist").get_json()
    assert body["entries"], "the alert should have blocked its address"
    assert body["totals"]["active_blocks"] >= 1
    # And it states the scope of enforcement rather than implying a firewall.
    assert "no" in body["enforcement"].lower() and "firewall" in body["enforcement"]


def test_unblock_over_http(client):
    process_log(_raw())
    assert client.delete(f"{API_PREFIX}/blocklist/{ATTACKER}").status_code == 200
    assert client.delete(f"{API_PREFIX}/blocklist/{ATTACKER}").status_code == 404


def test_playbooks_are_inspectable_over_http(client):
    body = client.get(f"{API_PREFIX}/playbooks").get_json()
    triggers = {pb["trigger"] for pb in body["playbooks"]}
    assert "brute_force" in triggers
    assert set(body["actions"]) == set(actions.ACTIONS)
    # `required` is the field that decides an alert's status; it must be visible.
    brute = [pb for pb in body["playbooks"] if pb["trigger"] == "brute_force"][0]
    assert any(s["required"] for s in brute["steps"])


def test_stats_surfaces_enforcement_numbers(client):
    process_log(_raw())
    for _ in range(3):
        process_log(_raw())
    body = client.get(f"{API_PREFIX}/stats").get_json()
    assert body["events_dropped_lifetime"] == 3
    assert body["active_blocks"] == 1


def test_soar_records_say_which_steps_really_ran(client):
    process_log(_raw())
    record = client.get(f"{API_PREFIX}/soar-actions").get_json()[0]
    assert record["execution_mode"] == "live"
    by_action = {s["action"]: s for s in record["execution_steps"]}
    assert by_action["block_ip"]["executed"] is True
    assert by_action["block_ip"]["status"] == "executed"
    # Nothing is configured for the webhook, and it says exactly that.
    assert by_action["webhook"]["status"] == "skipped"
    assert by_action["webhook"]["executed"] is False


def test_engine_describes_its_own_policy():
    described = engine.describe()
    assert described
    brute = [pb for pb in described if pb["trigger"] == "brute_force"][0]
    assert brute["source"] == "brute_force.yaml"


def test_soar_steps_record_whether_a_failure_was_allowed(client):
    """`required` decides the alert's status, so the API has to report it."""
    process_log(_raw())
    record = client.get(f"{API_PREFIX}/soar-actions").get_json()[0]
    by_action = {s["action"]: s for s in record["execution_steps"]}
    assert by_action["block_ip"]["required"] is True
    assert by_action["webhook"]["required"] is False


def test_legacy_webhook_details_are_redacted_from_all_read_endpoints(client):
    """Old databases may already contain credential-bearing webhook URLs."""
    process_log(_raw())
    secret = "credential-in-webhook-path"
    with db.write() as conn:
        conn.execute(
            "UPDATE soar_steps SET detail = ? WHERE action = 'webhook'",
            (f"POST https://example.test/{secret} → HTTP 202",),
        )

    for endpoint in ("/soar-actions", "/alerts"):
        body = client.get(f"{API_PREFIX}{endpoint}").get_json()
        assert secret not in str(body)
        assert "example.test" not in str(body)


def test_a_v1_ledger_still_verifies_under_the_v2_canon():
    """Adding one field must not retroactively accuse every old block.

    A false tamper alarm is indistinguishable, in the output, from a real one —
    which would make the whole check worthless. This is what `payload_canon`
    is stored per block for.
    """
    from watchtower import ledger

    process_log(_raw(event="failed_login"))  # below threshold: no block, no alert
    conn = db.connect()

    # Rewrite the one block as though it had been written by the v1 build:
    # v1 field tuple, v1 canon name, and no `dropped` in the digest.
    row = conn.execute("SELECT block_id, ts_ms, prev_hash FROM ledger").fetchone()
    event = dict(conn.execute("SELECT * FROM events").fetchone())
    v1_payload = ledger.canonical({**event, "id": event["id"]}, ledger.chain.CANON_V1)
    import hashlib

    v1_digest = hashlib.sha256(v1_payload.encode()).hexdigest()
    v1_header = ledger.block_hash(row["block_id"], row["ts_ms"], row["prev_hash"], v1_digest)
    with db.write() as w:
        w.execute(
            "UPDATE ledger SET payload_canon = ?, payload_json = ?, log_hash = ?, hash = ? "
            "WHERE block_id = ?",
            (ledger.chain.CANON_V1, v1_payload, v1_digest, v1_header, row["block_id"]),
        )

    result = ledger.verify(conn)
    assert result.ok, f"a v1 block failed under the v2 build: {result.findings}"


def test_a_canon_this_build_cannot_reproduce_is_reported_not_guessed():
    from watchtower import ledger

    process_log(_raw(event="failed_login"))
    with db.write() as w:
        w.execute("UPDATE ledger SET payload_canon = 'some-future-canon-v9'")

    result = ledger.verify(db.connect())
    assert not result.ok
    assert result.findings[0].reason == "unknown_canon"
    # It says it cannot check, rather than claiming tampering it did not observe.
    assert "neither confirmed nor refuted" in result.findings[0].detail


# ─── the response must never cost us the event ───────────────────────────────
def test_a_broken_playbook_does_not_erase_the_event(monkeypatch):
    """The critical one.

    Playbook selection used to run inside the ingest transaction. A typo in a
    YAML file raised, the exception unwound `Transaction.__exit__`, and the
    ROLLBACK took the event row, its ledger block and the counter bump with it.
    Every *benign* event was stored normally and every *alerting* event was
    erased — and because SQLite reuses the rowids of a rolled-back transaction,
    `verify` saw no height gap and reported the chain clean over a record set
    missing exactly the anomalous traffic.
    """
    from watchtower import ledger

    def explode(event):
        raise playbooks.PlaybookError("brute_force.yaml: unknown action 'block_ipp'")

    monkeypatch.setattr(playbooks, "for_event", explode)

    process_log(_raw(event="login_success"))  # benign
    process_log(_raw())  # alerting — its playbook is broken

    conn = db.connect()
    kinds = [r["event"] for r in conn.execute("SELECT event FROM events ORDER BY id")]
    assert kinds == ["login_success", "brute_force"], "the alerting event was erased"
    assert repos.counters()["events"] == 2
    assert repos.counters()["blocks"] == 2
    # The alert itself survives, with no response and an honest status.
    row = conn.execute("SELECT status FROM alerts").fetchone()
    assert row["status"] == "open"
    assert conn.execute("SELECT count(*) FROM soar_executions").fetchone()[0] == 0
    assert ledger.verify(conn).ok


def test_the_write_lock_is_not_held_across_the_response():
    """A 3s webhook used to hold BEGIN IMMEDIATE, so concurrent events were lost.

    Asserted structurally rather than by racing threads: the response runs after
    the ingest transaction has committed, so no write transaction is open while
    an action is executing.
    """
    seen = []

    def watching(ctx):
        seen.append(db.connect().in_transaction)
        return actions.Outcome(actions.EXECUTED, "noted")

    import pytest as _pytest

    mp = _pytest.MonkeyPatch()
    mp.setitem(actions.ACTIONS, "block_ip", watching)
    try:
        process_log(_raw())
    finally:
        mp.undo()

    assert seen, "the action never ran"
    assert not any(seen), "an action ran while the ingest write transaction was open"


def test_housekeeping_runs_for_every_source_not_just_synthetic():
    """It was wired only into SyntheticSource(on_tick=...).

    So `--sources syslog`, `--sources file:...` and `--sources replay:...` — all
    three documented real configurations — never pruned, never truncated the
    WAL and never reclaimed an expired blocklist row, while /api/v1/stats went
    on publishing the retention policy as fact.
    """
    from watchtower.pipeline import consumer

    calls = []
    real = consumer.housekeeping
    try:
        consumer.housekeeping = lambda: calls.append(1)
        # A replayed HDFS line: no synthetic source anywhere in the picture.
        from watchtower.sources import replay

        process_log(replay.parse_hdfs(HDFS_LINE_FOR_HOUSEKEEPING))
    finally:
        consumer.housekeeping = real
    assert calls, "housekeeping never ran for a non-synthetic source"


HDFS_LINE_FOR_HOUSEKEEPING = (
    "081109 204005 35 INFO dfs.FSNamesystem: BLOCK* NameSystem.addStoredBlock: "
    "blockMap updated: 10.251.73.220:50010 is added to blk_7128370237687728475 size 67108864"
)


def test_a_slow_webhook_does_not_hold_the_write_lock(monkeypatch):
    """The regression for the response blocking every other writer.

    The webhook's network call used to run inside `BEGIN IMMEDIATE`, holding
    SQLite's single write lock for its duration. Every other event waited behind
    it, and past `busy_timeout` (5s) they failed outright with
    `OperationalError: database is locked` — never written at all, printed by
    the source thread, and gone.

    What this test asserts is the property that prevents that: **the responses
    overlap.** Four threads each raise an alert whose webhook blocks for a
    second. Serialised behind the lock that is four seconds; concurrent it is
    one.

    It deliberately does not try to provoke "database is locked" itself. Doing
    so needs a webhook slower than busy_timeout/threads — measured here, the
    faithful pre-fix arrangement takes 4.3s for this workload and stays under
    the 5s timeout, so a test tuned to trip it would be both slow and
    fragile. Wall clock is the honest signal, and it separates the two designs
    by 3x.
    """
    barrier = threading.Barrier(4, timeout=10)
    webhook_seconds = 1.0

    def slow_webhook(ctx):
        time.sleep(webhook_seconds)
        return actions.Outcome(actions.EXECUTED, "pretended to POST")

    monkeypatch.setitem(actions.ACTIONS, "webhook", slow_webhook)

    errors = []

    def worker(n):
        try:
            barrier.wait()
            process_log(_raw(ip=f"203.0.113.{10 + n}"))
        except Exception as exc:  # noqa: BLE001 - the failure under test
            errors.append(f"{type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    started = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    elapsed = time.monotonic() - started

    assert errors == [], f"concurrent events failed: {errors}"
    # Serialised behind the write lock this is >= 4s. Two is a generous ceiling
    # that still fails loudly if the response moves back inside the transaction.
    assert elapsed < 2 * webhook_seconds, (
        f"{elapsed:.1f}s for four 1s webhooks — they serialised, so the write "
        "lock is being held across the response again"
    )

    conn = db.connect()
    assert conn.execute("SELECT count(*) FROM events").fetchone()[0] == 4
    assert repos.counters()["events"] == 4
    assert repos.counters()["blocks"] == 4
    assert conn.execute("SELECT count(*) FROM soar_executions").fetchone()[0] == 4


def test_a_response_is_recorded_before_it_can_have_a_side_effect():
    """`block_ip` commits on its own, so the record must exist before it runs.

    Round two found the window: the blocklist row committed on an autocommit
    connection while the alert still read "open" and no SOAR row existed. A stop
    or a crash in that window left an address under active enforcement beside an
    alert whose stored status means, in this module's own words, "nothing has
    run yet". A crash now leaves a row saying `running` with the steps that
    completed — incomplete, and true.
    """
    observed = {}

    def watching(ctx):
        # Mid-response: what does the store say has happened so far?
        conn = db.connect()
        row = conn.execute("SELECT id, status FROM soar_executions").fetchone()
        observed["soar_status"] = row["status"] if row else None
        return actions.Outcome(actions.EXECUTED, "noted")

    import pytest as _pytest

    mp = _pytest.MonkeyPatch()
    mp.setitem(actions.ACTIONS, "block_ip", watching)
    try:
        process_log(_raw())
    finally:
        mp.undo()

    assert observed["soar_status"] == "running", (
        "no SOAR row existed while an enforcing action was executing — the "
        "window that leaves a live block beside an alert reading 'open'"
    )
    # And it is finalised afterwards.
    final = db.connect().execute("SELECT status FROM soar_executions").fetchone()
    assert final["status"] == "contained"


def test_steps_are_recorded_as_they_complete():
    """The stored record must never claim less than what has happened."""
    counts = []

    def watching(ctx):
        counts.append(db.connect().execute("SELECT count(*) FROM soar_steps").fetchone()[0])
        return actions.Outcome(actions.EXECUTED, "noted")

    import pytest as _pytest

    mp = _pytest.MonkeyPatch()
    for name in ("block_ip", "incident_report", "notify"):
        mp.setitem(actions.ACTIONS, name, watching)
    try:
        process_log(_raw())
    finally:
        mp.undo()

    # Each action sees the steps before it already durably recorded.
    assert counts == sorted(counts)
    assert counts[-1] >= 1, "steps were only written at the end"
