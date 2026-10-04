"""Response actions that actually do something, and say so when they do not.

Every action returns an ``Outcome``. There are exactly three statuses and they
mean what they say:

    executed   the side effect happened, and the detail says what it was
    failed     it was attempted and did not work — connection refused, no
               write permission — and the detail carries the error
    skipped    it was not attempted, because nothing is configured to attempt
               it with. Not a failure. Not a success either.

The version this replaces returned a list of strings like ``"IP Blocked"``,
stamped each one "completed" with a `random.randint(120, 850)` duration, and set
the alert to `mitigated` on the next line. Nothing was ever contacted.

**Scope, stated deliberately.** Enforcement happens at this application's own
ingestion layer: a blocked address has its later events dropped before detection
runs. Nothing here touches pf, iptables, or any firewall, and nothing needs
root. "Real firewall integration would need pfctl and root; I scoped enforcement
to the pipeline" is a defensible decision. A `pfctl` wrapper nobody dares demo
is not.
"""

import json
import os
import time
import urllib.error
import urllib.request
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .. import config
from ..store import repos

EXECUTED = "executed"
FAILED = "failed"
SKIPPED = "skipped"

WEBHOOK_TIMEOUT_S = 3.0


@dataclass
class Outcome:
    status: str
    detail: str
    duration_us: float = 0.0
    data: dict | None = None

    @property
    def executed(self) -> bool:
        return self.status == EXECUTED

    @property
    def failed(self) -> bool:
        return self.status == FAILED


@dataclass
class Context:
    """Everything an action is allowed to know about the alert that fired it."""

    conn: object
    alert: dict
    step_params: dict

    def format(self, template: str) -> str:
        try:
            return template.format(
                **{k: v for k, v in self.alert.items() if isinstance(v, str | int | float)}
            )
        except (KeyError, IndexError, ValueError):
            # A bad placeholder in policy must not take down the response.
            return template


# ─── block_ip ────────────────────────────────────────────────────────────────
def block_ip(ctx: Context) -> Outcome:
    """Add the alert's address to the blocklist, with a TTL.

    This is the closed loop: ``pipeline.consumer`` checks the blocklist *before*
    detection, so events from this address are really suppressed from here on
    and the drop is counted against the block that caused it.
    """
    ip = ctx.alert.get("ip")
    if not ip:
        return Outcome(FAILED, "alert carries no address to block")

    ttl = int(ctx.step_params.get("ttl_seconds", 3600))
    if ttl <= 0:
        return Outcome(FAILED, f"ttl_seconds must be positive, got {ttl}")

    reason = str(ctx.step_params.get("reason") or ctx.alert.get("event", "alert"))
    row = repos.block_ip(
        ctx.conn,
        ip=ip,
        reason=reason,
        alert_id=ctx.alert.get("id"),
        ttl_seconds=ttl,
    )
    return Outcome(
        EXECUTED,
        f"{ip} blocked for {ttl}s at this pipeline's ingestion layer "
        f"(no firewall involved); expires {repos.to_iso(row['expires_ts_ms'])}",
        data={"ip": ip, "ttl_seconds": ttl, "expires_at": repos.to_iso(row["expires_ts_ms"])},
    )


# ─── webhook ─────────────────────────────────────────────────────────────────
def webhook(ctx: Context) -> Outcome:
    """POST the alert to WATCHTOWER_WEBHOOK_URL, if one is configured.

    Real network I/O with a real timeout. Connection refused is recorded as
    ``failed``, not swallowed — a notifier that silently drops alerts is worse
    than no notifier, because the operator believes someone was told.
    """
    url = ctx.step_params.get("url") or os.environ.get("WATCHTOWER_WEBHOOK_URL")
    if not url:
        return Outcome(SKIPPED, "no webhook configured (set WATCHTOWER_WEBHOOK_URL)")

    payload = json.dumps(
        {
            "source": "watchtower",
            "alert_id": ctx.alert.get("id"),
            "event": ctx.alert.get("event"),
            "ip": ctx.alert.get("ip"),
            "severity": ctx.alert.get("severity"),
            "anomaly_score": ctx.alert.get("anomaly_score"),
            "explanation": ctx.alert.get("explanation"),
            "timestamp": ctx.alert.get("timestamp"),
        }
    ).encode()

    try:
        req = urllib.request.Request(
            url, data=payload, headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(req, timeout=WEBHOOK_TIMEOUT_S) as resp:
            return Outcome(
                EXECUTED, f"webhook POST → HTTP {resp.status}", data={"status": resp.status}
            )
    except urllib.error.HTTPError as exc:
        # A 4xx/5xx is a real answer from a real server, and it is still a
        # failure to deliver.
        return Outcome(FAILED, f"webhook POST → HTTP {exc.code}", data={"status": exc.code})
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return Outcome(FAILED, f"webhook POST failed: {type(exc).__name__}")


# ─── incident_report ─────────────────────────────────────────────────────────
def incident_report(ctx: Context) -> Outcome:
    """Write a real INC-<date>-<seq>.md and .json with the evidence.

    Includes the ledger heights covering the cited events, so the report points
    at something whose integrity can be independently verified rather than
    restating the alert in prose.
    """
    cfg = config.get()
    directory = cfg.incidents_dir
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return Outcome(FAILED, f"cannot create {directory}: {exc}")

    alert = ctx.alert
    ip = alert.get("ip", "")
    triggering_event = repos.event_for_alert(ctx.conn, alert["id"])
    local_file_event = (
        triggering_event is not None
        and triggering_event["origin"] == "file"
        and triggering_event["event"] == "privilege_escalation"
        and ip == "127.0.0.1"
    )
    # Loopback is a placeholder for local file events, not a shared actor.
    # Grouping all loopback events into one report invents a relationship.
    evidence_scope = "triggering_local_event" if local_file_event else "recent_ip_events"
    evidence = (
        [triggering_event]
        if local_file_event
        else repos.recent_events_for_ip(ctx.conn, ip, limit=20)
        if ip
        else []
    )
    event_ids = [e["id"] for e in evidence]
    heights = repos.ledger_heights_for_events(ctx.conn, event_ids) if event_ids else []

    record = {
        "opened_at": datetime.now(UTC).isoformat(),
        "alert_id": alert.get("id"),
        "event": alert.get("event"),
        "severity": alert.get("severity"),
        "ip": ip,
        "source": alert.get("source"),
        "user": alert.get("user"),
        "anomaly_score": alert.get("anomaly_score"),
        "explanation": alert.get("explanation"),
        "ruleset_version": alert.get("ruleset_version"),
        "evidence_event_ids": event_ids,
        "evidence_scope": evidence_scope,
        "covering_ledger_blocks": heights,
        "verify_with": "python -m watchtower ledger verify",
    }

    try:
        ident, markdown_path = _write_incident_files(directory, record, evidence)
    except OSError as exc:
        return Outcome(FAILED, f"could not write incident report: {exc}")

    return Outcome(
        EXECUTED,
        f"wrote {ident}.md and {ident}.json ({len(event_ids)} evidence events, "
        f"{len(heights)} covering ledger blocks)",
        data={"incident_id": ident, "path": str(markdown_path)},
    )


def _write_incident_files(directory: Path, record: dict, evidence: list) -> tuple[str, Path]:
    """Claim both report names without replacing another writer's evidence."""
    day = datetime.now(UTC).strftime("%Y%m%d")
    seq = len(list(directory.glob(f"INC-{day}-*.json"))) + 1
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    while True:
        ident = f"INC-{day}-{seq:03d}"
        json_path = directory / f"{ident}.json"
        markdown_path = directory / f"{ident}.md"
        record["id"] = ident
        json_text = json.dumps(record, indent=2)
        markdown_text = _incident_markdown(record, evidence)

        try:
            json_fd = os.open(json_path, flags, 0o600)
        except FileExistsError:
            seq += 1
            continue
        try:
            markdown_fd = os.open(markdown_path, flags, 0o600)
        except OSError as exc:
            os.close(json_fd)
            json_path.unlink()
            if isinstance(exc, FileExistsError):
                seq += 1
                continue
            raise

        try:
            # Each descriptor belongs to this writer's exclusive filename.
            with os.fdopen(markdown_fd, "w", encoding="utf-8") as output:
                output.write(markdown_text)
            with os.fdopen(json_fd, "w", encoding="utf-8") as output:
                output.write(json_text)
        except OSError:
            with suppress(OSError):
                os.close(markdown_fd)
            with suppress(OSError):
                os.close(json_fd)
            with suppress(OSError):
                markdown_path.unlink()
            with suppress(OSError):
                json_path.unlink()
            raise
        return ident, markdown_path


def _incident_markdown(r: dict, evidence: list) -> str:
    local_file_event = r["evidence_scope"] == "triggering_local_event"
    address_line = (
        f"**Local host:** {_markdown_text(r['source'])} · **User:** {_markdown_text(r['user'])}  "
        if local_file_event
        else f"**Address:** `{_markdown_text(r['ip'])}` · **User:** {_markdown_text(r['user'])}  "
    )
    evidence_line = (
        f"{len(r['evidence_event_ids'])} triggering event from this local host, covered by ledger "
        if local_file_event
        else f"{len(r['evidence_event_ids'])} events from this address, covered by ledger "
    )
    lines = [
        f"# {r['id']}",
        "",
        f"**Opened:** {_markdown_text(r['opened_at'])}  ",
        f"**Event:** {_markdown_text(r['event'])} · **Severity:** {_markdown_text(r['severity'])} · "
        f"**Score:** {_markdown_text(r['anomaly_score'])}  ",
        address_line,
        f"**Ruleset:** `{_markdown_text(r['ruleset_version'])}`",
        "",
        "## Why this fired",
        "",
        _markdown_text(r["explanation"]),
        "",
        "## Evidence",
        "",
        f"{evidence_line}blocks {_range_text(r['covering_ledger_blocks'])}.",
        "",
        "| Event | Time | Type | Severity | Message |",
        "|---:|---|---|---|---|",
    ]
    for e in evidence[:20]:
        msg = _markdown_text(e["message"] or "", limit=90)
        lines.append(
            f"| {e['id']} | {_markdown_text(e['timestamp'])} | {_markdown_text(e['event'])} "
            f"| {_markdown_text(e['severity'])} | {msg} |"
        )
    lines += [
        "",
        "## Verifying this report",
        "",
        "The events above are linked in the local audit ledger. This checks the",
        "blocks currently present and detects edits that break the chain:",
        "",
        "```bash",
        f"{r['verify_with']}",
        "```",
        "",
        "A consistent chain rewrite or deletion of the final block requires a",
        "trusted external checkpoint kept outside this database. Verify with",
        "`--checkpoint PATH` when one is available. This report alone does not",
        "prove the history is complete.",
        "",
        "## What was and was not done",
        "",
        "This report is a record, not a remediation. Enforcement in this system",
        "happens at the ingestion layer: a blocked address has its later events",
        "dropped before detection runs. Nothing contacted a firewall, a mail",
        "server, or a ticketing system.",
        "",
    ]
    return "\n".join(lines)


def _markdown_text(value: object, *, limit: int | None = None) -> str:
    """Render untrusted text as plain text inside Markdown and table cells."""
    value = "" if value is None else str(value)
    if limit is not None:
        value = value[:limit]
    leading_digits = len(value) - len(value.lstrip("0123456789"))
    out = []
    for index, char in enumerate(value):
        if char == "\n":
            out.append(r"\n")
        elif char == "\r":
            out.append(r"\r")
        elif char == "\t":
            out.append(r"\t")
        elif not char.isprintable():
            out.append(f"\\u{ord(char):04x}")
        elif char == "&":
            out.append("&amp;")
        elif char == "<":
            out.append("&lt;")
        elif char == ">":
            out.append("&gt;")
        elif char == "`":
            # Backslash escapes are ignored inside a Markdown code span.
            out.append("&#96;")
        elif char in r"\*_{}[]()#!|~" or (char in "+-" and index == 0):
            out.append("\\" + char)
        elif (
            char == "."
            and index == leading_digits
            and leading_digits > 0
            and (index + 1 == len(value) or value[index + 1].isspace())
        ):
            out.append(r"\.")
        else:
            out.append(char)
    return "".join(out)


def _range_text(heights: list) -> str:
    if not heights:
        return "(none — the events were pruned by retention)"
    return f"{min(heights)}–{max(heights)}" if len(heights) > 1 else str(heights[0])


# ─── notify ──────────────────────────────────────────────────────────────────
def notify(ctx: Context) -> Outcome:
    """Write a line to the process log. Honest about being exactly that."""
    message = ctx.format(str(ctx.step_params.get("message", "alert raised")))
    print(f"🔔 SOAR: {message}")
    return Outcome(EXECUTED, f"logged to this process's stdout: {message}")


ACTIONS = {
    "block_ip": block_ip,
    "webhook": webhook,
    "incident_report": incident_report,
    "notify": notify,
}


def run(name: str, ctx: Context) -> Outcome:
    """Run one action, timing it and never letting it take the pipeline down."""
    fn = ACTIONS.get(name)
    if fn is None:
        return Outcome(FAILED, f"no such action {name!r}")
    t0 = time.perf_counter()
    try:
        outcome = fn(ctx)
    except Exception as exc:
        # A lower-level webhook exception may include the URL in its message.
        detail = type(exc).__name__ if name == "webhook" else f"{type(exc).__name__}: {exc}"
        outcome = Outcome(FAILED, detail)
    outcome.duration_us = round((time.perf_counter() - t0) * 1e6, 1)
    return outcome
