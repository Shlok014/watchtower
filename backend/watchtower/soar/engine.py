"""Playbook selection.

Written in the imperative — "Block IP", not "IP Blocked".

The past tense mattered more than it looks. Combined with a ✓ in the UI and a
"completed" status, "IP Blocked" reads as a record of a remediation that
happened. Nothing here contacts a firewall, a mail server or a ticket system, so
these are the steps a playbook *would* run.
"""

import time
from datetime import UTC, datetime

PLAYBOOKS = {
    "brute_force": {
        "actions": ["Block IP", "Terminate session", "Send alert email", "Open incident ticket"],
        "priority": "P1",
    },
    "suspicious_ip": {
        "actions": ["Block IP", "Update firewall rule", "Send alert email"],
        "priority": "P2",
    },
    "malware_detected": {
        "actions": ["Isolate host", "Trigger AV scan", "Send alert email", "Open incident ticket"],
        "priority": "P1",
    },
    "port_scan": {"actions": ["Block IP", "Update IDS rule", "Send alert email"], "priority": "P2"},
    "privilege_escalation": {
        "actions": [
            "Terminate session",
            "Lock account",
            "Send alert email",
            "Open incident ticket",
            "Start forensics",
        ],
        "priority": "P1",
    },
    "data_exfiltration": {
        "actions": [
            "Isolate network segment",
            "Terminate session",
            "Send alert email",
            "Start forensics",
        ],
        "priority": "P1",
    },
    "failed_login": {
        "actions": ["Send alert email", "Enable account monitoring"],
        "priority": "P3",
    },
}

DEFAULT_PLAYBOOK = {"actions": ["Notify", "Log to SIEM"], "priority": "P3"}


def respond(alert_entry: dict) -> dict:
    """Select a response playbook for an alert.

    No step here has a side effect: nothing contacts a firewall, sends mail, or
    opens a ticket. The previous version disguised that by inventing a per-step
    ``duration_ms = random.randint(120, 850)`` and stamping each step "completed"
    with a timestamp in the future, producing an execution trace detailed enough
    to be mistaken for a real one.

    Timings are now measured, which honestly yields microseconds, and every
    field says the step was selected rather than performed.
    """
    event = alert_entry["event"]
    playbook = PLAYBOOKS.get(event, DEFAULT_PLAYBOOK)
    actions = playbook["actions"]

    ts = datetime.now(UTC)
    steps = []
    t_start = time.perf_counter()
    for action in actions:
        t0 = time.perf_counter()
        # This is where a real integration would run. There isn't one.
        steps.append(
            {
                "action": action,
                "status": "selected",
                "executed": False,
                "duration_us": round((time.perf_counter() - t0) * 1e6, 1),
                "detail": "no integration configured — step selected, not executed",
            }
        )
    total_us = round((time.perf_counter() - t_start) * 1e6, 1)

    return {
        "alert_id": alert_entry["id"],
        "timestamp": ts.isoformat(),
        "event": event,
        "ip": alert_entry["ip"],
        # Renamed from `actions_taken`: nothing was taken.
        "playbook_steps": actions,
        "execution_steps": steps,
        "execution_mode": "simulated",
        "selection_time_us": total_us,
        "status": "selected",
        "priority": playbook["priority"],
        "playbook": f"PB-{event.upper().replace('_', '-')}",
    }
