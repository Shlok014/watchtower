"""Execute a response playbook, and report exactly what happened.

The status lifecycle is the whole point of this module:

    open            the alert was raised and nothing has run yet
    contained       every required step succeeded, and at least one had a real
                    side effect
    mitigated       every required step succeeded and the playbook considers
                    the incident closed
    action_failed   a required step failed. The alert stays visible.

What this replaces set ``alert["status"] = "mitigated"`` on the line after
selecting a playbook. Selecting a playbook only built a dict, so every alert in
the system claimed to have been remediated the instant it was raised — and the
UI showed a green tick beside each one.

A status is now earned by an action that actually ran, and an action reports
``skipped`` when nothing is configured for it rather than pretending either way.
"""

import time
from datetime import UTC, datetime

from . import actions as actions_mod
from . import playbooks as playbooks_mod

OPEN = "open"
CONTAINED = "contained"
MITIGATED = "mitigated"
ACTION_FAILED = "action_failed"

# Actions with a side effect on the world outside this process's own bookkeeping.
# Reaching `contained` requires at least one of them to have run: a playbook
# whose only successful step was writing a log line has not contained anything.
ENFORCING_ACTIONS = {"block_ip"}


def respond(conn, alert: dict, on_step=None, on_start=None) -> dict:
    """Run the playbook for this alert. Returns the execution record.

    ``on_start`` is called with the selected playbook *before* the first action,
    and ``on_step`` after each one completes. They exist so the store can record
    that a response is under way before anything has a side effect: `block_ip`
    commits on its own, so without them a crash mid-response left an address
    under active enforcement beside an alert reading "open" — which this
    module's own vocabulary defines as "nothing has run yet".
    """
    playbook = playbooks_mod.for_event(alert.get("event", ""))
    ts = datetime.now(UTC)
    if on_start is not None:
        on_start(playbook)
    t_start = time.perf_counter()

    steps = []
    required_failed = False
    enforced = False
    executed_any = False

    for step in playbook.steps:
        ctx = actions_mod.Context(conn=conn, alert=alert, step_params=step.params)
        outcome = actions_mod.run(step.action, ctx)
        if outcome.executed:
            executed_any = True
            if step.action in ENFORCING_ACTIONS:
                enforced = True
        if outcome.failed and step.required:
            required_failed = True
        record = {
            "action": step.action,
            "status": outcome.status,
            "required": step.required,
            "executed": outcome.executed,
            "duration_us": outcome.duration_us,
            "detail": outcome.detail,
        }
        steps.append(record)
        if on_step is not None:
            on_step(len(steps) - 1, record)

    total_us = round((time.perf_counter() - t_start) * 1e6, 1)

    if required_failed:
        status = ACTION_FAILED
    elif enforced:
        status = CONTAINED
    elif executed_any:
        # Something ran, nothing was enforced. "mitigated" would overstate it,
        # and "open" would understate it. This is what the playbook could do.
        status = MITIGATED if _closes(playbook) else OPEN
    else:
        status = OPEN

    return {
        "alert_id": alert["id"],
        "timestamp": ts.isoformat(),
        "event": alert["event"],
        "ip": alert["ip"],
        "playbook": playbook.name,
        "playbook_source": playbook.source,
        "playbook_steps": [s.action for s in playbook.steps],
        "execution_steps": steps,
        # 'live' now: at least one action in this build has a real side effect.
        # The column still admits 'simulated' because a build with every
        # integration removed should be able to say so.
        "execution_mode": "live",
        "selection_time_us": total_us,
        "status": status,
        "priority": playbook.priority,
    }


def _closes(playbook) -> bool:
    """Does succeeding at this playbook actually resolve the incident?

    Only when a required step had a real side effect. A playbook of notify and
    webhook has told somebody; it has not fixed anything, and calling that
    'mitigated' is how the previous version came to mark every alert resolved.
    """
    return any(s.required and s.action in ENFORCING_ACTIONS for s in playbook.steps)


def describe(*, include_params: bool = False) -> list[dict]:
    """Describe policy without publishing operator-supplied step parameters.

    A webhook URL may itself be a credential. Only an authorized owner may
    inspect raw parameters; anonymous readers still see the response flow.
    """
    return [
        {
            "name": pb.name,
            "trigger": pb.trigger,
            "priority": pb.priority,
            "source": pb.source,
            "steps": [
                {
                    "action": s.action,
                    "required": s.required,
                    "params": s.params if include_params else {},
                }
                for s in pb.steps
            ],
        }
        for pb in playbooks_mod.all_playbooks().values()
    ]
