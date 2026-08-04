"""Load and validate response playbooks.

Policy lives in ``backend/playbooks/*.yaml`` rather than in a Python dict,
because "which events get contained, in what order, and which steps are allowed
to fail" is configuration a security team changes without shipping code.

Validation is strict and loud. A playbook naming an action that does not exist
is a policy that will silently not run — the failure mode this whole session is
about — so it raises at load time rather than at 3am.
"""

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .. import config

WILDCARD = "*"


class PlaybookError(ValueError):
    pass


@dataclass(frozen=True)
class Step:
    action: str
    required: bool = False
    params: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Playbook:
    name: str
    trigger: str
    priority: str
    steps: tuple[Step, ...]
    source: str

    @property
    def is_default(self) -> bool:
        return self.trigger == WILDCARD


def playbooks_dir() -> Path:
    return config.BASE_DIR / "playbooks"


VALID_PRIORITIES = {"P1", "P2", "P3", "P4"}


def parse(data: dict, source: str, known_actions: set[str]) -> Playbook:
    if not isinstance(data, dict):
        raise PlaybookError(f"{source}: expected a mapping at the top level")
    for key in ("name", "trigger", "actions"):
        if key not in data:
            raise PlaybookError(f"{source}: missing required key {key!r}")

    priority = str(data.get("priority", "P3"))
    if priority not in VALID_PRIORITIES:
        raise PlaybookError(
            f"{source}: priority {priority!r} is not one of {sorted(VALID_PRIORITIES)}"
        )

    raw_actions = data["actions"]
    if not isinstance(raw_actions, list) or not raw_actions:
        raise PlaybookError(f"{source}: 'actions' must be a non-empty list")

    steps = []
    for i, raw in enumerate(raw_actions):
        if not isinstance(raw, dict) or "action" not in raw:
            raise PlaybookError(f"{source}: action {i} must be a mapping with an 'action' key")
        name = str(raw["action"])
        if name not in known_actions:
            # The important one. A typo here is a step that never runs, and a
            # playbook that quietly does nothing is indistinguishable from one
            # that ran and found nothing to do.
            raise PlaybookError(
                f"{source}: unknown action {name!r} — known actions: "
                f"{', '.join(sorted(known_actions))}"
            )
        params = {k: v for k, v in raw.items() if k not in ("action", "required")}
        steps.append(Step(action=name, required=bool(raw.get("required", False)), params=params))

    return Playbook(
        name=str(data["name"]),
        trigger=str(data["trigger"]),
        priority=priority,
        steps=tuple(steps),
        source=source,
    )


def load_all(directory: Path | None = None, known_actions: set[str] | None = None) -> dict:
    """Return {trigger: Playbook}. Raises on any malformed file."""
    from .actions import ACTIONS

    known_actions = known_actions if known_actions is not None else set(ACTIONS)
    directory = directory or playbooks_dir()
    out: dict[str, Playbook] = {}
    if not directory.is_dir():
        raise PlaybookError(f"no playbook directory at {directory}")

    for path in sorted(directory.glob("*.yaml")):
        # safe_load, never load. yaml.load can construct arbitrary Python
        # objects from a document, and a SOAR engine that executes its own
        # config is not a place to accept that trade.
        try:
            data = yaml.safe_load(path.read_text())
        except yaml.YAMLError as exc:
            raise PlaybookError(f"{path.name}: {exc}") from exc
        pb = parse(data, path.name, known_actions)
        if pb.trigger in out:
            raise PlaybookError(
                f"{path.name}: trigger {pb.trigger!r} is already defined by "
                f"{out[pb.trigger].source}"
            )
        out[pb.trigger] = pb

    if not out:
        raise PlaybookError(f"no playbooks found in {directory}")
    return out


_cache: dict | None = None


def all_playbooks(reload: bool = False) -> dict:
    global _cache
    if _cache is None or reload:
        _cache = load_all()
    return _cache


def for_event(event: str) -> Playbook:
    """The playbook for this event, or the wildcard one."""
    books = all_playbooks()
    if event in books:
        return books[event]
    if WILDCARD in books:
        return books[WILDCARD]
    raise PlaybookError(f"no playbook for {event!r} and no default is defined")
