"""Process-local, read-only live profile used only for event-linked shadow verdicts.

Profile files are read at startup. Ingestion uses this cached snapshot and does
no model fitting or filesystem access while holding the store write lock.
"""

from pathlib import Path

from .. import config
from . import live_profile

_profile: live_profile.LiveProfile | None = None
_unavailable_reason = "profile_missing"
_models_dir: Path | None = None


def enable(models_dir: Path) -> None:
    """Load and validate one profile for this process, or disable shadow mode."""
    global _profile, _unavailable_reason, _models_dir
    _profile = None
    _models_dir = models_dir
    path = models_dir / "live-profile.json"
    if not path.is_file():
        _unavailable_reason = "profile_missing"
        return
    try:
        _profile = live_profile.load_profile(path)
    except Exception:
        # A malformed JSON shape may raise outside load_profile's validation.
        # Startup must preserve rule ingestion even then.
        _unavailable_reason = "profile_invalid"
        return
    _unavailable_reason = ""


def status() -> dict:
    """Report the active process snapshot; no per-request file reads."""
    if _models_dir != config.get().models_dir:
        return {
            "status": "unavailable",
            "detector": "live_profile_shadow",
            "reason": "profile_not_loaded",
            "profile_digest": None,
        }
    if _profile is None:
        return {
            "status": "unavailable",
            "detector": "live_profile_shadow",
            "reason": _unavailable_reason,
            "profile_digest": None,
        }
    return {
        "status": "enabled",
        "detector": "live_profile_shadow",
        "profile_digest": _profile.digest,
        "profile_version": _profile.version,
        "source_hash": _profile.source_hash,
        "normal_windows": _profile.normal_windows,
        "mode": "shadow_only",
    }


def verdict(features: dict | None = None, *, blocked: bool = False) -> dict:
    """Score bounded rule features; failures never affect rule ingestion."""
    profile = _profile if _models_dir == config.get().models_dir else None
    if blocked:
        return {
            "status": "skipped",
            "detector": "live_profile_shadow",
            "reason": "blocked_event",
            "profile_digest": profile.digest if profile else None,
        }
    if profile is None:
        reason = (
            _unavailable_reason if _models_dir == config.get().models_dir else "profile_not_loaded"
        )
        return live_profile.score({}, None) | {"reason": reason}
    try:
        return live_profile.score(features or {}, profile)
    except Exception:
        return {
            "status": "unavailable",
            "detector": "live_profile_shadow",
            "reason": "invalid_features",
            "profile_digest": profile.digest,
        }
