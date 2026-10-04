"""Offline normal-window envelope for shadow scoring of live rule features.

This module has no alert or SOAR interface. Fit it outside ingestion from an
explicitly normal baseline, then pass the already computed rule features to
``score``. The score is an uncalibrated robust deviation, not a probability.
"""

import hashlib
import json
import math
from dataclasses import dataclass
from numbers import Real
from pathlib import Path
from statistics import median

FEATURE_NAMES = (
    "failed_attempts_count",
    "request_frequency",
    "ip_reputation_score",
)
PROFILE_VERSION = 1
THRESHOLD = 1.0
SCALE_FLOORS = {
    "failed_attempts_count": 1.0,
    "request_frequency": 1.0,
    "ip_reputation_score": 0.05,
}


def _vector(features: dict) -> dict[str, float]:
    values = {}
    for name in FEATURE_NAMES:
        raw = features.get(name)
        if isinstance(raw, bool) or not isinstance(raw, Real) or not math.isfinite(raw):
            raise ValueError(f"{name} must be a finite nonnegative number")
        value = float(raw)
        if value < 0 or (name == "ip_reputation_score" and value > 1):
            raise ValueError(f"{name} must be a finite nonnegative number in range")
        values[name] = value
    return values


def _digest(payload: dict) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode()).hexdigest()


@dataclass(frozen=True)
class LiveProfile:
    """A robust, normal-only baseline; never an alert policy."""

    centers: dict[str, float]
    scales: dict[str, float]
    normal_windows: int
    source_hash: str
    digest: str
    version: int = PROFILE_VERSION

    def score(self, features: dict) -> dict:
        values = _vector(features)
        # Three robust standard deviations above the training median is the
        # fixed, pre-evaluation decision boundary. The test labels never tune it.
        deviations = {
            name: max(0.0, values[name] - self.centers[name]) / (3 * self.scales[name])
            for name in FEATURE_NAMES
        }
        anomaly_score = max(deviations.values())
        return {
            "status": "scored",
            "detector": "live_profile_shadow",
            "profile_digest": self.digest,
            "anomaly_score": round(anomaly_score, 4),
            "shadow_anomaly": anomaly_score > THRESHOLD,
            "top_feature": max(deviations, key=deviations.get),
            "basis": "normal-only robust deviation; synthetic validation only",
        }

    def payload(self) -> dict:
        return {
            "version": self.version,
            "centers": self.centers,
            "scales": self.scales,
            "normal_windows": self.normal_windows,
            "source_hash": self.source_hash,
        }


def fit_normal(windows: list[dict], source_hash: str) -> LiveProfile:
    """Fit once offline from an explicitly selected normal-only baseline."""
    if not windows:
        raise ValueError("normal baseline must contain at least one window")
    if not source_hash:
        raise ValueError("source_hash is required")
    rows = [_vector(features) for features in windows]
    centers = {name: float(median(row[name] for row in rows)) for name in FEATURE_NAMES}
    scales = {
        name: max(
            SCALE_FLOORS[name], 1.4826 * median(abs(row[name] - centers[name]) for row in rows)
        )
        for name in FEATURE_NAMES
    }
    payload = {
        "version": PROFILE_VERSION,
        "centers": centers,
        "scales": scales,
        "normal_windows": len(rows),
        "source_hash": source_hash,
    }
    return LiveProfile(**payload, digest=_digest(payload))


def score(features: dict, profile: LiveProfile | None = None) -> dict:
    """Return a pure shadow verdict or explicit unavailable metadata."""
    if profile is None:
        return {
            "status": "unavailable",
            "detector": "live_profile_shadow",
            "reason": "profile_missing",
            "profile_digest": None,
        }
    return profile.score(features)


def save_profile(profile: LiveProfile, path: str | Path) -> None:
    """Persist the versioned profile produced by offline fitting."""
    Path(path).write_text(
        json.dumps({**profile.payload(), "digest": profile.digest}, sort_keys=True)
    )


def load_profile(path: str | Path) -> LiveProfile:
    """Load only a valid profile; caller can disable shadow mode on errors."""
    try:
        data = json.loads(Path(path).read_text())
        digest = data.pop("digest")
        if data["version"] != PROFILE_VERSION or set(data["centers"]) != set(FEATURE_NAMES):
            raise ValueError("unsupported profile version or features")
        if set(data["scales"]) != set(FEATURE_NAMES):
            raise ValueError("unsupported profile features")
        if digest != _digest(data):
            raise ValueError("profile digest mismatch")
        profile = LiveProfile(**data, digest=digest)
        if profile.normal_windows <= 0 or not profile.source_hash:
            raise ValueError("invalid profile baseline")
        _vector(profile.centers)
        _vector(profile.scales)
        if any(value <= 0 for value in profile.scales.values()):
            raise ValueError("invalid profile scales")
        return profile
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid profile") from exc
