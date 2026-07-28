"""Cache location, provenance manifest, and atomic writes."""

import contextlib
import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path

CACHE_DIR = Path(__file__).resolve().parent.parent / "data" / "feeds"
MANIFEST_NAME = "manifest.json"
SCHEMA = 1


def utcnow() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write via a temp file in the same directory, then os.replace.

    A half-written blocklist is indistinguishable from a short one, and a short
    one silently under-reports threats. Either the whole file lands or none of it.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", suffix=path.suffix)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def load_manifest(cache_dir: Path = CACHE_DIR) -> dict:
    path = cache_dir / MANIFEST_NAME
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return {"schema": SCHEMA, "feeds": {}}
    if not isinstance(data, dict) or "feeds" not in data:
        return {"schema": SCHEMA, "feeds": {}}
    return data


def save_manifest(manifest: dict, cache_dir: Path = CACHE_DIR) -> None:
    manifest["schema"] = SCHEMA
    atomic_write_bytes(
        cache_dir / MANIFEST_NAME, json.dumps(manifest, indent=2, sort_keys=True).encode()
    )


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_cached(spec, cache_dir: Path = CACHE_DIR, manifest: dict | None = None):
    """Return the cached bytes for a feed, or None.

    Verifies the recorded sha256. A mismatch means a truncated or corrupted
    cache, and it is reported as *missing* rather than loaded partially — a
    partial blocklist would answer "unlisted" for addresses it simply never saw.
    """
    path = cache_dir / spec.filename
    try:
        data = path.read_bytes()
    except OSError:
        return None
    manifest = manifest if manifest is not None else load_manifest(cache_dir)
    recorded = manifest.get("feeds", {}).get(spec.name, {}).get("sha256")
    if recorded and sha256_bytes(data) != recorded:
        return None
    return data
