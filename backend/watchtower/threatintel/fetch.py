"""Feed downloader.

    python -m watchtower.threatintel.fetch            # refresh both feeds
    python -m watchtower.threatintel.fetch --status   # report cache state, fetch nothing

Order of operations matters and is deliberate: download -> parse-validate ->
atomic write -> manifest update. A response that fails validation never touches
the cache, so the previous good copy survives a rate-limit page or a truncated
transfer.
"""

import argparse
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

from . import parse, store
from .feeds import FEEDS, FeedSpec

USER_AGENT = "Watchtower/0.2 (+https://github.com/Shlok014/watchtower)"
MAX_BYTES = 32 * 1024 * 1024
TIMEOUT = 20.0


def _ssl_context() -> ssl.SSLContext:
    """A verifying TLS context that also works on python.org macOS builds.

    Those installs ship no CA bundle until `Install Certificates.command` is
    run, so `urlopen` fails with CERTIFICATE_VERIFY_FAILED out of the box. The
    fix is certifi's bundle — the same one pip and requests use.

    Certificate verification is never disabled. An unverified context would let
    anyone on the path substitute their own blocklist, which for a tool whose
    entire job is deciding which addresses are hostile would be a considerably
    worse defect than the fabricated table this package replaces.
    """
    ctx = ssl.create_default_context()
    if ctx.cert_store_stats().get("x509_ca", 0):
        return ctx
    try:
        import certifi
    except ImportError:
        return ctx  # let it fail loudly with a real TLS error
    return ssl.create_default_context(cafile=certifi.where())


def fetch_feed(spec: FeedSpec, cache_dir: Path, prev: dict | None, timeout: float = TIMEOUT):
    """Return (status, detail, manifest_entry_or_None)."""
    req = urllib.request.Request(spec.url, headers={"User-Agent": USER_AGENT})
    if prev:
        # Be a polite client: both feeds serve validators, so an unchanged feed
        # costs a 304 instead of a full re-download.
        if prev.get("http_etag"):
            req.add_header("If-None-Match", prev["http_etag"])
        if prev.get("http_last_modified"):
            req.add_header("If-Modified-Since", prev["http_last_modified"])
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as resp:
            body = resp.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                return "failed", f"response exceeds {MAX_BYTES} bytes", None
            headers, status = resp.headers, resp.status
    except urllib.error.HTTPError as exc:
        if exc.code == 304 and prev:
            entry = dict(prev, checked_at=store.utcnow(), http_status=304)
            return "unchanged", f"{prev.get('entries', 0)} entries (304)", entry
        return "failed", f"HTTP {exc.code}", None
    except Exception as exc:  # URLError, timeout, SSL, DNS
        return "failed", f"{type(exc).__name__}: {exc}", None

    entries = parse.count(spec.parser, body)
    if entries < spec.min_entries:
        # A 200 carrying HTML (captcha, rate limit, outage page) lands here.
        return (
            "failed",
            f"parsed {entries} entries, below the {spec.min_entries} floor — cache left untouched",
            None,
        )

    store.atomic_write_bytes(cache_dir / spec.filename, body)
    entry = {
        "url": spec.url,
        "filename": spec.filename,
        # fetched_at = when the bytes last changed; checked_at = when we last
        # asked. Staleness is judged on fetched_at, because that is what the
        # data actually reflects.
        "fetched_at": store.utcnow(),
        "checked_at": store.utcnow(),
        "http_status": status,
        "http_etag": headers.get("ETag"),
        "http_last_modified": headers.get("Last-Modified"),
        "bytes": len(body),
        "sha256": store.sha256_bytes(body),
        "entries": entries,
        "max_age_hours": spec.max_age_hours,
    }
    return "updated", f"{entries} entries", entry


def fetch_all(cache_dir: Path | None = None) -> int:
    cache_dir = store.default_cache_dir() if cache_dir is None else cache_dir
    cache_dir.mkdir(parents=True, exist_ok=True)
    manifest = store.load_manifest(cache_dir)
    failures = 0
    for spec in FEEDS:
        prev = manifest.get("feeds", {}).get(spec.name)
        status, detail, entry = fetch_feed(spec, cache_dir, prev)
        if entry:
            manifest.setdefault("feeds", {})[spec.name] = entry
        if status == "failed":
            failures += 1
            kept = "keeping cached copy" if prev else "no cached copy available"
            print(f"  ✗ {spec.name:16} {detail} ({kept})", file=sys.stderr)
        else:
            print(f"  ✓ {spec.name:16} {status}: {detail}")
    store.save_manifest(manifest, cache_dir)
    return failures


def print_status(cache_dir: Path | None = None) -> int:
    cache_dir = store.default_cache_dir() if cache_dir is None else cache_dir
    from .index import MISSING, ReputationIndex

    idx = ReputationIndex.load(cache_dir)
    missing = 0
    for spec in FEEDS:
        st = idx.states[spec.name]
        if st.state == MISSING:
            missing += 1
            print(f"  ✗ {spec.name:16} missing — {st.error}")
        else:
            age = f"{st.age_hours:.1f}h" if st.age_hours is not None else "unknown age"
            print(f"  ✓ {spec.name:16} {st.state}, {st.entries} entries, fetched {age} ago")
    return missing


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Fetch Watchtower threat-intel feeds")
    ap.add_argument("--status", action="store_true", help="report cache state without fetching")
    args = ap.parse_args(argv)
    if args.status:
        return 1 if print_status() else 0
    print("Fetching threat-intel feeds…")
    failures = fetch_all()
    if failures:
        print(
            f"\n{failures} feed(s) unavailable. Watchtower still runs — IP reputation "
            "reports 'unavailable' rather than guessing.",
            file=sys.stderr,
        )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
