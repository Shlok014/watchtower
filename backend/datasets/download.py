"""Fetch the public log datasets used for parsing and detection benchmarks.

    python -m datasets.download --samples     # ~700 KB, checked into nothing, instant
    python -m datasets.download --hdfs        # ~186 MB download -> ~1.5 GB extracted
    python -m datasets.download --hdfs --delete-raw   # reclaim the 1.5 GB after parsing

Nothing here is committed. The data is third-party and large; `data/` is
git-ignored and this script is how it gets there.

Sources
  loghub HDFS_2k          ground-truth log templates, used to measure parsing
                          accuracy against a published benchmark
  loghub HDFS_v1          11,175,629 lines with 575,061 block-level anomaly
                          labels — the canonical log anomaly detection benchmark
"""

import argparse
import hashlib
import ssl
import sys
import urllib.request
import zipfile
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data" / "datasets"

SAMPLES = {
    "HDFS_2k.log": "https://raw.githubusercontent.com/logpai/loghub/master/HDFS/HDFS_2k.log",
    "HDFS_2k.log_structured.csv": (
        "https://raw.githubusercontent.com/logpai/loghub/master/HDFS/HDFS_2k.log_structured.csv"
    ),
    "OpenSSH_2k.log": (
        "https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log"
    ),
    "OpenSSH_2k.log_structured.csv": (
        "https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/"
        "OpenSSH_2k.log_structured.csv"
    ),
}

# Zenodo serves loghub from two records. 8196385 (loghub-2.0) has been
# returning 504 on the file endpoint; 3227177 is the original release and is the
# one actually reachable. Both are tried, in order.
HDFS_URLS = [
    ("HDFS_1.tar.gz", "https://zenodo.org/records/3227177/files/HDFS_1.tar.gz"),
    ("HDFS_v1.zip", "https://zenodo.org/records/8196385/files/HDFS_v1.zip"),
]


def _ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if ctx.cert_store_stats().get("x509_ca", 0):
        return ctx
    try:
        import certifi
    except ImportError:
        return ctx
    return ssl.create_default_context(cafile=certifi.where())


def _download(url: str, dest: Path, label: str) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        print(f"  ✓ {label} already present ({dest.stat().st_size / 1e6:.1f} MB)")
        return dest
    print(f"  ↓ {label} …", flush=True)
    req = urllib.request.Request(url, headers={"User-Agent": "Watchtower/0.3"})
    tmp = dest.with_suffix(dest.suffix + ".part")
    sha = hashlib.sha256()
    with urllib.request.urlopen(req, timeout=60, context=_ctx()) as r, open(tmp, "wb") as f:
        total = int(r.headers.get("Content-Length") or 0)
        done = 0
        while chunk := r.read(1 << 20):
            f.write(chunk)
            sha.update(chunk)
            done += len(chunk)
            if total:
                print(f"\r    {done / 1e6:7.1f} / {total / 1e6:.1f} MB", end="", flush=True)
    print()
    tmp.replace(dest)
    print(f"  ✓ {label}  sha256={sha.hexdigest()[:16]}…")
    return dest


def fetch_samples() -> None:
    print("loghub 2k samples (ground-truth templates):")
    for name, url in SAMPLES.items():
        _download(url, DATA / name, name)


def fetch_hdfs(delete_raw: bool = False) -> None:
    print("\nloghub HDFS_v1 (11.2M lines, 575k labelled blocks):")
    log = DATA / "HDFS.log"
    labels = DATA / "anomaly_label.csv"
    if log.exists() and labels.exists():
        print(f"  ✓ already extracted ({log.stat().st_size / 1e9:.2f} GB)")
        return

    archive = None
    for name, url in HDFS_URLS:
        try:
            archive = _download(url, DATA / name, name)
            break
        except Exception as exc:
            print(f"  ✗ {name}: {type(exc).__name__}: {exc}")
    if archive is None:
        raise SystemExit(
            "Could not fetch HDFS_v1 from any mirror. The 2k samples still work; "
            "detection metrics need this file."
        )

    print("  ⇪ extracting …", flush=True)
    wanted = ("HDFS.log", "anomaly_label.csv")
    if archive.suffixes[-2:] == [".tar", ".gz"] or archive.suffix == ".gz":
        import tarfile

        with tarfile.open(archive, "r:gz") as t:
            for member in t:
                base = Path(member.name).name
                if base in wanted:
                    with t.extractfile(member) as src, open(DATA / base, "wb") as dst:
                        while chunk := src.read(1 << 20):
                            dst.write(chunk)
                    print(f"    {base}: {(DATA / base).stat().st_size / 1e6:.0f} MB")
    else:
        with zipfile.ZipFile(archive) as z:
            for member in z.namelist():
                base = Path(member).name
                if base in wanted:
                    with z.open(member) as src, open(DATA / base, "wb") as dst:
                        while chunk := src.read(1 << 20):
                            dst.write(chunk)
                    print(f"    {base}: {(DATA / base).stat().st_size / 1e6:.0f} MB")
    if delete_raw:
        archive.unlink(missing_ok=True)
        print("  ✓ removed the archive")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Fetch benchmark datasets")
    ap.add_argument("--samples", action="store_true", help="2k samples only (~700 KB)")
    ap.add_argument("--hdfs", action="store_true", help="full HDFS_v1 (~186 MB -> 1.5 GB)")
    ap.add_argument("--delete-raw", action="store_true", help="remove the archive after extracting")
    args = ap.parse_args(argv)
    if not (args.samples or args.hdfs):
        args.samples = True
    if args.samples:
        fetch_samples()
    if args.hdfs:
        fetch_hdfs(args.delete_raw)
    print(f"\nData directory: {DATA}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
