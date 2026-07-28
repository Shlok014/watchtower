# Handoff — 2026-07-29

Where the rebuild stands, and exactly where to pick it up.

The governing rule, which has driven every decision so far: **no number is
reported unless it was measured, and anything not measured says so.** Several
changes below exist only because that rule forced them.

---

## Done

### Session 0 — genesis
`~/Documents/watchtower`, private repo `github.com/Shlok014/watchtower`.
Renamed from IRIS-SOC (it collided with the unrelated Sylox IRIS). Source-only
import, so the first commit never contained `node_modules`, `.venv`, the
examiner-facing docs, or — importantly — `frontend/public/favicon.svg` and
`icons.svg`, which were the **Bolt.new logo and a Bluesky icon**, unreferenced
leftovers that would have told any reviewer exactly how the project was made.

### Session 1 — every fabricated value replaced (merged, PR #1)
A 137-agent adversarial audit confirmed **63 findings across 41 locations, 35
fatal**, rejecting 68 others. Removed:

- `score + random.uniform(-0.04, 0.04)` under `# Randomness for realism`
- `confidence = 0.80 + score*0.15 + noise`, floored at 0.80 so it could never
  express doubt, displayed beside the score as if independent
- `/api/retrain` fabricating an accuracy that rose ~1% per click — now `501`
- `random.uniform` CPU and memory; six `random.randint` component latencies
- the decorative ledger nonce, which was never even an input to the digest

**IP reputation became real**: Tor Project bulk exit list + FireHOL level1,
cached with a provenance manifest, every verdict citing its feed and fetch date.

### Session 2 — SQLite (merged, PR #1)
Four module-level lists that a background thread mutated while Flask handlers
iterated them, with no lock. Now WAL-mode SQLite, one transaction per event.
`/api/stats` went **13.0 ms → 1.63 ms** (it had been re-parsing every timestamp
once per bucket, ~75,000 `fromisoformat` calls per request, every 2 seconds).

### Session 3 — tamper-evident ledger (merged, PR #2)
Verification previously compared `prev_hash` against the previous `hash` — two
strings in the same row — and never recomputed a digest from the data it claimed
to protect. Now every digest is recomputed from the live event row, with five
distinguished outcomes and a `cli ledger tamper` demo.

### Sessions 5–6 — real detection (this branch)
- `datasets/download.py` — loghub 2k samples and full HDFS_v1
- `detection/parser.py` — Drain3 with HDFS block-id masking
- `detection/features.py` — per-block template count vectors
- `eval/parsing.py`, `eval/benchmark.py` → `docs/METRICS.md`

**Completed on the full dataset** — 11,175,629 lines, 575,061 labelled blocks,
45 mined templates, 168.6s to parse and featurise (66,273 lines/sec):

| | Precision | Recall | F1 |
|---|---:|---:|---:|
| LogisticRegression | 0.9605 | 0.9998 | **0.9797** |
| DecisionTree | 0.9986 | 0.9987 | **0.9986** |
| IsolationForest (unsupervised) | 0.0774 | 0.0777 | **0.0775** |

Parsing grouping accuracy: HDFS_2k **0.9975**, OpenSSH_2k **0.7180**.

OpenSSH and IsolationForest are reported deliberately. Both are the unflattering
number, and a results table containing only its best figures is not a results
table.

---

## Pick up here

1. **Wire the trained model into a replay mode.** `detection/parser.py` has
   a `match()` that classifies without minting new templates — inference must
   use it, or an unseen line gets an id the model never trained on. The
   dashboard's detection stays a rule engine; replay is where the model belongs.
   Nothing currently persists a fitted model — add joblib serialisation when it
   is wired in, so `/api/retrain` can return genuine before/after metrics.
2. **Sessions 7–11** from the plan: real ingestion sources (syslog listener,
   file tailer, dataset replay), SOAR blocklist the pipeline actually enforces,
   the frontend split, CI, then the README/screenshots.

## Do not regress

- **`origin` is checked with `GLOB`, not `LIKE`.** SQLite's `LIKE` is ASCII
  case-insensitive, so `LIKE 'replay:%'` also accepts `REPLAY:` — two spellings
  of one provenance, and every `GROUP BY origin` under-counts.
- **The ledger digest covers `ts_ms`, not the ISO string.** Hashing ISO on write
  and reconstructing it from milliseconds on verify loses sub-millisecond
  precision and reports a clean chain as entirely tampered. That bug is
  invisible until verification actually recomputes something.
- **Detection windows key on `ingested_ts_ms`.** Keying on event time means a
  replayed 2008 dataset produces zero detections and a flat timeline while the
  ingest counter climbs — indistinguishable from a quiet network.
- **`auto_vacuum` must be set before the first `CREATE TABLE`.** Set afterwards
  it is silently ignored and the file then only ever grows.
- **Lifetime counters live in a table**, not `COUNT(*)`/`max(id)`, which fall
  when retention prunes.
- **FireHOL level1 contains RFC1918.** Address scope is classified *before* any
  feed lookup, using an explicit range table — not `ipaddress.is_private`, which
  CPython 3.13 changed for RFC 6598 space.
- **Unlisted addresses score 0.00.** Absence from a blocklist is not evidence.

## Open decisions

- **Ledger disk budget.** Append-only and exempt from retention: 838 bytes/block
  → ~48 MB/day at the generator's rate, ~1.7 GB/day at a 25 ev/s replay. Fine
  today; needs a policy before replay runs for any length of time.
- **Real Tor exit addresses in screenshots.** The generator uses real Tor exits
  for connection-provenance events and RFC 5737 documentation ranges for events
  that fabricate forensic detail, so no invented malware accusation is printed
  next to a real operator's address. Worth a second look before publishing
  screenshots.
- **The repo is still private.** The plan says go public once Sessions 0–6 and 9
  are done. 9 (the frontend split and error states) has not been started.

## Environment notes

- Python **3.14.1**, python.org framework build with **no CA bundle** — `urllib`
  raises `CERTIFICATE_VERIFY_FAILED` without `certifi`. Never "fixed" with
  `ssl._create_unverified_context`; for a tool that decides which addresses are
  hostile, letting someone swap the blocklist is worse than the fake table it
  replaced.
- numpy 2.5.1, scipy 1.18.0, scikit-learn 1.9.0, drain3 — all install cleanly on
  3.14, which was the plan's top risk.
- Zenodo record **8196385 returns 504**; record **3227177** works. The download
  script tries both.
- `backend/data/` (database, feeds, datasets) is git-ignored. Only the two
  ~700 KB loghub samples are fetched by default.
