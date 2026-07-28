# Watchtower

**A security operations dashboard: log pipeline, rule-based detection with
feature-level explanations, real threat-feed IP reputation, response playbooks,
and a SHA-256 hash-chained audit ledger — Flask + React.**

> ### Read this first
>
> This started as a one-day college demo in which most of the infrastructure was
> faked. The "Kafka stream" was a Python list, the "AI engine" was weighted
> arithmetic with `random.uniform(-0.04, 0.04)` added under a comment reading
> `# Randomness for realism`, the retrain endpoint was docstringed
> `"""Fake model retraining endpoint."""` and invented an accuracy figure that
> rose ~1% per button press, and CPU and memory were `random.uniform()` draws.
>
> I am rebuilding it into the real thing, one layer at a time. The table below
> says exactly what is real *today* — a security tool that lies about its own
> capabilities would be an irony too far.

## What's real right now

| Component | Current implementation | Status |
|---|---|---|
| Log ingestion | In-process list; synthetic generator thread, 7 source profiles. Every event carries `origin: "synthetic"`. | ⚠️ synthetic input, honestly labelled |
| Normalization | Severity and event-type classification | ✅ real |
| **IP reputation** | Live lookup against the **Tor Project bulk exit list** (1,380 entries) and **FireHOL level1** (4,580 CIDRs), cached locally with a provenance manifest. Every verdict names its feed and fetch date. Non-routable addresses short-circuit before the lookup. | ✅ **real, measured** |
| Detection | Sliding-window features (failed logins/60s, event rate/30s) + reputation, weighted. Deterministic: identical input and window state give an identical score. Versioned by the hash of the weights themselves. | ✅ real rules — **not** ML, and not called ML |
| Alerting | Threshold 0.45, every alert carries the rules that fired and their evidence | ✅ real |
| SOAR | Playbook *selection* is real; steps are labelled `selected`, `executed: false`, and nothing is contacted | ⚠️ no integrations — and the UI says so |
| **Audit ledger** | **Tamper-evident.** Every digest is recomputed from the live event row on verify, and the header digest covers height, timestamp, prev_hash and payload — so editing an event, rewriting a block, back-dating one, or deleting one is all detected and distinguished. | ✅ **real** |
| Telemetry | Measured: per-stage p50/p95 via `perf_counter`, real RSS, real CPU, real 60s-window throughput, real uptime | ✅ real, measured |
| **Persistence** | **SQLite in WAL mode.** One transaction per event covers the row, its alert, its SOAR record and its ledger block. Survives restart. Events retained 24h unless an alert cites them; the ledger is append-only and exempt. | ✅ **real** |
| Dashboard | React + Chart.js, 2s polling, real connection gate | ✅ real |

Detection is a **rule engine**, deliberately. Three sliding-window features and a
weighted sum is what SIEM correlation rules actually are; the dishonest part was
never the rules, it was calling them "LogLM AI" and adding noise so the output
looked like a model.

## Threat intelligence

```bash
python -m threatintel.fetch            # refresh the feed cache
python -m threatintel.fetch --status   # report freshness, fetch nothing
```

Feeds are cached under `backend/data/feeds/` (git-ignored — the data is dated,
third-party, and FireHOL aggregates sources with their own terms) alongside a
manifest recording URL, fetch time, SHA-256 and entry count.

Two details worth knowing, both of which caused real bugs before they were fixed:

* **FireHOL level1 contains RFC1918.** It aggregates `fullbogons`, so
  `10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12` and the RFC 5737 documentation
  ranges are all in the file. A naive "in the netset → malicious" lookup flags
  every internal host in the demo. Address scope is therefore classified *before*
  any feed lookup.
* **Absence from a blocklist scores 0.00.** The previous code gave any
  unrecognised address 0.25 — a quarter of the way to the alert threshold on no
  evidence at all.

With no feeds cached the app still runs: reputation reports `unavailable` and
`checked: false`, and never guesses.

### Demo addresses

The generator draws external addresses from two pools, and the split is
deliberate. Connection-provenance events (`suspicious_ip`, `port_scan`,
`brute_force`) use **real addresses sampled from the cached Tor exit list**, so
the reputation path is genuinely exercised end to end. Events that fabricate
forensic detail — a made-up malware signature, an invented transfer volume — use
**RFC 5737 documentation ranges**, which belong to nobody. Printing an invented
malware accusation next to a real relay operator's address would be inventing
evidence about a real third party.

Naturally this makes the demo's Tor hits self-fulfilling. They demonstrate that
fetch, parse, CIDR matching and citation work end to end; they are not evidence
of detecting real attacks.

## Roadmap

- [x] Remove every fabricated value from scoring, telemetry and retraining
- [x] Real IP reputation from public threat feeds
- [x] SQLite persistence (WAL) replacing shared mutable lists
- [x] Content-addressed hash chain with real tamper detection + a tamper demo
- [ ] Drain3 log parsing + a trained model measured on the HDFS_v1 benchmark
- [ ] Real ingestion sources: syslog listener, file tailer, dataset replay
- [ ] SOAR blocklist the pipeline actually enforces
- [ ] Tests + CI

## Storage

State lives in `backend/data/watchtower.db` (SQLite, WAL). It replaced four
module-level Python lists that a background thread appended to and popped from
while Flask handlers iterated them, with no lock held — and a ledger written to
JSON on every twentieth block inside a bare `except Exception: pass`.

Measured on this machine (Python 3.14, macOS/arm64):

| | |
|---|---|
| Sustained writes | ~1,800 events/sec, 4 writer threads + a concurrent reader, zero `database is locked` |
| `/api/stats` | **1.6 ms**, down from 13.0 ms — the old version re-parsed every timestamp once per time bucket, ~75,000 `fromisoformat` calls per request, every 2 seconds |
| Ledger growth | 838 bytes/block → **~48 MB/day** at the generator's ~0.7 ev/s, ~1.7 GB/day at a 25 ev/s replay |

That last row is a real constraint, not a footnote: the ledger is append-only
and exempt from retention, because an audit ledger you silently truncate is not
an audit ledger. `auto_vacuum=INCREMENTAL` is set before the first table is
created — set afterwards it is silently ignored and the file then only ever
grows.

Two schema decisions worth calling out:

* **Events carry both `ts_ms` and `ingested_ts_ms`.** Detection windows and
  dashboard buckets key on ingest time. Keying them on event time would mean a
  replayed 2008 dataset produces zero detections and a flat-zero timeline while
  the ingest counter climbs — a silent failure that looks exactly like a quiet
  network.
* **`origin` is checked with `GLOB`, not `LIKE`.** SQLite's `LIKE` is ASCII
  case-insensitive, so `LIKE 'replay:%'` also accepts `REPLAY:` and `Replay:`,
  and two spellings of one provenance makes every `GROUP BY origin` under-count.

## The audit ledger

A single-writer hash chain — the data structure inside a blockchain, without the
consensus, because there is exactly one trusted writer. It is not distributed,
there is no proof-of-work, and it is not Hyperledger.

The previous version compared each block's `prev_hash` against its predecessor's
`hash` and nothing else. Both live in the same row, so it verified that two
stored strings matched — it never recomputed a digest from the data it claimed
to protect. Editing a log entry passed. It reported `blocks_checked: N` while
checking nothing about those blocks' contents.

Try it:

```bash
cd backend
.venv/bin/python -m cli ledger verify
# ✅ Chain verified — 26 blocks, every digest recomputed from the live event rows

.venv/bin/python -m cli ledger tamper --event-id 7 --field message --value "nothing happened here"
#   event 7.message
#     before: '[SYSLOG] admin accessed /etc/shadow from 192.168.1.30'
#     after:  'nothing happened here'

.venv/bin/python -m cli ledger verify
# ❌ TAMPER DETECTED — 1 finding(s) across 26 blocks.
#   height 7 (block 7): payload_mismatch
#     event 7 was modified after it was recorded (stored 3e43b48f0e26…, recomputed 3218805befed…)
```

`tamper` issues a raw SQL UPDATE that bypasses the application, which is the
only honest way to demonstrate the property — anything routed through the app
would re-chain the block and detect nothing.

Verification distinguishes five outcomes: `payload_mismatch` (the event was
edited), `header_mismatch` (the ledger row was edited), `chain_break`,
`height_gap` (a block was deleted), and `pruned` — an event removed by
retention, which is reported rather than treated as tampering.

One implementation note worth reading if you ever build one of these: the digest
covers `ts_ms`, the stored integer, not the ISO-8601 string. Hashing the ISO
form on write and reconstructing it from milliseconds on verify silently loses
sub-millisecond precision, and every block in the chain then reports as
tampered. That bug is completely invisible until verification actually
recomputes something — which is the whole point.

## Tests

```bash
cd backend && .venv/bin/python -m pytest
```

31 tests covering provenance constraints, concurrent writers against a live
reader, retention (including that an alert-referenced event is never pruned and
that lifetime counters do not fall when it runs), transaction rollback leaving a
usable connection, restart durability, and every ledger tamper mode — event
edits across four columns, forged block digests, deleted blocks, back-dating,
and 600 appends yielding 600 contiguous ids (the original code produced id 501
forever).

## Running it

```bash
cd backend
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m threatintel.fetch     # optional; app runs without it
.venv/bin/python app.py                   # :5001

cd ../frontend && npm install && npm run dev   # :5173
```

A one-command `make dev` replaces this shortly.

## License

MIT — see [LICENSE](LICENSE).
