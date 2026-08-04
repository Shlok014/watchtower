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
| **Log ingestion** | Four sources through one pipeline: **UDP syslog** (RFC 3164 + 5424), **file tail** with inode rotation detection, **dataset replay** of real loghub logs, and the synthetic generator. Every event carries a mandatory `origin`, and the dashboard groups by it. | ✅ **real** — synthetic input still available, and labelled |
| Normalization | Severity and event-type classification | ✅ real |
| **IP reputation** | Live lookup against the **Tor Project bulk exit list** (1,380 entries) and **FireHOL level1** (4,580 CIDRs), cached locally with a provenance manifest. Every verdict names its feed and fetch date. Non-routable addresses short-circuit before the lookup. | ✅ **real, measured** |
| Detection (live dashboard) | Sliding-window features (failed logins/60s, event rate/30s) + reputation, weighted. Deterministic: identical input and window state give an identical score. Versioned by the hash of the weights themselves. | ✅ real rules — **not** ML, and not called ML |
| **Detection (model)** | **Drain3 template mining → per-block count vectors → scikit-learn**, measured on the full HDFS_v1 benchmark and persisted as a versioned artefact. `POST /api/v1/retrain` refits it and returns a real delta — 0.0000 on unchanged data. Live replay scores partial blocks and never borrows the benchmark's F1. | ✅ **real, measured, versioned** |
| Alerting | Threshold 0.45, every alert carries the rules that fired and their evidence | ✅ real |
| **SOAR** | **A closed loop.** YAML playbooks; `block_ip` writes to a blocklist the consumer checks *before* detection, so a blocked address really is suppressed and the drops are counted. Webhooks POST for real. Incident reports are real files citing the ledger blocks that cover their evidence. Alert status is earned: `contained` / `action_failed`, never assumed. | ✅ **real** — enforcement is at the ingestion layer, not a firewall |
| **Audit ledger** | **Tamper-evident.** Every digest is recomputed from the live event row on verify, and the header digest covers height, timestamp, prev_hash and payload — so editing an event, rewriting a block, back-dating one, or deleting one is all detected and distinguished. | ✅ **real** |
| Telemetry | Measured: per-stage p50/p95 via `perf_counter`, real RSS, real CPU, real 60s-window throughput, real uptime | ✅ real, measured |
| **Persistence** | **SQLite in WAL mode.** One transaction per event covers the row, its alert, its SOAR record and its ledger block. Survives restart. Events retained 24h unless an alert cites them; the ledger is append-only and exempt. | ✅ **real** |
| **Dashboard** | React + Chart.js. **LIVE / STALE / OFFLINE derived from the age of the last successful poll**, stale panels dimmed and labelled, an offline banner, and empty states that distinguish "no data" from "no backend". 16 components, an API client that throws on `!res.ok`, 36 Vitest tests. | ✅ **real** |

Detection is a **rule engine**, deliberately. Three sliding-window features and a
weighted sum is what SIEM correlation rules actually are; the dishonest part was
never the rules, it was calling them "LogLM AI" and adding noise so the output
looked like a model.

## Ingestion sources

Four of them, and every one goes through **the same** `process_log`. There is no
separate demo path, so nothing here can be true of the synthetic stream and
false of a real one. Every event carries a mandatory `origin`, which the
dashboard groups by — simulated traffic is *labelled*, not hidden.

```bash
python -m watchtower run --sources synthetic,syslog,file:/var/log/system.log,replay:hdfs@25
```

| Spec | What it is |
|---|---|
| `synthetic` | The generator. Real randomness, producing input data, labelled `origin: synthetic` |
| `syslog[:port]` | UDP listener, RFC 3164 and RFC 5424, default port **5514** |
| `file:<path>` | `tail -F` with inode-based rotation detection |
| `replay:<hdfs\|openssh>[@rate]` | Streams a real loghub dataset through the live pipeline |

**Replay is the one that matters.** A 2008 HDFS line keeps its 2008 timestamp in
`ts_ms`; `ingested_ts_ms` is when this process saw it. Detection windows and the
dashboard timeline key on ingest time — key them on event time instead and a
replay produces zero detections and a flat timeline while the ingest counter
climbs, which is silent and indistinguishable from a quiet network.

It also stays honest about what the data is. **HDFS is a filesystem log; nothing
in it is an attack.** Lines keep their own level (INFO/WARN/ERROR) and that is
all the severity they get. Mapping "WARN" onto "suspicious_ip" would manufacture
a threat judgement the data never made. Replay demonstrates that real volume
flows through real code — any alert it raises comes from the correlation windows
on real addresses, never from a lookup table of scary words. Measured on this
machine: 167 replayed events, 0 alerts, 0 fabricated threats.

OpenSSH replay is different, and the difference is the point: an sshd log
genuinely *is* an authentication log, so `Failed password for invalid user` is
matched literally and becomes `failed_login`. Nothing is inferred beyond the
message the daemon emitted about itself.

Two details in the syslog listener worth the thirty seconds:

* **The address comes from the socket, not the message.** RFC 3164's HOSTNAME is
  whatever the sender wrote, and forwarders rewrite it routinely. The peer
  address is the one thing about a datagram the sender could not simply assert,
  so that is what correlation keys on. The claimed hostname is kept as `source`,
  and not trusted as an address.
* **Port 5514, not 514,** because 514 needs root and a tool that asks for root
  to accept a datagram has made a bad trade. Note that `logger -n host -P port`
  is util-linux and **the BSD `logger` macOS ships rejects it**. Portable:

```bash
printf '<34>Aug  4 21:00:10 fw sshd[99]: Failed password for root from 198.51.100.4\n' \
  | nc -u -w1 127.0.0.1 5514
```

The file tailer attributes a line to an address found in the message, or to
`127.0.0.1` — the line did come from this host. That has a consequence worth
stating rather than hiding: the 30-second frequency rule counts per address, so
a busy system log will trip it on loopback. That is the rule doing exactly what
it says, and it is why real deployments scope rate rules by source type as well.

The loghub **2k samples are committed** (~1.2 MB), so replay and the
parsing-accuracy eval both run on a clean clone with nothing downloaded.

## Response, and what "enforced" means here

Playbooks are YAML in [`backend/playbooks/`](backend/playbooks) — trigger,
priority, and an ordered list of actions each marked `required` or not.
Detection-to-response policy is configuration, not a dict in a Python file.

```yaml
name: Brute force containment
trigger: brute_force
priority: P1
actions:
  - action: block_ip
    required: true
    ttl_seconds: 3600
  - action: incident_report
    required: true
  - action: webhook
    required: false      # nothing is configured by default, and a missing
                         # notifier must not make containment "fail"
```

### The closed loop

`block_ip` writes to a `blocklist` table. The pipeline consumer checks that
table **before detection runs**, marks matching events `dropped=1`, and counts
the hit against the block that caused it. Measured on a live instance:

```
$ curl -X POST localhost:5001/api/v1/simulate-attack -d '{"attack_type":"brute_force"}'
  Brute Force Attack triggered — 12 malicious events

$ curl localhost:5001/api/v1/blocklist
  192.0.2.45   repeated authentication failures   dropped=10   ttl=3598s
  totals: {active_blocks: 1, events_dropped_lifetime: 10}
```

Twelve events arrived, one alerted, the address was blocked, and the remaining
ten were **really discarded** before the detector saw them. That is a detect →
respond → enforce → observe loop with nothing simulated in the middle, and
`test_blocked_address_produces_no_further_alerts` fails if any link breaks.

Checked before detection, deliberately: running the rules first and throwing the
verdict away would keep the alert count climbing for an address that is supposed
to be silenced — the "we blocked it" / "then why is it still alerting"
contradiction.

### Scope, stated rather than implied

**Nothing here touches pf, iptables, or any firewall, and nothing needs root.**
Enforcement is at this application's own ingestion layer. *"Real firewall
integration would need pfctl and root; I scoped enforcement to the pipeline"* is
a defensible decision. A `pfctl` wrapper nobody dares demo is not.

The other actions are equally literal:

* **`webhook`** — a real `POST` with a 3-second timeout. Connection refused is
  recorded `failed`, not swallowed: a notifier that silently drops alerts is
  worse than no notifier, because the operator believes someone was told. With
  no `WATCHTOWER_WEBHOOK_URL` set it reports **`skipped`** — "nothing is
  configured" and "it was tried and broke" are different facts.
* **`incident_report`** — writes a real `INC-<date>-<seq>.md` and `.json` with
  the evidence event ids **and the ledger blocks covering them**, so the report
  points at something whose integrity can be independently checked. It also says
  in its own text that it is a record, not a remediation.
* The `malware_detected` playbook deliberately contains **no** `block_ip`. This
  process cannot isolate a host, so it records the incident and says the rest
  was not executed, rather than blocking an address as a substitute for the
  response it could not run.

### Status is earned

| Status | Means |
|---|---|
| `open` | raised; nothing has run |
| `contained` | every required step succeeded **and one had a real side effect** |
| `action_failed` | a required step failed — the alert stays visible |

What this replaced set `alert["status"] = "mitigated"` on the line after
selecting a playbook. Selecting only built a dict, so **every alert in the
system claimed to have been remediated the instant it was raised**, with a green
tick beside each one.

A playbook of `notify` and `webhook` can never reach `contained`. It has told
somebody; it has not fixed anything.

### The ledger covers the enforcement record

`dropped` is inside the payload digest, so flipping it `1 → 0` with raw SQL is
detected. In a system whose claim is that enforcement is real, which traffic was
suppressed is exactly the field worth protecting.

That addition required a second canonicalisation version. Each block records the
serialisation it was written under and is verified with **that one** — otherwise
adding a single field retroactively accuses every historical block of tampering,
and a false alarm is indistinguishable in the output from a real one. Both cases
are tested, along with a block naming a canon this build cannot reproduce, which
reports that it can neither confirm nor refute the digest rather than guessing.

## Threat intelligence

```bash
python -m watchtower.threatintel.fetch            # refresh the feed cache
python -m watchtower.threatintel.fetch --status   # report freshness, fetch nothing
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
- [x] Drain3 log parsing + a trained model measured on the HDFS_v1 benchmark
- [ ] Wire the trained model into a dataset-replay mode
- [ ] Real ingestion sources: syslog listener, file tailer, dataset replay
- [ ] SOAR blocklist the pipeline actually enforces
- [ ] Tests + CI

## Measured results

Full numbers, and how to reproduce them: **[docs/METRICS.md](docs/METRICS.md)**.
Every figure there is emitted by `python -m eval.benchmark`; none is typed by
hand.

**Log parsing** — grouping accuracy against loghub's ground-truth templates:

| Dataset | True templates | Mined | Grouping accuracy |
|---|---:|---:|---:|
| HDFS_2k | 14 | 16 | **0.9975** |
| OpenSSH_2k | 27 | 23 | **0.7180** |

**Anomaly detection** — loghub HDFS_v1, all 11,175,629 lines, 575,061 labelled
blocks (2.93% anomalous), 45 mined templates, stratified 50/50 split at seed 42:

| Model | Supervised | Precision | Recall | F1 | ROC-AUC |
|---|---|---:|---:|---:|---:|
| LogisticRegression | yes | 0.9605 | 0.9998 | **0.9797** | 0.9994 |
| DecisionTree | yes | 0.9986 | 0.9987 | **0.9986** | 0.9996 |
| IsolationForest | no | 0.0639 | 0.0640 | **0.0640** | 0.7014 |

Pipeline throughput: **103,181 lines/sec** end to end (108.3s to parse and
featurise 11.2M lines).

Three things worth saying plainly rather than letting the table imply otherwise:

* **HDFS is a near-separable benchmark.** F1 above 0.95 on template count
  vectors is the expected result here and matches published loglizer baselines.
  It is not evidence of anything novel in this repo.
* **The unsupervised row is bad, and it is the honest one.** IsolationForest gets
  0.0640 — that is the real cost of having no labels, which is exactly the
  situation the live dashboard is in.
* **These results are about HDFS, not the dashboard.** The live stream is
  synthetic and its detection is a rule engine. The two are deliberately
  separate and neither page claims otherwise.

Both the OpenSSH row and the IsolationForest row could have been quietly
omitted. They are here because a results table that only contains its best
numbers is not a results table.

### The model is a versioned artefact, not a script output

The LogisticRegression row is a real file on disk, and `POST /api/v1/retrain`
refits it, evaluates it on the same frozen held-out half, and returns what
changed. Each version records its seed, its split indices, its sklearn version,
its parameters, and a SHA-256 of the exact feature matrix it saw.

```
$ curl -X POST localhost:5001/api/v1/retrain
  version: 2      fit_seconds: 1.106      total_seconds: 1.87
  metrics:      f1 0.9797  precision 0.9605  recall 0.9998
  prev_metrics: f1 0.9797  precision 0.9605  recall 0.9998
  delta_f1: 0.0
```

**`delta_f1: 0.0`** is the point. Retraining on unchanged data changes nothing,
and the endpoint says so. What it replaced returned
`0.90 + (version - 2) * 0.01 + random.uniform(0, 0.02)` — an accuracy that rose
about a point per button press and could never fall — under a docstring reading
`"""Fake model retraining endpoint."""`.

Retraining takes under two seconds against 575,061 blocks because the feature
matrix is cached alongside the template ids that define its columns. The two are
meaningless apart: re-parsing would re-mine the templates, and the column space
would shift underneath two models that are supposed to be comparable.

### The model in the live pipeline

`--sources replay:hdfs` scores blocks as their lines arrive, using
`parser.match()` — never `parse()`, which would mint a template for an unseen
line and hand the model a column index that means nothing.

**The published F1 does not transfer to those scores, and `/api/v1/model` says
so on every verdict it returns.** It was measured on complete blocks; scoring a
block that is three lines old is the same model answering a harder question. So
that endpoint reports a probability, the number of lines behind it, the observed
min/median/max of recent scores, and how many lines matched no template at all —
a rising unmatched rate being the honest signal that the miner has drifted. No
accuracy is claimed for live scoring anywhere.

## The dashboard, and what it refuses to imply

The frontend was where the original demo lied most loudly, and the fixes are
the same shape as the backend's.

**The boot screen is gone.** It was a six-stage animation — "Initializing Kafka
stream…", "Syncing blockchain ledger…" — that ticked each line to a green
checkmark on a 400 ms timer without ever contacting the backend. It reported six
subsystems healthy before a single request had been made, and played the
identical sequence with the server switched off. What replaces it reflects
exactly one thing: whether a real request to a real endpoint came back.

**The header said `LIVE`. Always.** It now reads LIVE, STALE or OFFLINE, derived
from the age of the last *successful* poll — including a separate one-second
clock, so it degrades on its own while every request is failing rather than
freezing on whatever it last rendered. Stale panels are dimmed and labelled;
an offline banner says in words that what is on screen is the last data
received, not the current state.

**The API client used to swallow everything:**

```js
const fetchJSON = async (url, opts) => {
  try { const r = await fetch(url, opts); return await r.json() } catch { return null }
}
```

It never checked `res.ok`, so a 500 with a JSON body rendered as data; a 404's
HTML body threw inside `.json()` and came back as `null`, which every caller
read as "no data yet". Both failures looked exactly like a quiet system. The
client now distinguishes *nothing answered* from *the backend said no*, carries
the backend's own `detail` into the UI, and refuses a 200 that is not JSON.

**Empty states say which thing is true.** "No logs ingested yet" and "No logs
match these filters" were one message that also covered a dead backend.

**Polling no longer churns.** The interval was torn down and recreated on every
search keystroke, because `fetchAll` depended on `search`. Filters now live in a
ref; the timer is created once, and a slow backend cannot queue polls behind
itself.

`App.jsx` went from 662 lines holding ten components to 16 components,
`src/api/client.js` and `src/hooks/usePolling.js`. `VITE_API_URL` replaces the
hardcoded localhost URL — the production bundle could previously only ever talk
to the machine it was built on.

No TypeScript, deliberately. A day of migration churn on an API-thin dashboard
versus tests, error handling and honest states for the same day; a half-migrated
`any`-riddled codebase is worse signal than clean JSX. JSDoc typedefs on the API
client instead, and "TypeScript migration" stays on the roadmap unchecked.

## Storage

State lives in `backend/data/watchtower.db` (SQLite, WAL). It replaced four
module-level Python lists that a background thread appended to and popped from
while Flask handlers iterated them, with no lock held — and a ledger written to
JSON on every twentieth block inside a bare `except Exception: pass`.

Measured on this machine (Python 3.14, macOS/arm64):

| | |
|---|---|
| Sustained writes | ~1,800 events/sec, 4 writer threads + a concurrent reader, zero `database is locked` |
| `/api/v1/stats` | **1.6 ms**, down from 13.0 ms — the old version re-parsed every timestamp once per time bucket, ~75,000 `fromisoformat` calls per request, every 2 seconds |
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
.venv/bin/python -m watchtower ledger verify
# ✅ Chain verified — 26 blocks, every digest recomputed from the live event rows

.venv/bin/python -m watchtower ledger tamper --event-id 7 --field message --value "nothing happened here"
#   event 7.message
#     before: '[SYSLOG] admin accessed /etc/shadow from 192.168.1.30'
#     after:  'nothing happened here'

.venv/bin/python -m watchtower ledger verify
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
cd backend  && .venv/bin/python -m pytest    # 128
cd frontend && npm test                      # 36
```

128 tests covering the HTTP contract, the four ingestion sources (including a real
UDP datagram end to end, and a tailer surviving both rotation and in-place
truncation), the SOAR closed loop (blocked address → zero further alerts, N real
drops), playbook validation, a webhook against a real HTTP server and a closed
port, model versioning and the zero-delta retrain, bounded live block scoring,
provenance constraints, concurrent writers against a live
reader, retention (including that an alert-referenced event is never pruned and
that lifetime counters do not fall when it runs), transaction rollback leaving a
usable connection, restart durability, and every ledger tamper mode — event
edits across four columns, forged block digests, deleted blocks, back-dating,
and 600 appends yielding 600 contiguous ids (the original code produced id 501
forever).

## Running it

```bash
make setup     # both dependency trees
make dev       # API on :5001, dashboard on :5173
```

`make help` lists everything. The ones worth knowing:

| | |
|---|---|
| `make test` | 128 backend + 36 frontend |
| `make lint` | ruff, eslint, and the honesty gate |
| `make bench` | regenerate `docs/METRICS.md` from a real run |
| `make demo` | verify the ledger, corrupt one event with raw SQL, verify again |
| `make feeds` | refresh the cached threat feeds |
| `make data` | download the full HDFS_v1 benchmark (~1.5 GB extracted) |

`SOURCES=synthetic,syslog,replay:hdfs@25 make dev` picks the ingestion sources.

`scripts/dev.sh` replaces the old `start.sh`, whose first line was
`lsof -ti:5001 | xargs kill -9` — that kills whatever owns the port, not what
this project started, on a Mac where 5001 is also AirPlay Receiver. The
replacement only ever signals the two children it launched, and fails by name if
the port is taken.

**A clean clone needs no downloads.** The loghub 2k samples and their labels are
committed, so `make test`, `make bench`'s parsing section, and `replay:hdfs` all
work immediately.

## Layout

```
backend/
  watchtower/          the application package
    config.py          every WATCHTOWER_* setting, resolved once
    app.py             create_app() factory
    api/routes.py      the HTTP surface, at /api/v1
    pipeline/          normalize.py, consumer.py — one path for every source
    detect/            rules.py (live), parser.py + features.py (benchmark)
    sources/           base.py, synthetic.py
    soar/engine.py     playbook selection
    ledger/chain.py    the tamper-evident audit chain
    store/             db.py, repos.py, schema.sql
    telemetry/         measured, never invented
    threatintel/       cached public feeds + provenance
  eval/                benchmarks; writes docs/METRICS.md
  datasets/            loghub download
  tests/
```

The API is versioned at `/api/v1` and there is no unversioned alias. Two of
these responses have already changed meaning during the rebuild — `links_ok` on
the chain check, `playbook_steps` on SOAR — and a client pinned to `/api` can
only discover that by rendering an empty cell, since every field the dashboard
reads is optional-chained.

## Configuration

Everything is an environment variable with a working default, so the app runs
with none of them set. `python -m watchtower config` prints what a process
resolved, and `GET /api/v1/config` reports it from a running one.

| Variable | Default | |
|---|---|---|
| `WATCHTOWER_DATA_DIR` | `backend/data` | database, feed cache, drain state |
| `WATCHTOWER_DB` | `<data>/watchtower.db` | |
| `WATCHTOWER_RETENTION_HOURS` | `24` | events only; the ledger is exempt |
| `WATCHTOWER_ALERT_THRESHOLD` | `0.45` | changing it changes `ruleset_version` |
| `WATCHTOWER_SOURCES` | `synthetic` | comma-separated |
| `WATCHTOWER_CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | |
| `WATCHTOWER_HOST` / `WATCHTOWER_PORT` | `127.0.0.1` / `5001` | |

Two of those defaults are deliberate changes from what the demo shipped with.
CORS was `CORS(app)` — any origin — on an unauthenticated API that includes a
destructive `POST /reset`, so any page open in the browser could have emptied
the store. And the server bound `0.0.0.0`, publishing that same API to every
machine on the network the moment the demo ran on café wifi.

## License

MIT — see [LICENSE](LICENSE).
