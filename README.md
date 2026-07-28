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
| Audit ledger | SHA-256 chain, monotonic block ids, no decorative nonce. Verification compares `prev_hash` links **only** — it does not recompute content hashes, so it cannot yet detect an edited log entry. | ⚠️ hash chain, **not yet tamper-evident** |
| Telemetry | Measured: per-stage p50/p95 via `perf_counter`, real RSS, real CPU, real 60s-window throughput, real uptime | ✅ real, measured |
| Persistence | Module-level ring buffers; only the ledger is written to JSON | ❌ resets on restart |
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
- [ ] SQLite persistence (WAL) replacing shared mutable lists
- [ ] Content-addressed hash chain with real tamper detection + a tamper demo
- [ ] Drain3 log parsing + a trained model measured on the HDFS_v1 benchmark
- [ ] Real ingestion sources: syslog listener, file tailer, dataset replay
- [ ] SOAR blocklist the pipeline actually enforces
- [ ] Tests + CI

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
