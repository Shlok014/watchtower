# Watchtower

**A security operations platform: streaming log pipeline, anomaly detection with
explainable alerts, automated response playbooks, and a tamper-evident audit
ledger — Flask + React.**

> ### Read this first
>
> This started life as a one-day college demo in which most of the infrastructure
> was faked — the "Kafka stream" was a Python list, the "AI engine" was weighted
> arithmetic with random noise added "for realism", and the "blockchain" was an
> array whose validation never actually recomputed a hash. I am rebuilding it
> into the real thing, one layer at a time.
>
> This commit is the honest baseline: the original demo, with the dead template
> assets removed and every component renamed to what it actually is. The table
> below tracks what is real today. It will keep changing.

## What's real right now

| Component | Current implementation | Status |
|---|---|---|
| Log ingestion | In-process list, synthetic generator thread (7 source profiles) | ⚠️ synthetic |
| Normalization | Severity + event-type classification, geo lookup | ✅ real |
| Detection | Sliding-window features (failed logins/60s, request rate/30s, IP reputation) + weighted rules | ⚠️ real features, but noise-injected score and a fake IP-reputation table |
| Alerting | Threshold at 0.45, feature-level explanations | ✅ real |
| SOAR | Playbook selection real; actions are strings with no side effects | ❌ no enforcement |
| Audit ledger | SHA-256 chain — but validation only checks links, never recomputes content hashes | ⚠️ not actually tamper-evident |
| Persistence | Module-level lists; only the ledger is written to JSON, every 20th block | ❌ resets on restart |
| Telemetry | CPU/RAM/latency are `random.uniform()` | ❌ fabricated |
| Dashboard | React + Chart.js, live polling | ✅ real (with a fake boot animation) |

## Roadmap

- [ ] Remove every fabricated value from scoring, telemetry and retraining
- [ ] SQLite persistence (WAL) replacing shared mutable lists
- [ ] Content-addressed hash chain with real tamper detection
- [ ] Drain3 log parsing + a trained model measured on the HDFS_v1 benchmark
- [ ] Real ingestion sources: syslog listener, file tailer, dataset replay
- [ ] SOAR blocklist that the pipeline actually enforces
- [ ] Tests + CI

## Running it

```bash
cd backend && pip install -r requirements.txt && python3 app.py   # :5001
cd frontend && npm install && npm run dev                          # :5173
```

A one-command `make dev` replaces this shortly.

## License

MIT — see [LICENSE](LICENSE).
