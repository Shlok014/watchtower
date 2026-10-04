# Live detection and analyst triage design

## Goal

Make Watchtower a credible analyst-facing cybersecurity prototype: measure a second live-event anomaly signal without presenting it as validated production detection, and let an owner document the investigation and closure of an alert without rewriting what SOAR actually did.

## Boundaries

- The existing rule detector remains the only automatic alert trigger until a separate, reproducible promotion evaluation establishes acceptable false-positive and recall behavior. No silent model promotion.
- Shadow scores are explicitly named, versioned, and tied to an event. They never claim the HDFS complete-block F1 applies to live logs.
- Triage state is separate from `alerts.status`, which records SOAR action outcome. An analyst can mark an alert `new`, `investigating`, or `closed`, with a required note for closure. Reopening is allowed; history is append-only.
- Owner-only writes use the existing access boundary. Anonymous readers may see synthetic demo triage; non-demo log/alert access needs a separate read-protection decision before this becomes a public real-data system.
- The live profile is trained only from an explicitly selected normal baseline. An evaluation harness uses disjoint synthetic scenario sequences and reports precision, recall, false-positive rate, and examples of misses. These numbers are synthetic-scenario evidence, not production validity.

## Components

1. `detect/live_profile.py`: bounded feature vector from the live event window, persisted profile with source hash and version, and pure shadow scoring. No network calls or fitting in an ingest transaction.
2. `store` schema/repository: persist one shadow verdict per event and append-only analyst transitions, with an independent `review_status` field on alerts. Migration preserves existing alerts as `new`.
3. `pipeline.consumer`: calculate a shadow verdict after the rule result using the same ingested event; a missing or invalid profile produces an explicit unavailable state and never stops ingestion.
4. API/UI: read verdicts and triage history; owner-only transition endpoint. The dashboard labels rule detection, shadow model, and SOAR response distinctly.
5. `eval/live.py`: deterministic scenario split and measured gates. Promotion remains off by default; the report is regenerated from the harness.

## Failure behavior

- A corrupt or missing profile disables shadow scoring and reports why; rule alerts and ledger writes continue.
- Duplicate or invalid analyst transitions return 409/400 and create no history row.
- Alert closure never unblocks an IP or changes SOAR status.
- Reset removes triage and shadow records along with the demo data. A migration on an existing database keeps alerts and their SOAR histories intact.

## Verification

Test schema migration, transactionality, owner-only writes, restart durability, scoring provenance, corrupt-profile fail-closed behavior, deterministic evaluation, and dashboard permission states. Run the complete backend/frontend suites and lint/build before PR review.
