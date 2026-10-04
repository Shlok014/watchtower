# Live Detection and Analyst Triage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add measured shadow anomaly scoring and a persistent owner-only analyst triage workflow to Watchtower.

**Architecture:** Keep rule-based alerting and SOAR status unchanged. Persist a separate shadow verdict per event and an append-only analyst history per alert. Train the shadow profile offline from explicitly normal scenarios; evaluate on disjoint synthetic scenarios and retain shadow mode unless a later independent evaluation supports promotion.

**Tech Stack:** Python, Flask, SQLite WAL, React, Vitest, pytest, scikit-learn where justified by measured comparison.

**Spec:** `docs/superpowers/specs/2026-10-04-live-detection-triage-design.md`

## Global Constraints

- No model training or network call inside the ingestion write transaction.
- No synthetic evaluation metric presented as production performance.
- All new mutations go through the existing owner-only access boundary.
- SOAR `status` keeps its existing meaning; analyst `review_status` is separate.
- Preserve migration and restart behavior for current SQLite databases.

## Review Focus

- A failed analyst transition leaves both alert state and history unchanged.
- Closing an alert does not remove a block or change SOAR status.
- An absent or corrupt shadow profile does not drop an event or create a model alert.
- Replayed old event timestamps do not alter ingestion-window scoring.
- A public read-only client cannot submit triage writes.

---

### Task 1: Triage persistence and API

**Files:** `backend/watchtower/store/schema.sql`, `backend/watchtower/store/migrations/003_alert_triage.sql`, `backend/watchtower/store/db.py`, `backend/watchtower/store/repos.py`, `backend/watchtower/api/routes.py`, `backend/tests/test_triage.py`.

**Interfaces:** `repos.transition_alert_review(conn, alert_id: int, target: str, note: str) -> dict`; `repos.alert_review_history(alert_id: int) -> list[dict]`; `POST /api/v1/alerts/<id>/review` receives `{status,note}`.

- [ ] Write tests for migration, valid/invalid transitions, restart, atomicity, and owner access; verify RED.
- [ ] Implement migration, repository operations, and API; verify GREEN and full backend suite.
- [ ] Commit.

### Task 2: Analyst dashboard

**Files:** `frontend/src/components/AlertsPanel.jsx`, `frontend/src/App.jsx`, `frontend/src/api/client.js`, `frontend/src/index.css`, frontend component/App tests.

**Interfaces:** alert rows include `review_status` and latest review; owner controls call the transition endpoint and refresh the snapshot.

- [ ] Write UI tests for state, note requirement, read-only display, and error handling; verify RED.
- [ ] Implement the panel and API client; verify GREEN, lint, build, and frontend suite.
- [ ] Commit.

### Task 3: Live shadow profile and persistence

**Files:** `backend/watchtower/detect/live_profile.py`, `backend/watchtower/pipeline/consumer.py`, store schema/migration/repository, model/status API, backend tests.

**Interfaces:** `live_profile.score(features) -> ShadowVerdict`; a disabled profile returns explicit unavailable metadata; persisted verdict references event id and profile digest.

- [ ] Write tests for feature extraction, profile identity, corrupt/missing profile, ingestion continuity, and restart; verify RED.
- [ ] Implement offline profile loading and shadow scoring outside the ingest write transaction; verify GREEN and full backend suite.
- [ ] Commit.

### Task 4: Reproducible evaluation and evidence

**Files:** `backend/eval/live.py`, `backend/tests/test_live_eval.py`, `docs/METRICS.md`, `README.md`.

**Interfaces:** deterministic train/validation/test scenarios with disjoint source/IP groups and explicit normal/attack labels; generated report includes denominators, precision, recall, FPR, misses, and profile digest.

- [ ] Write tests for split isolation, reproducibility, and metric denominators; verify RED.
- [ ] Implement evaluator and generate a report; verify GREEN and complete suite.
- [ ] Commit; request independent whole-branch review before PR.
