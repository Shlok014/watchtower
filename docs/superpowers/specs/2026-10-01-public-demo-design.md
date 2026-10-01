# Watchtower public portfolio demo

## Goal

Provide one public URL for the React dashboard and its Flask API. Visitors should
see actual synthetic ingestion, alerts, ledger verification, and application-layer
blocking. All generated traffic must be visibly labelled synthetic. The hosted
instance is a shared, disposable demonstration, not a security operations service.

## Host

Use one Render free web service with a multi-stage Docker build. Build React with
`VITE_API_URL=/api/v1`, then serve its static bundle from Flask alongside the API.
Use one Gunicorn worker because the runtime source and SQLite store are process-local.
The service must honor Render's `PORT` environment variable and store runtime data
outside the source tree. Free Render storage disappears on restart or idle spin-down;
show that limitation in the UI and README.

## Public boundaries

An explicit `WATCHTOWER_PUBLIC_DEMO=1` setting permits only synthetic sources.
Public requests may read dashboard data, verify the ledger, and trigger one bounded
attack simulation per source address per minute. Disable reset, retrain, and unblock
on the public host. Keep webhook targets unset; the public image ships no secrets.
The demo must report unavailable feed or model state honestly. Do not advertise
long-term audit retention for the free host.

## Dashboard presentation

The visitor is a recruiter or security engineer checking whether the operations
workflow is real. The first view keeps the existing connection status, pipeline,
alerts, logs, and ledger. A compact notice beneath the header says the traffic
is synthetic, the database is shared and disposable, and the one available action
is a bounded attack simulation. Existing empty, stale, and offline states stay
visible. No new cards or visual language are needed.

Component tree: `App` → `Header` (attack menu, no reset on public host) →
`DemoNotice` → existing pipeline and evidence panels → `BlocklistPanel` (no
unblock on public host) and `ModelPanel` (no retrain on public host) → ledger.
The backend still rejects these writes even if someone calls the API directly.
The notice wraps on mobile; existing grid breakpoints handle the panel layout.

Risks and corrections: a fake-live dashboard is avoided by retaining the real
polling/connection gate; a misleading ML claim is avoided by leaving the model
panel's absence state; an overpromising ledger claim is avoided by the disposable
notice; dead buttons are removed; visual clutter is avoided with one text notice.

## Proof

Add route tests for denied mutation, bounded simulation, and static serving.
Run backend and frontend suites, build the Docker image, then smoke test the
public URL: loaded UI, live API, generated attack, dropped follow-up traffic,
and ledger verification. Confirm a restart resets the disposable store.
