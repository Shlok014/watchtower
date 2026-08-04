"""The HTTP surface, versioned at ``/api/v1``.

Versioned because the shape of these responses is a contract the dashboard
depends on, and because two of them have already changed meaning during the
rebuild (``links_ok`` on the chain check, ``playbook_steps`` on SOAR). A client
pinned to a version can be told what changed; a client pinned to ``/api`` can
only discover it by rendering an empty cell.
"""

from flask import Blueprint, abort, jsonify, request

from .. import config, ledger, runtime, telemetry, threatintel
from ..detect import rules
from ..pipeline.consumer import process_log
from ..sources import synthetic
from ..store import db as store_db
from ..store import repos, retention_note

bp = Blueprint("api", __name__)


def query_int(name: str, default: int, lo: int, hi: int) -> int:
    """Bounded integer query param. ``?limit=abc`` used to raise and return 500."""
    raw = request.args.get(name)
    if raw in (None, ""):
        return default
    try:
        return max(lo, min(hi, int(raw)))
    except (TypeError, ValueError):
        abort(400, description=f"{name} must be an integer")


# ─── reads ────────────────────────────────────────────────────────────────────
@bp.route("/logs", methods=["GET"])
def get_logs():
    return jsonify(
        repos.recent_events(
            limit=query_int("limit", 100, 1, 1000),
            severity=request.args.get("severity") or None,
            source=request.args.get("source") or None,
            search=request.args.get("search") or None,
        )
    )


@bp.route("/alerts", methods=["GET"])
def get_alerts():
    return jsonify(repos.recent_alerts(query_int("limit", 50, 1, 500)))


@bp.route("/stats", methods=["GET"])
def get_stats():
    """Dashboard aggregates, computed in SQL.

    This used to loop over every retained log and every alert once per time
    bucket, calling datetime.fromisoformat each time — roughly 75,000 parses per
    request at a full buffer, measured at 13.0 ms of which 9.2 ms was parsing,
    repeated every 2 seconds.
    """
    st = repos.stats()
    totals, retained = st["totals"], st["retained"]
    return jsonify(
        {
            # Lifetime totals, from the persisted counters table. Returning a
            # row count here would make every "total" fall the moment retention
            # pruned an old event.
            "total_logs": totals["events"],
            "total_alerts": totals["alerts"],
            "total_blocks": totals["blocks"],
            "soar_actions_count": totals["soar"],
            # ...and what is currently on disk, under names that say so.
            "logs_retained": retained["events"],
            "alerts_retained": retained["alerts"],
            "blocks_retained": retained["blocks"],
            # Derived from the live policy, never a literal. Hardcoded, this
            # string would have gone on describing the in-memory ring buffers it
            # was written for — in the very field added to stop the app
            # misdescribing its own storage.
            "retention_note": retention_note(),
            "high_severity_alerts": st["high_severity_alerts"],
            "critical_alerts": st["critical_alerts"],
            "medium_severity_alerts": st["medium_severity_alerts"],
            "ruleset_version": rules.ruleset_version(),
            "logs_over_time": st["timeline"],
            "alert_distribution": st["alert_distribution"],
            "event_distribution": st["event_distribution"],
            "source_distribution": st["source_distribution"],
            "origin_distribution": st["origin_distribution"],
            "uptime_seconds": telemetry.uptime_seconds(),
            "sources": synthetic.SOURCES,
        }
    )


@bp.route("/blockchain", methods=["GET"])
def get_blockchain():
    return jsonify(repos.recent_blocks(query_int("limit", 30, 1, 500)))


@bp.route("/soar-actions", methods=["GET"])
def get_soar_actions():
    return jsonify(repos.recent_soar(query_int("limit", 30, 1, 500)))


@bp.route("/threat-intel", methods=["GET"])
def threat_intel_status():
    """Provenance for the reputation data: which feed, how many entries, how old."""
    idx = threatintel.get_index()
    return jsonify(
        {
            "usable": idx.usable,
            "feeds": [
                {
                    "name": s.name,
                    "state": s.state,
                    "entries": s.entries,
                    "fetched_at": s.fetched_at,
                    "age_hours": round(s.age_hours, 2) if s.age_hours is not None else None,
                    "citation": s.citation,
                    "homepage": s.homepage,
                    "error": s.error,
                }
                for s in idx.states.values()
            ],
            "demo_address_pool": {
                "addresses": list(synthetic.external_ips()),
                "note": synthetic.pool_note(),
            },
        }
    )


# ─── ledger ───────────────────────────────────────────────────────────────────
def validate_chain() -> dict:
    """Full verification: every digest recomputed from the live event rows."""
    result = ledger.verify(store_db.connect()).as_dict()
    count, oldest, newest = repos.ledger_bounds()
    result.update(
        {
            "chain_length": count,
            "latest_hash": newest,
            "genesis_hash": oldest,
            # Kept so the existing dashboard panel keeps rendering; it now means
            # "the whole chain verified", not "two stored strings matched".
            "links_ok": result["ok"],
        }
    )
    return result


@bp.route("/blockchain/validate", methods=["POST"])
def validate_blockchain():
    return jsonify(validate_chain())


# ─── writes ───────────────────────────────────────────────────────────────────
@bp.route("/simulate-attack", methods=["POST"])
def simulate_attack():
    """Trigger a simulated attack — supports multiple attack types."""
    attack_type = request.json.get("attack_type", "mixed") if request.is_json else "mixed"
    label, raws = synthetic.build_attack(attack_type)
    for raw in raws:
        process_log(raw)
    return jsonify(
        {
            "status": "success",
            "attack_type": attack_type,
            "label": label,
            "message": f"{label} triggered — {len(raws)} malicious events",
            "events_generated": len(raws),
        }
    )


@bp.route("/retrain", methods=["POST"])
def retrain_model():
    """Not implemented — there is no model wired into the live pipeline.

    This endpoint used to increment a counter and return ``previous_accuracy``,
    ``new_accuracy``, ``improvement`` and an ``epochs`` count, all synthesised
    from ``random.uniform`` so that accuracy climbed roughly 1% per button press
    and could never go down. Its own docstring read "Fake model retraining
    endpoint." The dashboard rendered the result as a toast reading "Model
    retrained on N samples — +1.31% improvement".

    Live detection is a rule set, versioned by the hash of its own weights. A
    trained model and a real evaluation against a labelled benchmark exist in
    ``eval/``; until one is wired into this process, this returns 501 rather
    than a number.
    """
    version = rules.ruleset_version()
    return jsonify(
        {
            "status": "not_implemented",
            "error": "No trainable model is wired into the live pipeline.",
            "detail": (
                f"Detection is a rule set versioned by content hash ({version}); "
                "changing it means editing the weights, not retraining. Accuracy "
                "figures will appear here once a model is trained and evaluated "
                "against a labelled dataset."
            ),
            "ruleset_version": version,
        }
    ), 501


@bp.route("/reset", methods=["POST"])
def reset_all():
    """Delete every stored row, and report what was actually deleted.

    Against the old in-memory lists this cleared four Python lists and unlinked
    a JSON file. Left unchanged against a database it would have deleted nothing
    while still returning "All data cleared" — an endpoint that says it removed
    everything and did not is exactly the class of statement this project exists
    to remove. The message is now built from real row counts.
    """
    with store_db.write() as conn:
        deleted = repos.reset_all(conn)
    store_db.checkpoint()
    telemetry.reset()
    total = sum(deleted.values())
    return jsonify(
        {
            "status": "success",
            "deleted": deleted,
            "message": (
                f"Deleted {total} rows — "
                f"{deleted['events']} events, {deleted['alerts']} alerts, "
                f"{deleted['ledger']} ledger blocks, "
                f"{deleted['soar_executions']} SOAR records"
            ),
        }
    )


# ─── health ───────────────────────────────────────────────────────────────────
def _component_health():
    """Per-stage health derived from measured state.

    Every ``status`` below is computed. The previous version returned the string
    literal "running" for all six components and a ``random.randint`` latency
    for each, so the panel reported a healthy system even with the generator
    thread dead and nothing being processed.
    """
    alive = runtime.any_alive()
    gen_status = "running" if alive else "stopped"
    c = repos.counters()
    retained = store_db.connect().execute("SELECT count(*) FROM events").fetchone()[0]
    feeds = threatintel.get_index()
    feed_ok = feeds.usable
    stale = any(s.state == threatintel.STALE for s in feeds.states.values())

    def stage(name, icon, stage_key, detail, status="running"):
        st = telemetry.stage_stats(stage_key)
        return {
            "name": name,
            "icon": icon,
            "status": status,
            "detail": detail,
            "p50_ms": st["p50_ms"],
            "p95_ms": st["p95_ms"],
            "samples": st["samples"],
        }

    return (
        [
            stage("Ingest Queue", "📡", "ingest", f"{c['events']} ingested", gen_status),
            stage("Normalization", "⚙️", "normalize", f"{retained} retained", gen_status),
            stage(
                "Detection Engine",
                "🧠",
                "detect",
                rules.ruleset_version() if feed_ok else "no threat feed",
                "running" if feed_ok else "degraded",
            ),
            stage("Alert System", "🚨", "alert", f"{c['alerts']} raised"),
            stage("SOAR Engine", "🤖", "alert", f"{c['soar']} playbooks selected", "simulated"),
            stage("Audit Ledger", "🔗", "ledger", f"{c['blocks']} blocks"),
        ],
        feed_ok,
        stale,
        alive,
    )


@bp.route("/system-health", methods=["GET"])
def system_health():
    """Measured process and pipeline health."""
    components, feed_ok, stale, alive = _component_health()

    if not alive:
        state, label = "down", "No source is running"
    elif not feed_ok:
        state, label = "degraded", "No threat feed cached — reputation unavailable"
    elif stale:
        state, label = "degraded", "Threat feed is stale"
    else:
        state, label = "ok", "All systems operational"

    payload = {
        "components": components,
        "summary": {"state": state, "label": label},
        "sources": runtime.status(),
        **telemetry.process_metrics(),
        "stages": telemetry.all_stage_stats(),
    }
    # Kept under its old name for the dashboard, but it is now a measured rate
    # over a rolling 60s window. It used to be len(logs)/uptime — a numerator
    # capped at 2000 over a denominator that grows forever, so it provably
    # decayed toward zero no matter how fast the pipeline was actually running.
    payload["logs_per_second"] = payload["events_per_second"]
    return jsonify(payload)


@bp.route("/pipeline-status", methods=["GET"])
def pipeline_status():
    components, _, _, _ = _component_health()
    return jsonify({"stages": components, "ruleset_version": rules.ruleset_version()})


@bp.route("/config", methods=["GET"])
def get_config():
    """What this process is actually configured to do.

    Exposed because "which database, which sources, what retention" is the first
    question anyone asks of a running instance, and reading it out of the
    environment is guesswork once the process has started.
    """
    cfg = config.get()
    return jsonify(
        {
            "database": str(cfg.db_path),
            "retention_hours": cfg.retention_hours,
            "alert_threshold": cfg.alert_threshold,
            "configured_sources": list(cfg.sources),
            "running_sources": runtime.status(),
            "cors_origins": list(cfg.cors_origins),
            "ruleset_version": rules.ruleset_version(),
        }
    )
