"""Application factory.

A factory rather than a module-level ``app = Flask(__name__)`` with a
``if __name__ == "__main__"`` block: the previous arrangement started the log
generator and set the uptime clock only under ``python app.py``, so under
``flask run``, gunicorn, a WSGI shim or a test client the generator never ran
and uptime read 0 forever. Every entry point now goes through ``create_app``.
"""

from flask import Flask, jsonify, request
from flask_cors import CORS

from . import access, config, runtime, threatintel
from .api.routes import bp as api_bp
from .detect import live_shadow, stream
from .soar import playbooks
from .sources import synthetic
from .store import db as store_db

API_PREFIX = "/api/v1"


def create_app(cfg: config.Config | None = None, start_sources: bool = True) -> Flask:
    if cfg is not None:
        config.set_config(cfg)
    cfg = config.get()

    app = Flask(__name__)
    app.config["TRUSTED_HOSTS"] = list(cfg.trusted_hosts)

    # CORS is for response access. The request-provenance guard below protects
    # the write itself, including a plain cross-site HTML form POST.
    CORS(app, origins=list(cfg.cors_origins))

    @app.before_request
    def _protect_unsafe_requests():
        # CORS only limits who can read a response. A cross-site HTML form can
        # still submit POST /reset, /retrain, or /simulate-attack and the route
        # would run. Check browser provenance before any write reaches a view.
        if request.method in {"GET", "HEAD", "OPTIONS"}:
            return None
        origin = request.headers.get("Origin")
        allowed = {*cfg.cors_origins, request.host_url.rstrip("/")}
        if (origin and origin not in allowed) or (
            not origin and request.headers.get("Sec-Fetch-Site") == "cross-site"
        ):
            return jsonify({"error": "cross_site_write_forbidden"}), 403
        # Ledger validation computes a read-only verdict despite its legacy POST
        # route. Every actual state-changing endpoint needs owner access.
        if request.path == f"{API_PREFIX}/blockchain/validate" and request.method == "POST":
            return None
        if not access.can_write(cfg, request):
            return jsonify({"error": "write_forbidden"}), 403
        return None

    app.register_blueprint(api_bp, url_prefix=API_PREFIX)

    @app.errorhandler(400)
    def _bad_request(err):
        return jsonify({"error": "bad_request", "detail": getattr(err, "description", "")}), 400

    @app.errorhandler(404)
    def _not_found(err):
        return jsonify(
            {"error": "not_found", "detail": f"no route for this path ({API_PREFIX})"}
        ), 404

    @app.errorhandler(500)
    def _server_error(err):  # pragma: no cover - defensive
        return jsonify({"error": "internal_error"}), 500

    store_db.connect()  # creates/validates the schema once

    # Load and validate the response playbooks NOW, so a typo in a YAML file is
    # a refusal to start rather than a surprise at 3am. Before this the first
    # alerting event discovered the problem, from inside the ingest
    # transaction, and took the event down with it.
    playbooks.all_playbooks(reload=True)

    synthetic.refresh_ip_pools()
    # Load the newest trained model if there is one. Absence is normal on a
    # clean clone and is reported through /api/v1/model rather than logged and
    # forgotten — "no model" and "a model that silently failed to load" have to
    # be distinguishable from outside the process.
    stream.enable()
    live_shadow.enable(cfg.models_dir)
    if start_sources:
        runtime.start(cfg.sources)
    return app


def startup_banner() -> str:
    cfg = config.get()
    idx = threatintel.get_index()
    from .detect import rules
    from .store import repos

    lines = [
        "\n🛡️  Watchtower backend starting...",
        f"📥 Sources: {', '.join(cfg.sources) or 'none'}",
        f"🧠 Detection engine loaded — rule-based, {rules.ruleset_version()}",
    ]
    for st in idx.states.values():
        if st.state == threatintel.MISSING:
            lines.append(f"⚠️  Threat feed '{st.name}' unavailable — {st.error}")
        else:
            lines.append(f"🌐 {st.citation}: {st.entries} entries ({st.state})")
    if not idx.usable:
        lines.append("   IP reputation will report 'unavailable' rather than guessing.")
        lines.append("   Fetch feeds with: python -m watchtower.threatintel.fetch")
    c = repos.counters()
    lines.append(f"💾 Store: {cfg.db_path} ({c['events']} events, {c['blocks']} blocks so far)")
    lines.append(f"🔎 Demo addresses: {synthetic.pool_note()}")
    lines.append(f"🔗 API: http://{cfg.host}:{cfg.port}{API_PREFIX}\n")
    return "\n".join(lines)
