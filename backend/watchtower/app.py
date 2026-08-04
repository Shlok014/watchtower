"""Application factory.

A factory rather than a module-level ``app = Flask(__name__)`` with a
``if __name__ == "__main__"`` block: the previous arrangement started the log
generator and set the uptime clock only under ``python app.py``, so under
``flask run``, gunicorn, a WSGI shim or a test client the generator never ran
and uptime read 0 forever. Every entry point now goes through ``create_app``.
"""

from flask import Flask, jsonify
from flask_cors import CORS

from . import config, runtime, threatintel
from .api.routes import bp as api_bp
from .sources import synthetic
from .store import db as store_db

API_PREFIX = "/api/v1"


def create_app(cfg: config.Config | None = None, start_sources: bool = True) -> Flask:
    if cfg is not None:
        config.set_config(cfg)
    cfg = config.get()

    app = Flask(__name__)

    # Not `CORS(app)`. Wide-open was the previous setting, on an unauthenticated
    # API that includes a destructive POST /reset — any page open in the browser
    # could have emptied the store.
    CORS(app, origins=list(cfg.cors_origins))

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
    synthetic.refresh_ip_pools()
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
