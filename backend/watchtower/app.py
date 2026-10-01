"""Application factory.

A factory rather than a module-level ``app = Flask(__name__)`` with a
``if __name__ == "__main__"`` block: the previous arrangement started the log
generator and set the uptime clock only under ``python app.py``, so under
``flask run``, gunicorn, a WSGI shim or a test client the generator never ran
and uptime read 0 forever. Every entry point now goes through ``create_app``.
"""

from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

from . import config, runtime, threatintel
from .api.routes import bp as api_bp
from .detect import stream
from .soar import playbooks
from .sources import synthetic
from .store import db as store_db

API_PREFIX = "/api/v1"
FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"


def create_app(cfg: config.Config | None = None, start_sources: bool = True) -> Flask:
    if cfg is not None:
        config.set_config(cfg)
    cfg = config.get()
    if cfg.public_demo and any(source != "synthetic" for source in cfg.sources):
        raise ValueError("Public demo only permits the synthetic source")

    app = Flask(__name__)

    # Not `CORS(app)`. Wide-open was the previous setting, on an unauthenticated
    # API that includes a destructive POST /reset — any page open in the browser
    # could have emptied the store.
    CORS(app, origins=list(cfg.cors_origins))

    app.register_blueprint(api_bp, url_prefix=API_PREFIX)

    if cfg.public_demo:
        @app.before_request
        def _public_demo_boundary():
            blocked = (
                ("POST", f"{API_PREFIX}/reset"),
                ("POST", f"{API_PREFIX}/retrain"),
            )
            if (request.method, request.path) in blocked or (
                request.method == "DELETE"
                and request.path.startswith(f"{API_PREFIX}/blocklist/")
            ):
                return jsonify({
                    "error": "public_demo_read_only",
                    "detail": "Operational changes are disabled on the shared public demo.",
                }), 403

    @app.get("/")
    def _frontend_index():
        if not (FRONTEND_DIST / "index.html").is_file():
            return jsonify({"error": "frontend_not_built"}), 503
        return send_from_directory(FRONTEND_DIST, "index.html")

    @app.get("/assets/<path:filename>")
    def _frontend_asset(filename: str):
        return send_from_directory(FRONTEND_DIST / "assets", filename)

    @app.get("/favicon.svg")
    def _frontend_favicon():
        return send_from_directory(FRONTEND_DIST, "favicon.svg")

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
