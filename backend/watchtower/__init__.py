"""Watchtower — a security operations pipeline that does not lie about itself.

Layout:

    config.py        every WATCHTOWER_* setting, resolved once
    app.py           create_app() factory
    api/routes.py    the HTTP surface, at /api/v1
    pipeline/        normalize.py, consumer.py  — one path for every source
    detect/          rules.py (live), parser.py + features.py (benchmark)
    sources/         base.py, synthetic.py
    soar/            engine.py
    ledger/          chain.py — the tamper-evident audit chain
    store/           db.py, repos.py, schema.sql
    telemetry/       metrics.py — measured, never invented
"""

__version__ = "0.4.0"
