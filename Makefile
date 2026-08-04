# Watchtower — the single interface.
#
#   make help     what you can do
#   make setup    create both dependency trees
#   make dev      backend + dashboard
#   make test     everything
#
# Paths are relative to this file so `make` works from the repository root and
# nowhere else needs to know the layout.

SHELL   := /bin/bash
PY      := backend/.venv/bin/python
PIP     := backend/.venv/bin/pip
PORT    ?= 5001
SOURCES ?= synthetic

.DEFAULT_GOAL := help
.PHONY: help setup dev backend frontend test test-backend test-frontend lint \
        format bench feeds data verify demo clean clean-data

help:  ## Show this help
	@echo "Watchtower"
	@echo
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "  Variables: PORT=$(PORT) SOURCES=$(SOURCES)"

# ── setup ────────────────────────────────────────────────────────────────────
setup: $(PY) frontend/node_modules  ## Install backend and frontend dependencies
	@echo "✅ setup complete — run 'make dev'"

$(PY):
	python3 -m venv backend/.venv
	$(PIP) install --upgrade pip --quiet
	$(PIP) install -r backend/requirements.txt --quiet
	$(PIP) install pytest pytest-cov ruff --quiet

frontend/node_modules: frontend/package-lock.json
	cd frontend && npm ci
	@touch frontend/node_modules

# ── running ──────────────────────────────────────────────────────────────────
dev: setup  ## Run the API and the dashboard together
	@bash scripts/dev.sh

backend: $(PY)  ## Run the API only
	$(PY) -m watchtower run --port $(PORT) --sources $(SOURCES)

frontend: frontend/node_modules  ## Run the dashboard only
	cd frontend && npm run dev

# ── checks ───────────────────────────────────────────────────────────────────
test: test-backend test-frontend  ## Run every test

test-backend: $(PY)
	$(PY) -m pytest -q

test-frontend: frontend/node_modules
	cd frontend && npm run test

lint: $(PY) frontend/node_modules  ## Lint, format-check, and the honesty gate
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .
	$(PY) scripts/check_no_fabrication.py
	cd frontend && npm run lint

format: $(PY)  ## Apply formatting
	$(PY) -m ruff check --fix .
	$(PY) -m ruff format .

# ── data and measurement ─────────────────────────────────────────────────────
feeds: $(PY)  ## Refresh the cached threat-intelligence feeds
	$(PY) -m watchtower.threatintel.fetch

data: $(PY)  ## Download the full HDFS_v1 benchmark (~1.5 GB extracted)
	cd backend && ../$(PY) -m datasets.download --hdfs

bench: $(PY)  ## Regenerate docs/METRICS.md from a real run
	cd backend && ../$(PY) -m eval.benchmark
	@echo
	@echo "docs/METRICS.md regenerated. Every number in the README comes from here."

verify: $(PY)  ## Recompute every ledger digest
	$(PY) -m watchtower ledger verify

demo: $(PY)  ## The tamper demo: verify, corrupt one event, verify again
	@bash scripts/tamper_demo.sh

# ── cleaning ─────────────────────────────────────────────────────────────────
clean:  ## Remove build output and caches (keeps your data)
	rm -rf frontend/dist frontend/coverage .ruff_cache .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
	@echo "✅ cleaned"

clean-data:  ## Delete the database, models and feature cache. Not the samples.
	rm -rf backend/data/watchtower.db backend/data/watchtower.db-wal \
	       backend/data/watchtower.db-shm backend/data/models \
	       backend/data/processed backend/data/drain backend/data/incidents
	@echo "✅ runtime data removed (datasets, feeds and samples kept)"
