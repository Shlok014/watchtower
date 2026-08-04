#!/usr/bin/env bash
# Run the API and the dashboard together, and stop both cleanly.
#
# The script this replaces began:
#
#     lsof -ti:5001 | xargs kill -9
#
# which kills whatever owns the port, not what this project started — including
# somebody else's database, on a machine where 5001 is also AirPlay Receiver.
# This one only ever signals the two children it launched itself.
set -euo pipefail

cd "$(dirname "$0")/.."
PORT="${PORT:-5001}"
SOURCES="${SOURCES:-synthetic}"
PY="backend/.venv/bin/python"

if [[ ! -x "$PY" ]]; then
  echo "No virtualenv at $PY — run 'make setup' first." >&2
  exit 1
fi

# Fail fast and by name if the port is taken, rather than killing the occupant.
if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "Port $PORT is already in use by:" >&2
  lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >&2
  echo >&2
  echo "Stop it, or run with a different port:  PORT=5002 make dev" >&2
  exit 1
fi

pids=()
cleanup() {
  trap - INT TERM EXIT
  for pid in "${pids[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  echo
  echo "Stopped."
}
trap cleanup INT TERM EXIT

echo "🛡️  backend  → http://localhost:$PORT/api/v1   (sources: $SOURCES)"
"$PY" -m watchtower run --port "$PORT" --sources "$SOURCES" &
pids+=($!)

echo "📊 dashboard → http://localhost:5173"
(cd frontend && npm run dev) &
pids+=($!)

wait -n
