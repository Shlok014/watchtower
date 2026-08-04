#!/usr/bin/env bash
# Run the API and the dashboard together, and stop both cleanly.
#
# Two things this script is careful about, both learned the hard way.
#
# **It must run on bash 3.2.** macOS has shipped 3.2.57 since 2007 and will not
# ship a newer one, for licensing reasons. So `wait -n` — bash 4.3+, and the
# obvious way to say "return when either child exits" — fails outright with
# "wait: -n: invalid option", takes the trap with it, kills the backend and
# orphans the dashboard. `make dev` is the one command the README tells everyone
# to run, and it was broken for every Mac user. Found by cloning the repository
# and running the quickstart exactly as written.
#
# Two named PIDs and a poll loop replace it. bash 3.2 array handling under
# `set -u` is its own minefield, and there were only ever two children.
#
# **It does not kill whatever owns the port.** The script this replaces began
#
#     lsof -ti:5001 | xargs kill -9
#
# which shoots the occupant, not the thing this project started — on a Mac where
# 5001 is also AirPlay Receiver. This one reports who has the port and exits.
set -euo pipefail

cd "$(dirname "$0")/.."
PORT="${PORT:-5001}"
SOURCES="${SOURCES:-synthetic}"
PY="backend/.venv/bin/python"
# backend/ on the import path: the package is at backend/watchtower, and
# `python -m` only adds the current directory, which is the repository root.
export PYTHONPATH="$(pwd)/backend${PYTHONPATH:+:$PYTHONPATH}"

if [[ ! -x "$PY" ]]; then
  echo "No virtualenv at $PY — run 'make setup' first." >&2
  exit 1
fi

if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "Port $PORT is already in use by:" >&2
  lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >&2
  echo >&2
  echo "Stop it, or run with a different port:  PORT=5002 make dev" >&2
  exit 1
fi

backend_pid=""
frontend_pid=""

cleanup() {
  trap - INT TERM EXIT
  if [[ -n "$backend_pid" ]]; then kill "$backend_pid" 2>/dev/null || true; fi
  if [[ -n "$frontend_pid" ]]; then kill "$frontend_pid" 2>/dev/null || true; fi
  wait 2>/dev/null || true
  echo
  echo "Stopped."
}
trap cleanup INT TERM EXIT

echo "🛡️  backend  → http://localhost:$PORT/api/v1   (sources: $SOURCES)"
"$PY" -m watchtower run --port "$PORT" --sources "$SOURCES" &
backend_pid=$!

echo "📊 dashboard → http://localhost:5173"
(cd frontend && npm run dev) &
frontend_pid=$!

echo
echo "Ctrl-C stops both."

# Poll rather than `wait -n`. If either child exits — a crash, a port grab, a
# syntax error in a component — bring the other down too, instead of leaving
# half a stack running and looking healthy.
while true; do
  if ! kill -0 "$backend_pid" 2>/dev/null; then
    echo >&2
    echo "⚠️  The backend exited. Stopping the dashboard too." >&2
    exit 1
  fi
  if ! kill -0 "$frontend_pid" 2>/dev/null; then
    echo >&2
    echo "⚠️  The dashboard exited. Stopping the backend too." >&2
    exit 1
  fi
  sleep 1
done
