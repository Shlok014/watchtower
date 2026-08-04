#!/usr/bin/env bash
# The thirty seconds that make the ledger claim believable.
#
# `tamper` issues a raw SQL UPDATE that bypasses the application entirely, which
# is the only honest way to demonstrate the property: anything routed through
# the app would re-chain the block and detect nothing.
set -uo pipefail
cd "$(dirname "$0")/.."
PY="backend/.venv/bin/python"
# backend/ on the import path: the package is at backend/watchtower, and
# `python -m` only adds the current directory, which is the repository root.
export PYTHONPATH="$(pwd)/backend${PYTHONPATH:+:$PYTHONPATH}"

echo "── 1. verify the chain as it stands ──────────────────────────────────────"
"$PY" -m watchtower ledger verify || true
echo

EVENT_ID="${1:-}"
if [[ -z "$EVENT_ID" ]]; then
  EVENT_ID=$("$PY" - <<'PYEOF'
from watchtower.store import db
row = db.connect().execute("SELECT id FROM events ORDER BY id DESC LIMIT 1").fetchone()
print(row["id"] if row else "")
PYEOF
)
fi

if [[ -z "$EVENT_ID" ]]; then
  echo "No events in the store yet. Run 'make dev' for a few seconds first." >&2
  exit 1
fi

echo "── 2. corrupt event $EVENT_ID with raw SQL ───────────────────────────────"
"$PY" -m watchtower ledger tamper --event-id "$EVENT_ID" --field message \
      --value "nothing happened here"
echo

echo "── 3. verify again ───────────────────────────────────────────────────────"
"$PY" -m watchtower ledger verify
echo
echo "Exit code above is 1, and the finding names the height, the event, and"
echo "both digests. Nothing about the block itself was touched."
