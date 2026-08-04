#!/usr/bin/env bash
# The thirty seconds that make the ledger claim believable.
#
# `tamper` issues a raw SQL UPDATE that bypasses the application entirely, which
# is the only honest way to demonstrate the property: anything routed through
# the app would re-chain the block and detect nothing.
#
# Step 4 puts the original value back. Without it the demo leaves the store
# permanently tampered, so the next `make verify` fails and a first-time user
# reasonably concludes something is broken. It also demonstrates something worth
# seeing: restoring the exact original bytes makes the chain verify again,
# because the digest covers the content and nothing else — no timestamp, no
# sequence number, nothing that would make the damage irreversible.
set -uo pipefail
cd "$(dirname "$0")/.."
PY="backend/.venv/bin/python"
# backend/ on the import path: the package is at backend/watchtower, and
# `python -m` only adds the current directory, which is the repository root.
export PYTHONPATH="$(pwd)/backend${PYTHONPATH:+:$PYTHONPATH}"

echo "── 1. verify the chain as it stands ──────────────────────────────────────"
if ! "$PY" -m watchtower ledger verify; then
  echo >&2
  echo "The chain is already broken, so there is nothing to demonstrate — a" >&2
  echo "second failure would prove nothing, and step 4 would 'restore' whatever" >&2
  echo "the previous tamper left behind. Reset with 'make clean-data' and run" >&2
  echo "'make dev' for a few seconds to build a fresh chain." >&2
  exit 1
fi
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

# Captured before the UPDATE, so step 4 can put back the exact bytes.
ORIGINAL=$("$PY" - "$EVENT_ID" <<'PYEOF'
import sys
from watchtower.store import db
row = db.connect().execute(
    "SELECT message FROM events WHERE id = ?", (int(sys.argv[1]),)
).fetchone()
print(row["message"] if row else "", end="")
PYEOF
)

if [[ -z "$ORIGINAL" ]]; then
  echo "Event $EVENT_ID has no message to restore; refusing to tamper." >&2
  exit 1
fi

echo "── 2. corrupt event $EVENT_ID with raw SQL ───────────────────────────────"
"$PY" -m watchtower ledger tamper --event-id "$EVENT_ID" --field message \
      --value "nothing happened here"
echo

echo "── 3. verify again ───────────────────────────────────────────────────────"
"$PY" -m watchtower ledger verify
echo
echo "Exit code above was 1, and the finding names the height, the event, and"
echo "both digests. Nothing about the block itself was touched."
echo

echo "── 4. put the original bytes back ────────────────────────────────────────"
"$PY" -m watchtower ledger tamper --event-id "$EVENT_ID" --field message \
      --value "$ORIGINAL" >/dev/null
echo "Restored event $EVENT_ID."
echo

# Checked, not asserted. The first version of this script printed "Clean again"
# unconditionally — including on a run where verify had just reported the chain
# still broken. A closing line that says the opposite of the output above it is
# the exact failure this project exists to remove.
if "$PY" -m watchtower ledger verify; then
  echo
  echo "Clean again — the digest covers the content and nothing else, so restoring"
  echo "the exact bytes restores the chain. Your store is as it was."
else
  echo >&2
  echo "⚠️  The chain did NOT come back clean. Something other than this demo has" >&2
  echo "   modified the store. Reset with 'make clean-data'." >&2
  exit 1
fi
