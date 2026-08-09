# Watchtower Release Publication Design

## Goal

Finish the final public-release deliverables in `docs/HANDOFF.md`: authentic
dashboard media, README integration, an evidence-backed release check, and a
public GitHub repository with its first CI result observed.

## Scope

- Capture the running Watchtower dashboard at a 1440 px viewport.
- Record a short live dashboard attack/enforcement demonstration and an actual
  `make demo` ledger-tampering demonstration.
- Keep public media free of third-party Tor exit IP addresses. The dashboard
  capture may use only RFC 5737 documentation addresses, or any address field
  showing a live Tor address must be masked before it is committed.
- Add the media to the README immediately after the masthead and in the
  Response section, with descriptive alt text and no claims beyond what the
  recorded UI demonstrates.
- Repair the proven CI blockers before release: Node 22 is the frontend floor,
  the lockfile must install cleanly under that runtime, and every committed
  Python file must satisfy Ruff's pinned `0.16.2` formatter gate.
- Correct documentation that claimed private Actions could not run, that the
  event transaction included a SOAR response, or that no routable address was
  committed. Add a third-party notice excluding Loghub sample data from the MIT
  license and preserving Loghub attribution.
- Run the existing lint, test, ledger-verification, published-numbers, and
  media-inspection gates. Use a separate Sol review as the independent release
  gate.
- Push and publish only through the `Shlok014` GitHub account. Make the
  repository public only after the release commit is merged to `main`; add a CI
  badge only after the first GitHub Actions run is demonstrably green.

## Capture Approach

The dashboard is started with the existing real synthetic and HDFS replay
sources. The capture is taken only after it has processed enough traffic to
show the timeline, alerts, and a non-zero enforcement drop count. The visual
evidence is exported from that running application; it is never reconstructed
from invented metrics or mocked UI state.

The attack GIF records the same live dashboard flow: start state, a brute-force
simulation, and the resulting enforcement evidence. The terminal GIF uses the
actual `make demo` output so it visibly proves a clean ledger verification,
tampering, and failure at the detected block. Each GIF is palette-optimized and
kept under 6 MB.

## Repository and Release Flow

Work occurs on `codex/release-assets` in an isolated worktree. The release
commit contains the CI repair, truthful release documentation, and generated
media. After local gates and the Sol audit pass, it is pushed with the active
`Shlok014` account and merged to `main`. The resulting private-repository
workflow must pass for that exact commit before the repository is made public;
that passing result permits a second small commit adding the CI badge.

## Acceptance Criteria

- `docs/assets/dashboard.png`, `docs/assets/attack-demo.gif`, and
  `docs/assets/tamper-demo.gif` exist, open correctly, and are referenced by
  the README.
- No public asset shows a routable third-party IP address.
- `make lint`, `make test`, and `make verify` pass on the release worktree.
- The independent Sol audit identifies no unresolved publication blocker.
- The release lands on `main`, is pushed by `Shlok014`, and the repository is
  public.
- The first GitHub Actions run is checked directly; a badge appears only when
  that run passes.
