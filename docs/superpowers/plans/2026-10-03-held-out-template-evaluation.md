# Held-out template evaluation implementation

Spec: `docs/superpowers/specs/2026-10-03-held-out-template-evaluation-design.md`

## Task 1: Lock the leakage with tests

Files: `backend/tests/test_model.py`, `backend/watchtower/detect/features.py`.
Add a small synthetic labelled log fixture with train-only, held-out-only,
and mixed-ID lines. Assert that parser `parse()` never receives a held-out
line, parser `match()` handles held-out lines, and the vocabulary has no test
template. Add a stale-cache regression. Run the new tests and observe failure.

## Task 2: Split before mining

Files: `backend/watchtower/detect/features.py`,
`backend/watchtower/detect/train.py`.
Discover labelled blocks before fitting the miner; use the frozen split to
choose train/test blocks; parse training-only lines, then match test/mixed
lines against fixed templates. Keep row order stable and record held-out
coverage. Version the feature cache and require the persisted miner on cache
reuse. Pass the focused tests, existing model tests, and backend suite.

## Task 3: Make published claims match evidence

Files: `backend/eval/benchmark.py`, `docs/METRICS.md`, `README.md`,
`docs/metrics.json`, plus new sample output if useful.
Report preprocessing and held-out match coverage in benchmark output. Label
old full-dataset figures transductive until rerun. Run the sample benchmark,
lint, and claim-check scripts; do not substitute sample metrics for the full
dataset. Commit only after checks pass.

## Review focus

Look for multi-block lines that could leak held-out text into training, cache
reuse with a missing or mismatched parser state, changed split indices, and
claims that imply the old full-dataset scores are new held-out scores.
