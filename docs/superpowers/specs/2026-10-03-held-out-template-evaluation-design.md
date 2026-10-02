# Held-out template evaluation

## Goal

Make the HDFS model's held-out scores reflect a feature extractor that has not
learned from held-out log lines. Preserve deterministic block-level splitting,
versioned artifacts, and the existing CLI/API retraining path.

## Design

Discover labelled block IDs in log order, then use the existing stratified
frozen split. Mine Drain templates only from lines whose labelled block IDs all
belong to training. Freeze the miner before a separate pass over held-out lines:
`match` may assign an existing template but cannot create one. A line with
both train and test IDs is excluded from training and counted separately;
its held-out IDs may still be matched. Unknown held-out templates produce zero
counts and an explicit unmatched counter.

The resulting matrix retains the discovered block order, so `model.fit` and
the comparison models use exactly the split that governed preprocessing.
Persist only the train-fitted miner for live scoring. Cache schema 2 includes
the split method and unmatched counters. Reject old caches and rebuild them.

## Evidence and claims

Tests must prove held-out-only messages never call `parse`, mixed lines do not
enter the miner, `match` leaves the template vocabulary unchanged, and old
caches cannot be accepted. Run the committed sample through retraining and
report its measured held-out result. The currently published full-dataset
figures were produced under the older transductive preprocessing and must be
labelled as such until the full dataset is downloaded and rerun.

## Scope

This does not add a new detector, claim generalization to other log sources,
or treat partial-block live scores as equivalent to complete-block evaluation.
