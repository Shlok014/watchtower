# Measured results

## OpenSSH live rule replay

`python scripts/check_openssh_live_evidence.py` checks [the frozen replay JSON](openssh-live-replay.json) against a fresh run through the live parser, rule detector, SQLite store, and alert path. It replays the committed Loghub `OpenSSH_2k.log` with its original time intervals. The counterfactual changes only the alert cooldown; SOAR and threat feeds are disabled in both runs. The JSON records the source hash and event breakdown.

<!-- openssh-live-metrics:start -->
| Replay policy | Parsed events | Alerts | Alerted IPs |
|---|---:|---:|---:|
| No cooldown | 2,000 | 426 | 5 |
| 60s_per_ip_event_type | 2,000 | 26 | 5 |

The same 2,000 OpenSSH log lines produced **400 fewer repeated alerts** with the cooldown. The alerted IP set is identical in both runs, checked by its digest in the frozen JSON. The source has no independent incident labels, so these counts measure alert burden, not precision, recall, or false-alarm rate.
<!-- openssh-live-metrics:end -->

The cooldown is 60 seconds per IP, event type, and ruleset version. Every event is still recorded; repeat alerts within that window do not trigger another SOAR action. A successful manual unblock resets the cooldown for that IP. New event types may alert during an existing cooldown. The 2k sample is a fixed excerpt, and compressed `message repeated` lines are not expanded into individual attempts. A real traffic distribution and independent incident labels would be needed to evaluate detection quality.

## Live shadow evaluation

`python scripts/check_live_shadow_evidence.py` regenerates the deterministic evidence and compares it with [the frozen JSON](live-shadow-eval.json). The direct feature proxy and raw-event replay are different tests of the new live shadow profile. Both use generated, labelled scenarios. The rule detector remains the only automatic alert trigger.

<!-- live-shadow-metrics:start -->
| Synthetic test | TP | FP | FN | TN |
|---|---:|---:|---:|---:|
| Direct feature proxy, shadow | 24 | 0 | 8 | 64 |
| Raw-event replay, rules | 6 | 0 | 30 | 35 |
| Raw-event replay, shadow | 18 | 8 | 18 | 27 |

The raw-event replay has **71 generated events**; labels are assigned by its scenario generator. Its validation/test IPs and sources are disjoint from training, but the scenarios share a generator. These figures do not estimate production precision or false-alarm rate. SOAR actions are disabled during evaluation, and shadow verdicts never trigger alerts.
<!-- live-shadow-metrics:end -->

The direct feature proxy feeds rule-feature-shaped dictionaries to the profile; it bypasses normalization, feed lookup, SQL windows, and ingestion. The raw-event replay passes generated events through those application stages and reads stored alert and shadow verdict rows from temporary SQLite. It disables SOAR actions. Neither evaluation has independent incident labels, live traffic distribution, or calibrated probabilities. A production promotion gate therefore remains unproven.

The event ledger hashes the ingested event, not the analyst review history or shadow verdict. The profile digest detects accidental artifact changes; it is not an authenticity signature.

## HDFS benchmark

The HDFS figures below come from `python -m eval.benchmark`; the live shadow
section comes from `python scripts/check_live_shadow_evidence.py`. Each section
names the run that produced it. Template mining uses training blocks only;
held-out log lines can match existing templates but cannot create new ones.

## Log parsing

Grouping accuracy against loghub's ground-truth templates: a line counts
as correct only when the set of lines sharing its predicted template is
exactly the set sharing its true template.

| Dataset | Lines | True templates | Mined | Grouping accuracy |
|---|---:|---:|---:|---:|
| HDFS_2k | 2,000 | 14 | 16 | **0.9975** |
| OpenSSH_2k | 2,000 | 27 | 23 | **0.7180** |

OpenSSH is included deliberately. Drain does markedly worse on it, and a
table showing only the flattering dataset would misrepresent how general
this is.

## Anomaly detection

**Dataset:** loghub HDFS_v1 (full, 11.2M lines) — 11,175,629 lines, 575,061 labelled blocks, 16,838 anomalous (2.93%), 45 mined templates.

**Split:** stratified block 50/50; train-only template mining, seed 42 — 287,530 train / 287,531 held out.

**Held-out template coverage:** 5,588,020 of 5,588,021 lines matched templates mined from training blocks; 1 were unmatched. 0 lines mentioned blocks on both sides of the split and were excluded from template training.

| Model | Supervised | Precision | Recall | F1 | ROC-AUC | Fit (s) |
|---|---|---:|---:|---:|---:|---:|
| LogisticRegression | yes | 0.9605 | 0.9998 | **0.9797** | 0.9994 | 1.143 |
| DecisionTree | yes | 0.9986 | 0.9986 | **0.9986** | 0.9996 | 0.37 |
| IsolationForest | no | 0.1969 | 0.7150 | **0.3087** | 0.9465 | 0.85 |

Confusion matrix for DecisionTree on the held-out half: TP 8,407 · FP 12 · FN 12 · TN 279,100

### Reading these numbers honestly

- The template miner only sees training blocks. A held-out line may
  match an existing template, but cannot create a new one. Unmatched lines
  contribute zero template counts; the coverage above makes this visible.
- IsolationForest is fit on all training feature rows without labels
  using a fixed automatic threshold. It is a comparator, not the detector
  used by the live dashboard.
- These results describe **HDFS**, not the synthetic stream the dashboard
  shows by default. The two are separate: the dashboard's detection is a
  rule engine, and this page does not claim otherwise.
- Every figure above is measured on **complete blocks**. Live replay scores
  blocks as their lines arrive, which is a strictly harder problem — the
  same model, a different question. No accuracy is claimed for that, and
  `/api/v1/model` says so on every verdict it returns.

## The persisted model

This benchmark saved LogisticRegression as **version 5** in the
environment that ran it. Model artefacts are not committed to Git; a fresh
clone must train its own. The benchmark and `POST /api/v1/retrain` use the
same fit and evaluation path. Each version records its seed, split indices,
sklearn version, parameters, source hashes, and a SHA-256 of the feature
matrix and miner state. Live scoring refuses a mismatched miner.

Retraining on unchanged data returns a delta of exactly 0.0000. The endpoint
this replaced returned a figure that rose about a point per button press and
could never fall.

### What reproduces, and what does not

Running `make bench` twice against the same cached feature matrix was
checked, field by field. **Every measured quantity is identical** —
precision, recall, F1, ROC-AUC and all four confusion-matrix cells, for all
three models. The seed is fixed and the split is frozen, so they have to be.

Three things do move between runs, and none of them is a result:
`fit_seconds` (wall clock), the model `version` counter (a new artefact is
persisted each time), and the parse throughput when the matrix is rebuilt
rather than loaded. They are reported because they were measured, not
because they are stable.

## Pipeline

| Parse + featurise | 89,055 lines/sec (125.5s for 11,175,629 lines) |
|---|---|


## Environment

Python 3.14.1 · scikit-learn 1.9.0 · numpy 2.5.1 · Darwin arm64

Reproduce:

```bash
cd backend
python -m datasets.download --samples --hdfs
python -m eval.benchmark
```
