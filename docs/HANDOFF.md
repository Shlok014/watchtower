# Handoff — 2026-08-05

Where the rebuild stands, and exactly where to pick it up.

> **2026-08-09 release correction.** This handoff is a historical snapshot, not
> a proof that `main` was release-ready. The 2026-08-04 private-repository CI
> run did execute and failed: the frontend lockfile was incompatible with its
> Node 20 runtime, and five files failed Ruff's format check. It was not blocked
> by Actions billing. The release branch raises the frontend baseline to Node 22,
> restores formatting, corrects the affected documentation, and requires a
> matching green CI run before visibility changes or a CI badge.

> **2026-08-09 release evidence update.** The repaired baseline was merged in
> PR #19 and its post-merge Actions run passed. `README.md` now embeds a
> 1440 px dashboard capture from a live local run, an animated capture of one
> simulated brute-force burst flowing into application-layer enforcement, and a
> command-recorded ledger tamper demonstration. Neither shows third-party Tor
> exit IP addresses. The synthetic input is labelled; alerting, blocklist writes,
> and dropped-event counting are real application behavior. Add the CI badge
> only after the follow-up release-media commit is observed green.

> **2026-08-09 publication update.** PR #20 merged as `b92dd21`; its `main`
> workflow run 31314295495 passed both jobs. The repository is public under
> `Shlok014/watchtower`, and the README now carries the CI badge for `main`.

The governing rule, which has driven every decision: **no number is reported
unless it was measured, and anything not measured says so.** Most of what
follows exists because that rule forced it.

---

## Historical state at the original handoff

**At the original handoff, `main` was clean but not verified green.** There were
no open pull requests, no uncommitted work, nothing running, and 18 PRs merged.

    make lint    ruff · eslint · fabrication gate · published-numbers gate
    make test    150 backend · 45 frontend
    make perf    storage figures  →  docs/STORAGE.md
    make bench   detection figures →  docs/METRICS.md
    make demo    the tamper demo, which now restores the store afterwards

**The visual evidence is now available:** the README contains a live dashboard
capture, an animated browser capture of the simulated attack-to-enforcement
flow, and a terminal-recorded ledger-tamper GIF.

**The repository stayed private until release assets and a green CI run existed**
— the 2026-08-04 decision. The repaired baseline has since passed; it remains
private only until the release-media commit is verified green and publication is
performed. No badge belongs in the README until that matching run is observed.

## What happened after the sessions were merged

The sessions themselves are summarised further down. Since then, four things —
all of which found real defects:

**The clean-clone gate** (the plan's stated final gate) — never run before, and
it failed twice before passing. Four bugs, below.

**An adversarial review** — 20 agents in throwaway clones, 4 lenses, every claim
handed to a separate agent instructed to refute it. **16 raised, 10 confirmed.**
The worst: a typo in a playbook YAML silently erased every alerting event, while
the ledger still verified clean and health said "All systems operational".

**A second review, of those fixes** — because moving the SOAR response out of the
ingest transaction genuinely weakened atomicity. **6 raised, 4 confirmed**,
including that the docstring written in round one was itself false.

**A re-measurement of the storage figures** — three numbers hand-typed in the
README since session 2 and never re-checked. One had moved by about half. They
are generated now.

If you take one process lesson from all of it: **review the fixes, not just the
code.** Round two found a bug inside round one's fix that reviewing the original
would never have surfaced.

## The clean-clone gate — run, and it found four bugs

The plan calls this the final gate: *"clone the repo into a temp dir on this same
Mac, run `make setup && make dev`, and confirm the dashboard comes up. If that
fails for a stranger, nothing else in this plan matters."* It had never been run.
It now has, and **it failed twice before it passed**:

1. **`backend/pytest.ini` shadowed the root config.** pytest takes the nearest
   config walking up from the invocation directory, so running from `backend/` —
   what CI does — used it and everything in `pyproject.toml` was silently
   inactive there, including the warning filters. Deleted; one config now.
2. **`requirements-ml.txt` was a stale duplicate** headed *"not needed to run the
   dashboard"*, which stopped being true when the app began loading a model at
   startup. Merged into `requirements.txt` and deleted.
3. **`make dev` was broken on every Mac.** `scripts/dev.sh` ended in `wait -n`,
   which is bash 4.3+; macOS ships 3.2.57 and always will. It failed with
   *"wait: -n: invalid option"*, took the EXIT trap with it, killed the backend
   and orphaned the dashboard. Replaced with a poll loop; both scripts now pass
   `/bin/bash -n`.
4. **Five targets could not import the app.** The package is at
   `backend/watchtower`, recipes run from the repository root, and `python -m`
   adds only the current directory to `sys.path` — so `dev`, `backend`, `feeds`,
   `verify` and `demo` all died with *"No module named watchtower"*. The three
   that worked (`test`, `lint`, `bench`) are exactly the three that had been run
   before. Fixed with one exported `PYTHONPATH`.

**The gate now passes.** On a virgin clone: `make setup`, 141 + 45 tests, `make
lint` with all three gates, `make verify`, `make bench`, and `make dev` bringing
up both services. 988 events flowed (911 from real HDFS replay, 77 synthetic),
an attack blocked 5 addresses and really dropped 18 events, and 989 ledger blocks
verified clean.

`scripts/check_published_numbers.py` was added along the way: `docs/metrics.json`
and `docs/METRICS.md` cannot disagree because one generates the other, but the
README and this file are hand-written. 43 figures checked.

## What the review found

Twenty agents, four lenses, each in its own throwaway clone; every finding put
to a separate agent instructed to refute it. **16 raised, 10 confirmed, 6
refuted** (four of the six from the tests lens). All ten are fixed, with eight
regression tests.

The one that mattered: **a typo in a playbook silently erased every alerting
event.** Playbook selection ran inside the ingest transaction, so `PlaybookError`
rolled back the event row, its ledger block and the counter bump. Benign events
stored normally; anomalous ones ceased to exist — and because SQLite reuses the
rowids of a rolled-back transaction, `verify` saw no height gap and called the
chain clean over a record set missing exactly the interesting traffic, while
health said "All systems operational".

Its sibling: the webhook's 3-second call ran inside `BEGIN IMMEDIATE`, so
concurrent events died with "database is locked" and were never written.

Both have one cause and one fix — **the response now runs after the ingest
transaction commits.** Nothing that can fail or block belongs in a transaction
holding the single write lock. Playbooks are also validated in `create_app`, so
a typo refuses to start the app rather than surfacing at 3am.

The rest: health read `any(alive)` so one dead source among several stayed
green; feed freshness was computed once and frozen, so the "stale" branch could
never fire; `housekeeping` was wired only into the synthetic source, so no real
configuration ever pruned; the dashboard printed a hardcoded `0.45` threshold
the API never sent; `/stats` returned the synthetic generator's hostnames so the
source filter matched nothing under a real source; the file tailer emitted half
a line as a finished event; and a 200-event window was charted beside a lifetime
stat card with nothing saying why.

## And a second review, of those fixes

Moving the response out of the ingest transaction weakened atomicity, so it got
its own round. Three lenses, six claims, **four confirmed**.

**The docstring I wrote was itself the bug.** It said a failed response "leaves
an alert with status open and no SOAR record — a true statement about what
happened". It was not. `block_ip` writes on an autocommit connection, so the
block lands the moment it runs while the alert still reads "open" — leaving an
address under active enforcement beside a status that means "nothing has run
yet". Reproduced on a graceful Ctrl-C, and it survived a restart still dropping
traffic. The execution row is now written before the first action can have an
effect, and steps are recorded as they complete.

**The partial-line fix from round one made a worse bug possible.**
`copytruncate` plus a refill past the old offset let the buffer glue the head of
one file's last line onto the tail of another's first — one well-formed,
attributed, severity-classified record whose text never existed anywhere, with
the severity coming from a word in the other file. Fragments now expire.

Also: the SOAR health tile was reporting the alert-insert time (0.05 ms) for
work measured at 1014 ms, and a replay that finished its file made health read
"degraded" forever.

And a flaky test, at a measured 0.54%: it drove `/simulate-attack`, whose
brute_force burst draws randomly from a pool two thirds `failed_login` — which
has no playbook and blocks nothing.

## Release evidence

The release now includes `docs/assets/dashboard.png` from a live local dashboard,
`docs/assets/attack-demo.gif` assembled from actual browser states during one
simulated brute-force run, and `docs/assets/tamper-demo.gif` from `make demo`.
All three are referenced by the README. The input burst is synthetic; its
resulting alert, blocklist write, and later dropped events come from the running
application.

```bash
make setup
SOURCES=synthetic,replay:hdfs@20 make dev     # :5001 and :5173
```

Let it run 30–60 seconds so the timeline fills and a few alerts land, then:

1. **`docs/assets/dashboard.png`** — complete. It is a 1440 px capture from a
   live dashboard run with alerts and enforced drops.
2. **`docs/assets/attack-demo.gif`** — complete. An 11-second browser capture
   shows one synthetic brute-force burst, its alert evidence, and the resulting
   ingestion-layer Enforcement table with a non-zero dropped count.
3. **`docs/assets/tamper-demo.gif`** — complete: 10–15s of `make demo` in a terminal:
   verify passes, one event is corrupted with raw SQL, verify fails and names
   the height, the event and both digests.

QuickTime screen recording → two-pass palette, under 6 MB each:

```bash
ffmpeg -i in.mov -vf "fps=12,scale=1000:-1:flags=lanczos,palettegen" palette.png
ffmpeg -i in.mov -i palette.png -lavfi "fps=12,scale=1000:-1:flags=lanczos [x]; [x][1:v] paletteuse" out.gif
```

The README already embeds the dashboard under its masthead and the two GIFs
beside their relevant behavior. Set `dashboard.png` as the GitHub social preview
(Settings → General → Social preview) so the link unfurls on LinkedIn. Push the
release commit and verify its green CI run before flipping the repo public:

```bash
gh auth switch -u Shlok014
gh run watch RUN_ID --repo Shlok014/watchtower --exit-status
gh repo edit Shlok014/watchtower --visibility public --accept-visibility-change-consequences
```

The successful run must match the release commit. Add the badge only then.

**Check before publishing:** the demo address pool draws real Tor exit
addresses for connection-provenance events (see `threatintel/pool.py`), so a
screenshot could show a real relay operator's address beside a "suspicious IP"
verdict. Events that fabricate forensic detail already use RFC 5737 ranges.
The feed cache is git-ignored, but the committed OpenSSH sample includes
routable addresses from Loghub. This is both a screenshot and a data-provenance
question; see `docs/THIRD_PARTY_NOTICES.md`.

---

## Done since the last handoff

### Session 4 — the 1,055-line module became a package
`backend/watchtower/` with `config.py`, a `create_app()` factory, a blueprint at
**`/api/v1`** and no unversioned alias. Two defaults changed, and both were
security bugs rather than taste: `CORS(app)` allowed every origin against an
unauthenticated API with a destructive `POST /reset`, and the server bound
`0.0.0.0`, publishing that API to every machine on the network.

**The CI honesty gate needed a real CI run.** A private-repository Actions run
executed later and exposed the formatter and frontend-runtime drift recorded in
the release correction above.
`grep -rn .` emits `./`-prefixed paths under GNU grep and bare paths under BSD
grep, which broke its own allowlist; and the retired-names check flagged the six
lines of prose that *retire* them — "there is no proof-of-work, and it is not
Hyperledger" is the honesty story. Replaced by
`scripts/check_no_fabrication.py`, which strips comments and docstrings with
`tokenize` before matching, and in prose flags only claim-shaped mentions.

### Session 7 — four sources, one pipeline
`syslog` (UDP, RFC 3164 + 5424, port 5514), `file:<path>` (inode-based rotation
*and* in-place truncation), `replay:<hdfs|openssh>[@rate]`, and the synthetic
generator. All four emit through the same `process_log`.

Replay keeps the log's own timestamp in `ts_ms`; `ingested_ts_ms` is now. And it
stays honest that **HDFS is a filesystem log** — lines keep their own level, and
nothing maps `WARN` onto a threat. Measured: 167 replayed events, 0 alerts.

`logger -n host -P port` is util-linux and **the BSD logger macOS ships rejects
it**. The README gives the portable `nc` form.

### Session 6b — the model became an artefact
`POST /api/v1/retrain` refits on the frozen split, persists a version, and
returns a real delta. Live: **`delta_f1: 0.0`** in 1.9 s against 575,061 blocks.
Each version records seed, split indices, sklearn version, params and a SHA-256
of the matrix it saw.

Live block scoring during replay uses `parser.match()`, never `parse()`. **The
published F1 does not transfer to those scores and every verdict says so.**

Two latent CI failures fixed: `requirements.txt` had never gained numpy, scipy,
scikit-learn, joblib or drain3; and a `--dataset sample` run overwrote
`docs/METRICS.md` with a 2,200-block result.

### Session 8 — SOAR closes the loop
`block_ip` writes to a `blocklist` table the consumer checks **before**
detection. Live: 12 events → 1 alert → block → **10 events really dropped**.
YAML playbooks, `safe_load` only, unknown actions rejected at load. Status is
earned: `contained` needs a required step with a real side effect.

Two things the tests found: `dropped` had to go inside the ledger digest (which
required per-block canon versioning, so old blocks still verify), and the ledger
had to move **ahead of detection** so an incident report can cite the block
covering its own triggering event.

Schema 1 → 2 with a real migration runner, verified against a v1 database built
from `origin/main`'s schema.

### Session 9 — the dashboard stopped implying things
The six-stage boot animation is gone. `LIVE` was a string literal; it is now
LIVE/STALE/OFFLINE from the age of the last successful poll. The API client no
longer swallows every error. Empty states distinguish "no data" from "no
backend". `App.jsx` 662 lines → 16 components. **45 Vitest tests**, including App's own gate → dashboard → offline transitions.

### Session 10 — tooling and the gates
`make help` is the interface. `scripts/dev.sh` replaces `start.sh`, whose
`lsof -ti:5001 | xargs kill -9` killed whatever owned the port — on a Mac where
5001 is also AirPlay Receiver. CI gained Vitest, coverage (printed, **not**
thresholded), and `scripts/check_detection_floor.py`.

**The CI backend job was run end to end locally for the first time**, on a clean
Python 3.13 venv installed only from `requirements.txt`: the full suite, ruff, both
gates, all green.

---

## Measured results

Current train-only template-mining run, regenerated by `make bench` on the full
dataset — 11,175,629 lines, 575,061 labelled blocks, 45 templates, 125.5 s
(89,055 lines/sec over three passes):

| | Precision | Recall | F1 |
|---|---:|---:|---:|
| LogisticRegression | 0.9605 | 0.9998 | **0.9797** |
| DecisionTree | 0.9986 | 0.9986 | **0.9986** |
| IsolationForest (unsupervised) | 0.1969 | 0.7150 | **0.3087** |

Parsing grouping accuracy: HDFS_2k **0.9975**, OpenSSH_2k **0.7180**.

The earlier IsolationForest row used labels to select normal training rows and
full-dataset prevalence to set its threshold. The current row uses neither.
Earlier figures remain in Git history; the table above reflects the current
run and its measured coverage is in `docs/METRICS.md`.

Tests: **154 backend + 45 frontend**.

---

## Pick up here

Everything was merged at the time of this historical handoff. The current
release corrections and evidence status are recorded at the top of this file.

**1. The release evidence is complete.** The dashboard PNG, attack GIF, and
ledger GIF are already integrated. The capture recipe above remains available
when a fresh recording is useful.

```bash
make setup
SOURCES=synthetic,replay:hdfs@20 make dev     # :5001 and :5173
```

Let it run 30–60 seconds, fire a `⚡ Simulate Attack → Brute Force` so the
Enforcement panel shows a real application-layer block with a non-zero drop
count, then recapture if needed.

**2. Set `dashboard.png` as the GitHub social preview** so the link unfurls on
LinkedIn. The image is already embedded under the README masthead.

**3. Push the release commit and verify a matching green CI run, then flip the
repo public.**

```bash
gh auth switch -u Shlok014      # NOT shlok-sylox — see Environment notes
gh repo edit Shlok014/watchtower --visibility public \
   --accept-visibility-change-consequences
```

**4. Add the CI badge only after that matching run is green.** Private Actions
already executed and failed on the original `main`; repository visibility does
not itself start this workflow.

### Before publishing

The demo address pool draws **real Tor exit addresses** for connection-provenance
events (`threatintel/pool.py`), so a screenshot could put a real relay operator's
address beside a "suspicious IP" verdict. Events that fabricate forensic detail
already use RFC 5737 ranges. The committed OpenSSH sample also contains routable
addresses from Loghub, so both public media and bundled-data provenance need
review.

A limited pre-publish sweep found no secrets or local paths. It did not perform a
full-history secret scan, and the committed Loghub OpenSSH sample includes
routable addresses.

---

## Do not regress

- **`origin` is checked with `GLOB`, not `LIKE`.** SQLite's `LIKE` is ASCII
  case-insensitive, so `LIKE 'replay:%'` also accepts `REPLAY:`.
- **The ledger digest covers `ts_ms`, not the ISO string.**
- **Each block verifies under the canon *it* records.** Adding a field to
  `CANON_FIELDS` without a new canon version retroactively accuses every
  historical block of tampering — and a false alarm is indistinguishable in the
  output from a real one.
- **Detection windows key on `ingested_ts_ms`,** and exclude `dropped` rows.
- **The blocklist is checked before detection,** not after.
- **`auto_vacuum` must be set before the first `CREATE TABLE`.**
- **Lifetime counters live in a table**, not `COUNT(*)`/`max(id)`.
- **FireHOL level1 contains RFC1918.** Classify address scope first, and never
  with `ipaddress.is_private`.
- **Unlisted addresses score 0.00.** Absence from a blocklist is not evidence.
- **`schema.sql` is always the current schema**, so a fresh database skips every
  migration. Migrations run only on older files, and each goes in one
  transaction with its version stamp.
- **A sample-dataset benchmark run must never write `docs/METRICS.md`.**
- **`match()`, never `parse()`, at inference.**
- **The SOAR response runs *after* the ingest transaction commits.** Putting it
  back inside means a broken playbook rolls the event out of existence and a
  slow webhook holds the single write lock. Both were reproduced.
- **The execution row is written before the first action can have an effect.**
  `block_ip` commits on its own connection; without the row first, a crash
  leaves an address under enforcement beside an alert reading "open".
- **A held partial line in the file tailer must expire.** Holding it
  indefinitely lets `copytruncate` splice two files into one fabricated,
  severity-classified record.
- **Health distinguishes *finished* from *died*.** A replay reaching EOF is
  success, not a fault.
- **Storage and detection figures are generated, never typed.** `make perf` and
  `make bench`; `scripts/check_published_numbers.py` fails the build on drift.

## Open decisions

- **Ledger disk budget.** Append-only and exempt from retention. Re-measured by
  `make perf` on a fresh database: **1,015 bytes/block**, about **2 GB/day** at a
  25 ev/s replay. Up from the 838 published in session 2 because the digest now
  covers `dropped` and each row records its `payload_canon`. Fine today; still
  needs a policy before a replay runs for any length of time.
- **Real Tor exit addresses in screenshots.** The generator uses real Tor exits
  only for connection-provenance events and RFC 5737 ranges for events that
  fabricate forensic detail. Worth a second look before publishing images.
- **Blocklist TTLs** are per-playbook (900 s – 7200 s) and were chosen by
  judgement, not measurement. Nothing depends on them being right.

## Environment notes

- Python **3.14.1** locally, python.org build with **no CA bundle** — `urllib`
  raises `CERTIFICATE_VERIFY_FAILED` without `certifi`. Never "fixed" with
  `ssl._create_unverified_context`.
- CI targets **3.12**; the local clean-install verification used **3.13**, which
  is the closest interpreter on this machine.
- `backend/data/` is git-ignored **except `data/samples/`**, which holds the
  committed loghub 2k logs, their structured CSVs, and the label subset for the
  blocks they contain (~1.3 MB total). That is what makes a clean clone
  runnable, testable and benchmarkable with zero downloads.
- Zenodo record **8196385 returns 504**; record **3227177** works.
- **`gh` has two accounts.** The repo is owned by `Shlok014` but `shlok-sylox` is
  often the active one, and every repo command 404s until you switch. If a push
  fails with "Repository not found", `gh auth switch -u shlok-sylox` then back to
  `Shlok014` re-primes the git credential helper. This happened three times.
- **`bash` on this Mac is 3.2.57** and always will be. `wait -n`, `declare -A`
  and friends are unavailable; both scripts in `scripts/` are checked with
  `/bin/bash -n`.
- **Disk is tight: ~9 GB free.** `backend/data/datasets` is 1.7 GB (the full
  HDFS_v1 download plus its zip). Deleting `HDFS_v1.zip` reclaims 178 MB safely;
  deleting `HDFS.log` means `make bench` has to re-download before it can
  regenerate the full-dataset page.
- **Review subagents mutate the working tree.** `isolation: "worktree"` fails
  here because the session's cwd is not a git repo, so they were each given a
  throwaway `git clone` instead. Two of them also ran `rm -rf` over shared
  `$TMPDIR` with wildcards. Never point them at this repo directly.
