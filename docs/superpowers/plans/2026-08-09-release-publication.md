# Watchtower Release Publication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish Watchtower with authentic, privacy-safe visual evidence and a verified first CI result.

**Architecture:** The application itself remains unchanged. A release worktree generates three documentation assets from real runtime behavior, the README embeds them, and existing quality gates plus an independent audit protect the public-release step.

**Tech Stack:** Flask, React/Vite, Make, pytest, Vitest, Ruff, GitHub Actions, ffmpeg.

## Global Constraints

- Use only the `Shlok014` GitHub account for remote GitHub operations.
- Never commit an image that displays a real third-party Tor exit IP address.
- Generate dashboard and terminal evidence from actual application commands, not fabricated output.
- Keep each GIF at or below 6 MB.
- Add the CI badge only after a directly observed successful workflow run.

---

### Task 1: Establish a verified release baseline

**Files:**
- Modify: no tracked files
- Verify: `Makefile`, `.github/workflows/ci.yml`, `docs/HANDOFF.md`

- [ ] **Step 1: Verify the worktree and GitHub identity**

Run: `git status --porcelain=v1 --branch` and `gh auth status`

Expected: branch is `codex/release-assets`, no working-tree changes, and the active GitHub account is `Shlok014`.

- [ ] **Step 2: Run the release-quality baseline**

Run: `make lint && make test && make verify`

Expected: all established lint, fabricated-claim, published-number, backend, frontend, and ledger-verification checks pass before media generation.

### Task 2: Generate and inspect authentic media

**Files:**
- Create: `docs/assets/dashboard.png`
- Create: `docs/assets/attack-demo.gif`
- Create: `docs/assets/tamper-demo.gif`

- [ ] **Step 1: Start the documented demo sources**

Run: `SOURCES=synthetic,replay:hdfs@20 make dev`

Expected: API listens on port 5001 and Vite serves the dashboard on port 5173.

- [ ] **Step 2: Capture the live dashboard**

At a 1440 px viewport, wait until the timeline has events, use the existing
Brute Force simulation, and capture only after the Enforcement panel has a
non-zero dropped count.

Expected: the PNG shows live status, source data, alert evidence, and enforced
drops without a real Tor exit IP address.

- [ ] **Step 3: Capture the live attack flow**

Record 10-15 seconds from the dashboard while an actual attack is simulated
and the Enforcement panel shows a block and increasing dropped count. Convert
the recording with the documented two-pass `ffmpeg` palette command.

Expected: `docs/assets/attack-demo.gif` plays, is no larger than 6 MB, and
shows the closed detection-to-enforcement loop.

- [ ] **Step 4: Capture the ledger-tamper flow**

Run `make demo`, record the actual verification-success, tamper, and
verification-failure sequence, then palette-optimize it with `ffmpeg`.

Expected: `docs/assets/tamper-demo.gif` plays, is no larger than 6 MB, and its
terminal text matches a fresh run of the same command.

- [ ] **Step 5: Inspect every generated asset**

Run: `file docs/assets/* && du -h docs/assets/*`

Expected: one PNG and two valid GIF files exist; each GIF is at or below 6 MB.

### Task 3: Integrate media without changing product claims

**Files:**
- Modify: `README.md`
- Create: `docs/assets/dashboard.png`
- Create: `docs/assets/attack-demo.gif`
- Create: `docs/assets/tamper-demo.gif`

- [ ] **Step 1: Add the dashboard image under the masthead**

Add this exact Markdown after the opening description:

```markdown
![Watchtower dashboard showing live sources, alerts, and enforcement](docs/assets/dashboard.png)
```

- [ ] **Step 2: Add the attack GIF in the Response section**

Add this exact Markdown immediately after the closed-loop explanation:

```markdown
![A brute-force alert causes an enforcement block and subsequent event drops](docs/assets/attack-demo.gif)
```

- [ ] **Step 3: Add the tamper GIF beside the ledger explanation**

Add this exact Markdown immediately after the ledger verification explanation:

```markdown
![Ledger verification detects a deliberately tampered event](docs/assets/tamper-demo.gif)
```

- [ ] **Step 4: Review the rendered README and media paths**

Run: `git diff --check && rg -n 'docs/assets/(dashboard|attack-demo|tamper-demo)' README.md`

Expected: no Markdown path typo, whitespace error, unsupported claim, or broken
reference exists.

### Task 4: Release, independently audit, and publish

**Files:**
- Modify: `README.md`
- Create: `docs/assets/dashboard.png`
- Create: `docs/assets/attack-demo.gif`
- Create: `docs/assets/tamper-demo.gif`
- Create: `docs/superpowers/specs/2026-08-09-release-publication-design.md`
- Create: `docs/superpowers/plans/2026-08-09-release-publication.md`

- [ ] **Step 1: Run final local verification**

Run: `make lint && make test && make verify`

Expected: all release gates pass after documentation changes and media creation.

- [ ] **Step 2: Obtain and resolve the independent Sol audit**

Expected: audit checks the handoff, README, workflow, generated media, and
release evidence; any blocker is resolved before pushing.

- [ ] **Step 3: Commit the release artifacts**

Run: `git add README.md docs/assets docs/superpowers && git commit -m "docs: add verified release media"`

Expected: one intentional release commit on `codex/release-assets`.

- [ ] **Step 4: Push and merge through Shlok014**

Run: `gh auth switch -u Shlok014`, push the branch, create and merge the
release pull request.

Expected: `main` contains the release commit and the remote action history is
owned by `Shlok014`.

- [ ] **Step 5: Make the repository public and observe CI**

Run: `gh repo edit Shlok014/watchtower --visibility public --accept-visibility-change-consequences`, then inspect the triggered workflow.

Expected: repository visibility is public and the first Actions result is
observed directly. Add a CI badge in a follow-up commit only if that result is
successful.
