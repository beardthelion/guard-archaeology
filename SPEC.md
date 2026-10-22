# Guard Archaeology — SPEC

Status: spec (2026-10-21). Build order in the tool queue: Holdout first,
then this. Repo: beardthelion/guard-archaeology (private).

## Purpose

Find security guards that a codebase added and later silently lost.

Patch history asks what got fixed. Guard archaeology asks what unfixed
itself: a validation, bounds check, auth check, or escaping step added in
one commit (very often a security fix), then removed by a later commit
(refactor, rewrite, merge cleanup) while the dangerous operation it
protected is still there. Fix regressions are a real paid class in
source-code bounties, and no existing tool in the stack greps history
for removed defenses.

The tool's output is candidates, not findings. A candidate enters the
audit pipeline at kill-before-debug and pays only on a proven PoC, same
as every other candidate source.

## Core discipline

- Deterministic. Guard identification, forward tracking, and removal
  classification are mechanical (diff shapes, pickaxe search, commit
  metadata signals). No model judgment anywhere in the verdict path.
- Fail quiet over loud. A candidate with a weak chain is closed, not
  flagged. Deleted-guard noise is the known failure mode; the design
  treats noise control as the primary constraint.
- Three-link evidence or it does not ship. Every candidate carries the
  fix commit that added the guard, the commit that removed it, and the
  current code at HEAD. That is the kill-before-debug input shape.

## Definitions

- **Guard**: a code construct whose purpose is to reject, clamp, or
  sanitize before a dangerous operation: bounds/length/size checks,
  input validation and normalization, allowlist/denylist checks, auth
  or permission checks, escaping/encoding before a sink, type/range
  checks, symlink/TOCTOU checks. Guard classes reuse the variant sweep
  corpus vocabulary where they overlap.
- **Sink**: the dangerous operation the guard precedes, in the same
  function or the immediate caller chain.
- **Seed commit**: a commit eligible to originate a tracked guard (see
  Seeding). Guards are only tracked from seed commits, never from all
  history.

## Pipeline

### 1. Seed

Collect seed commits from the target repo's history:

- Commits referenced by published advisories (GHSA/CVE fix commits for
  that repo), when available.
- Commits whose message carries security signals: CVE/GHSA identifiers,
  or security vocabulary in the subject (fix + security, vulnerability,
  overflow, injection, bypass, traversal, auth, sanitize, escape,
  bounds, validate where paired with a fix verb).
- Commits in security-tagged releases or branches, when the repo marks
  them.

Everything else in history is ignored as a guard origin. This is the
noise gate: a tight seed set is what keeps the deleted-if problem
manageable.

### 2. Extract

From each seed commit's diff, extract added guard hunks:

- Added conditional rejection shapes: a new condition guarding an
  early return, raise, revert, or error path, positioned before a sink
  in the same function.
- Added call shapes: a new validation/sanitizer/escaping call inserted
  on the data path to a sink.
- Added constant shapes: a new size cap, allowlist, or limit consulted
  before the sink.

Record per guard: guard class, the normalized guard signature (the
condition or call shape with identifiers abstracted), the sink it
precedes (file:function), the seed commit SHA, and the advisory ID when
the seed came from one.

### 3. Track forward

For each extracted guard, follow it from the seed commit to HEAD:

- Locate the guard signature through subsequent history (pickaxe search
  on the signature, plus file-level following across renames).
- Identify the first commit where the signature is absent from the
  file's reachable code while the file and function lineage continue.
  That is the candidate removal commit.
- If the guard survives to HEAD, the guard is closed as INTACT and is
  not reported (counts only, for the run summary).

### 4. Removal classification

For each candidate removal, classify:

- **REGRESSED**: the guard is gone, the sink is still present and
  reachable at HEAD, and no equivalent guard replaced it. This is the
  only class reported as a candidate.
- **RELOCATED**: the removal commit (or the same PR range, when
  identifiable) adds an equivalent guard elsewhere on the sink's path
  (caller chain, shared helper, middleware). Closed.
- **REMOVED-WITH-SINK**: the sink itself was deleted or the feature was
  removed wholesale. Closed as noise.
- **DELIBERATE**: the removal commit's message or linked PR states the
  removal or revert intentionally (revert of the fix commit, explicit
  removal language). Closed as a candidate but listed separately in the
  run summary; a deliberate revert of a security fix is worth a human
  glance, not a pipeline slot.
- **UNKNOWN**: tracking lost the lineage (history rewrite, squash
  across the boundary, file deleted and recreated). Closed, counted.

Replacement and sink-survival checks are the second noise gate. A
guard that moved is not a regression, and the classifier must prove
absence on the whole sink path (function plus bounded caller chain,
the same bounded-depth rule Holdout uses) before REGRESSED is allowed.

### 5. Emit

One row per REGRESSED candidate, siblings-shaped so sibling-triage and
divergence-triage drain it unchanged, written to
`.clawpatch/archaeology.md` (or `.jsonl`) next to the target's scope
note:

- guard class
- sink file:function at HEAD
- guard signature (what is missing)
- seed: commit SHA + advisory ID when known
- removal: commit SHA + one-line commit subject
- current: the unguarded sink excerpt at HEAD
- exposure bucket when a scope note exists (untrusted / internal /
  unknown); unknown is its own bucket, never assumed

Run header: counts by class (tracked, INTACT, REGRESSED, RELOCATED,
REMOVED-WITH-SINK, DELIBERATE, UNKNOWN) so an empty candidate list
reads as checked, not skipped.

## Guard classifier (v1)

Per-language guard shapes for the ecosystems already in the stack:
Go, Rust, Python, TypeScript/JavaScript.

The classifier is shape tables, not heuristics soup:

- Rejection shapes per language (early return / raise / revert / error
  propagation under a new condition).
- Known validation and sanitizer call families per ecosystem (the
  sweep corpus's verified fixes are the training set: every verified
  rule's fix diff contains at least one real guard in its final form,
  which gives the classifier grounded examples from day one).
- A shape must sit on the data or control path to a catalogued sink in
  the same function, or it is not a guard for this tool's purposes.

Anything the shape tables cannot classify is not extracted. Precision
over recall, explicitly: a missed guard costs coverage; a noisy
candidate queue costs trust in every candidate the pipeline drains.

## Validation gate

Before the tool is trusted on a live target, it must pass a
known-answer test:

- Pick a repo with a documented fix regression (a vulnerability whose
  fix was reverted or lost and later re-fixed, or a re-disclosed CVE
  with the same root cause). Run the tool against the history as of
  just before the second fix.
- Pass condition: the lost guard appears as a REGRESSED candidate,
  with the true seed commit and a removal commit in the true range.
- Also run one large mature repo with no known regression in scope and
  confirm the REGRESSED count is small enough to drain by hand. If
  the queue is not drainable, the classifier is too loose and the tool
  does not ship.

## Integration

- Input: a local clone of the target repo; advisory fix-commit lists
  when the target has published GHSAs.
- Output: `.clawpatch/archaeology.md` candidates file per target, plus
  run counts. Candidates flow to kill-before-debug unchanged.
- Chains with Holdout: Holdout ranks currently unguarded sites by
  consensus; archaeology explains how a specific site lost its guard.
  A site that is both a Holdout outlier and an archaeology REGRESSED
  is the strongest candidate either tool produces; the emit step
  should cross-reference the holdout file when one exists for the
  target.
- No network access needed beyond the clone. No target code is ever
  executed.

## Out of scope for v1

- Guards that were never in git history (codebase's first commit is
  the floor).
- Non-source defenses: config flags, infrastructure rules, WAF rules.
- Merge-conflict resolution analysis beyond the removal classification
  above.
- Automated PoC generation or submission. Candidates only; the
  pipeline's existing gates decide what pays.

## Build notes

- Language: Python, matching dyetrace and the sweep pipeline.
- Git access via subprocessed git commands (log, show, log -S, blame)
  on a local clone; no GitHub API dependency for the core run.
- Deterministic output: stable sort by removal commit date then sink
  path; identical input history produces an identical candidates file,
  diffable run to run.
- Tests: fixture repos with planted histories (guard added, intact;
  guard added, relocated; guard added, removed with sink; guard added,
  silently removed) covering every verdict class before any real target
  is run.
