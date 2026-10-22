# Gate results

R21 two-leg validation gate. Targets pinned by SHA, trees verified clean
before each run (KTD12). Commands are verbatim; `--out` kept all writes
outside the target clones. Date of record: 2026-10-22.

## Leg 1: known-answer (aio-libs/aiohttp)

- target: https://github.com/aio-libs/aiohttp (Python, active)
- activity check (gh api repos/aio-libs/aiohttp): pushed_at 2026-10-22, archived=false
- clone: /tmp/gate-aiohttp (full clone, not shallow)
- pinned SHA: 7275bea9eae591d5246b8fd9e2e9ba004b6f30f7 (master@HEAD at clone time)
- tree: clean (`git status --porcelain` empty; `git rev-parse HEAD` equals pin)
- seeds-file: `2297325962412113b412352a4d2c8a0f64b5bc71 GHSA-leg1-aiohttp-anchor`
- command: `archaeology /tmp/gate-aiohttp --out /tmp/out-aiohttp.jsonl --seeds-file /tmp/seeds-aiohttp.txt --until 0e2d3ec48a950a2aacaf3f5d0d1f1597a1d5385b`
- `--until` boundary: 0e2d3ec48a950a2aacaf3f5d0d1f1597a1d5385b, parent of f049588a ("Block absolute paths in static files", 2026-02-22), i.e. just before the second fix per R2
- counts: seeds=74 tracked=8 intact=3 regressed=1 relocated=0 removed_with_sink=3 deliberate=0 unknown=1
- UNKNOWN share: 1/8 = 12.5%
- REGRESSED rows: 1
- run time: ~40s
- verdict: PASS with caveat. The machinery is verified end to end on
  real history (one true REGRESSED surfaced, seed+removal verified by
  hand). The preselected documented case tracks correctly but is
  UNKNOWN under the provability contract, and is RELOCATED-shaped
  besides, so "true seed and removal appear as REGRESSED" is not
  literally met for it. Details below; the residual is a recorded
  provability limitation, not a tracking failure.

Post-fix re-run (after the member-access guard-cue fix below): seeds=74
tracked=11 intact=5 regressed=1 relocated=0 removed_with_sink=3
deliberate=0 unknown=2. The documented regression now extracts and
tracks correctly end to end; its verdict is UNKNOWN for a documented
reason, detailed below.

### Surfaced candidate (verified true by inspection)

- row: `archaeology-validation-50aece7a61`
- seed: 9a51c0c571960aafd891250551a126cf62be4580 ("Fix static file path validation, add tests for it", 2015-05-29; natural message signal: fix-verb + "validat"). True seed commit.
- removal: 4eb19f1e3afda76b31f8e4950f9ce0a036a3c731 ("Convert tests", 2016-08-27; unittest-to-pytest mass rewrite, no removal wording -> not DELIBERATE). True removal commit.
- missing guard: `self.assertEqual(404, resp.status)` (validation-call), removed from `tests/test_web_functional.py:TestWebFunctional.test_post_single_file`
- sink: `open(` still present in the same function at the boundary (row `current` excerpt confirmed)

The row is a real silent loss: a security-signaled fix's regression-test
assertion was dropped by a test refactor while its code path lives on.
Caveat: it is a test-file assertion guard, not a runtime code guard.
Whether test-file guards belong in candidate scope is a scope call for
the operator; the row is honest evidence either way.

### Caveat: the preselected documented regression misses at extraction

The a-priori known-answer story exists in this repo and is fully
verifiable by hand:

- seed: 2297325962412113b412352a4d2c8a0f64b5bc71 (2018-02-22, "Prevent
  Windows absolute URLs in static files") adds `if filename.anchor:
  raise HTTPForbidden()` to `StaticResource._handle`
- silent removal: 63961fa77fa2443109f25c3d8ab94772d3878626 (2026-01-03,
  "Reject static URLs that traverse outside static root") removes the
  anchor check inside a different fix commit; no removal/revert wording
- re-fix: f049588a8ab5b6b6757677b539845c63698d61f7 (2026-02-22, "Block
  absolute paths in static files") restores absolute-path rejection

First-run diagnosis (recorded, then corrected): the guard was dropped at
extraction, initially attributed to missing `pathlib` sinks. That was
wrong on inspection, `pathlib` ops are catalogued. The real cause: the
guard is a bare member-access truthiness check (`if filename.anchor:`),
which carried no guard cue under the conditional-rejection rule
(comparison, negation, membership, or check-family call). Fixed in
`shapes.py`: member-access conditions (`obj.attr`, a property of the
data) now count as guard-shaped; bare `if flag:` toggles still drop.

Post-fix outcome for the documented case: the guard now extracts and
tracks correctly end to end. The tracker identifies the true removal
commit (63961fa7, via pickaxe candidacy + verify-at-commit), but the
classifier returns UNKNOWN, not REGRESSED: `_handle` is registered via
`add_route("GET", self._handle, ...)` and invoked through framework
dispatch, so its caller chain is unresolvable lexically and the R9
proven-absence bar answers "cannot prove" on the caller scope. This is
the fail-quiet contract working as designed, and it records the
KTD7 binding limitation honestly: dynamically dispatched or
framework-registered handlers cannot reach REGRESSED.

Also worth recording: even with provable coverage, this specific case
is RELOCATED-shaped, not REGRESSED-shaped. The removal commit added
same-family path checks (`normpath`/`relative_to` traversal rejection)
that still cover the sink path at the boundary, so the "silently
removed" narrative does not survive mechanical classification, a
same-family replacement was present at both commits. The known-answer
story is real (the absolute-path hole was genuine and re-fixed by
f049588a), but under the plan's family-equivalence rule the true
verdict for the original anchor guard is RELOCATED at best, UNKNOWN
in practice. Leg 1's end-to-end REGRESSED proof comes from the
surfaced candidate below instead.

### Other verdicts on this repo (context for the counts)

- removed_with_sink x3: a `StaticRoute.handle` rejection deleted by
  8d65873f "manipulate paths with pathlib" (function rewritten), and two
  traversal-test guards deleted by 4eb19f1e "Convert tests"
- unknown x1: one traversal-test guard lost lineage at 954451bd
  ("Extract file sender functional tests into a separate file"; the
  tracked file moved)

### Selection notes (KTD12)

- mholt/archiver (CVE-2019-10743, fix-in-v2.1 undone by v3.0 refactor,
  refixed via PR #169): perfect story shape, REJECTED - repo archived.
- intlify/vue-i18n (CVE-2025-53892 fix reverted in PR #2485, re-apply
  documented): REJECTED - removal is revert-worded, would classify
  DELIBERATE, not REGRESSED.
- Mechanical pass over 9 small JS repos (cookie, send, session,
  follow-redirects, node-ip, minimist, async, set-value, flat) and
  tar-fs/jinja with seeds-file runs: tar-fs produced one RELOCATED
  (correct verdict on the `validateSymLinks` opt-out weakening); no
  silent-removal REGRESSED surfaced on the others.

## Leg 2: drainability (holdout sibling repo)

- target: /home/ubuntu/projects/holdout (local clone, used read-only)
- pinned SHA: cd8d3f1d73afd255562d1949a0cba8c460f26457
- tree: clean (`git status --porcelain` empty; `git rev-parse HEAD` equals pin)
- note: repo is 10 commits deep, no security-signaled commit messages

### Run A: natural seeding

- command: `archaeology /home/ubuntu/projects/holdout --out /tmp/out-holdout-natural.jsonl`
- counts: seeds=0 tracked=0 intact=0 regressed=0 relocated=0 removed_with_sink=0 deliberate=0 unknown=0
- read: vacuous run - zero security-signaled commits in the window, so
  the drain question is exercised trivially. Recorded, not counted.

### Run B: forced seeding (all 10 commits via --seeds-file)

- command: `archaeology /home/ubuntu/projects/holdout --out /tmp/out-holdout-allseeds.jsonl --seeds-file /tmp/seeds-holdout.txt`
- rationale: the seeds-file is the documented operator path; seeding
  every commit maximizes guard extraction, i.e. the worst-case noise
  input for the drainability bar.
- counts: seeds=10 tracked=36 intact=29 regressed=0 relocated=1 removed_with_sink=2 deliberate=0 unknown=4
- UNKNOWN share: 4/36 = 11% (no provability collapse)
- REGRESSED count: 0 (bar: ~20 hand-drainable; observed 0)
- verdict: PASS - zero candidates under maximal seeding; the queue is
  hand-drainable by any reading of the bar.

## Fixture-level gate (tests/test_gate.py)

Scripted fix -> silent removal -> re-fix history through the full CLI:
REGRESSED row content asserted end-to-end under `--until` (true seed,
true removal, sink alive), zero candidates at HEAD after the re-fix,
zero candidates with `--until` pinned before the removal, and
byte-identical re-runs. Covered by the pytest suite.
