# Gate results

R21 two-leg validation gate, refreshed after the v1 usefulness audit.
Targets pinned by SHA, trees verified clean before each run (KTD12).
Commands are verbatim; `--out` kept all writes outside the target
clones. Date of record: 2026-10-22.

## Leg 1: known-answer (aio-libs/aiohttp)

- target: https://github.com/aio-libs/aiohttp (Python, active)
- clone: `<aiohttp-clone>` (full clone, not shallow)
- pinned SHA: 7275bea9eae591d5246b8fd9e2e9ba004b6f30f7 (master@HEAD at clone time)
- tree: clean (`git status --porcelain` empty; `git rev-parse HEAD` equals pin)
- seeds-file: `2297325962412113b412352a4d2c8a0f64b5bc71 FIXTURE-aiohttp-anchor`
- command: `archaeology <aiohttp-clone> --out <out>.jsonl --seeds-file <seeds-aiohttp.txt> --until 0e2d3ec48a950a2aacaf3f5d0d1f1597a1d5385b`
- `--until` boundary: 0e2d3ec48a950a2aacaf3f5d0d1f1597a1d5385b, parent of
  f049588a ("Block absolute paths in static files"), i.e. just before the
  second fix
- counts: seeds=49 tracked=2 intact=0 regressed=1 relocated=1
  removed_with_sink=0 deliberate=0 unknown=0
- UNKNOWN share: 0/2
- verdict: **PASS**. The documented regression emits REGRESSED with the
  true seed SHA and true removal SHA. Details below.

### The documented case (verified)

The known-answer story:

- seed: 2297325962412113b412352a4d2c8a0f64b5bc71 (2018-02-22, "Prevent
  Windows absolute URLs in static files") adds `if filename.anchor:
  raise HTTPForbidden()` to `StaticResource._handle`
- silent removal: 63961fa77fa2443109f25c3d8ab94772d3878626 (2026-01-03,
  "Reject static URLs that traverse outside static root") removes the
  anchor check inside a different fix commit; no removal wording
- re-fix: f049588a8ab5b6b6757677b539845c63698d61f7 (2026-02-22) restores
  absolute-path rejection

Emitted row `archaeology-bounds-ffd710f270`: family `bounds`, sink
`StaticResource._handle` at `aiohttp/web_urldispatcher.py:625`,
operation `.joinpath(`, seed and removal SHAs as above. The row's
`current` excerpt shows the sink live at the boundary and the guard
absent.

What changed since the first gate attempt (all verified):

- the member-access guard cue (`if obj.attr:`) now extracts this shape;
- dispatch registration now counts as a caller edge, so a handler bound
  via `add_route("GET", self._handle, self, ...)` and
  `self._app._handle` handoffs is provably reachable rather than
  UNPROVABLE, and family absence over function + module scope yields
  `absent` at both the removal and boundary commits;
- the coverage rule emits REGRESSED when the family is absent at the
  boundary whether or not a same-family replacement briefly covered the
  removal commit (the documented relocate-then-lose shape);
- test-file guards no longer reach candidate rows, so the only
  REGRESSED here is the runtime guard, not the earlier test-assertion
  artifact.

Second tracked guard on this seed (context for the counts): the
constant-limit record (`filename = request.match_info["filename"]`)
classifies RELOCATED - same-family path checks added at the removal
commit still cover the path at the boundary.

### Negative control

Same repo, same seeds-file, `--until` at the removal commit's parent
(7a067d1905e1eeb921a50010dd0004990dbb3bf0), where the guard is still
present:

- command: `archaeology <aiohttp-clone> --out <neg>.jsonl --seeds-file <seeds-aiohttp.txt> --until 7a067d1905e1eeb921a50010dd0004990dbb3bf0`
- counts: seeds=42 tracked=2 intact=2 regressed=0 relocated=0
  removed_with_sink=0 deliberate=0 unknown=0
- read: zero candidates where no silent loss exists. Both guards
  classify INTACT.

Second negative control (no signaled commits): holdout under natural
advisory seeding returns seeds=0 tracked=0 with an empty candidate
file.

## Leg 2: drainability (holdout sibling repo)

- target: beardthelion/holdout (local clone, used read-only)
- pinned SHA: cd8d3f1d73afd255562d1949a0cba8c460f26457
- tree: clean

### Run A: natural seeding (advisory default)

- command: `archaeology <holdout-clone> --out <out>.jsonl`
- counts: seeds=0 tracked=0 intact=0 regressed=0 relocated=0
  removed_with_sink=0 deliberate=0 unknown=0
- read: vacuous - no advisory-signaled commits in the window.

### Run B: forced seeding (all 10 commits via --seeds-file)

- command: `archaeology <holdout-clone> --out <forced>.jsonl --seeds-file <seeds-holdout.txt>`
- counts: seeds=10 tracked=40 intact=33 regressed=0 relocated=1
  removed_with_sink=2 deliberate=0 unknown=4
- UNKNOWN share: 4/40 = 10%
- verdict: PASS - zero candidates under maximal seeding.

## Fixture-level gate (tests/test_gate.py)

Scripted fix -> silent removal -> re-fix history through the full CLI:
REGRESSED row content asserted end-to-end under `--until` (true seed,
true removal, sink alive), zero candidates at HEAD after the re-fix,
zero candidates with `--until` pinned before the removal, and
byte-identical re-runs. Covered by the pytest suite.
