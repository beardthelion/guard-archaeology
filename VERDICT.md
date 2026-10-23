# Usefulness audit, round 2

Re-run of the v1 usefulness audit after the fix batch. All targets are
fresh clones under /tmp; every command shown verbatim. Date: 2026-10-22.

## What changed since the failed audit

- Default seeding is advisory-only (CVE/GHSA, seeds-file, marked refs);
  the fix-verb harvest moved behind `--seeds-mode message|all`.
- Test-only and merge-rollup seeds are dropped; `--include-test-seeds`
  restores them.
- Candidate rows are runtime-only: guards whose sink lives on a
  test/fixture path are classified but never emitted.
- Framework dispatch registration (`add_route`, `@app.route`,
  `router.get`, `HandleFunc`, ...) counts as a caller edge, so a
  registered handler's coverage can prove out to REGRESSED instead of
  UNKNOWN.
- Blob reads are cached per run and bounded by a 256MB byte budget;
  vendored/venv paths are skipped in the caller corpus; `--max-seeds`
  bounds seed count.

## Gate (aiohttp known-answer) — PASS

`archaeology /tmp/gate-aiohttp --out /tmp/ga-out3.jsonl --seeds-file /tmp/seeds-aiohttp.txt --until 0e2d3ec48a950a2aacaf3f5d0d1f1597a1d5385b`

`seeds=49 tracked=2 intact=0 regressed=1 relocated=1 removed_with_sink=0 deliberate=0 unknown=0`

The documented anchor guard (`if filename.anchor: raise HTTPForbidden()`
in `StaticResource._handle`) emits REGRESSED with the true seed
(22973259) and removal (63961fa7) SHAs, sink live at
`aiohttp/web_urldispatcher.py:625` (`.joinpath(`). Negative control at
the removal's parent emits zero candidates (intact=2).

## Chia (Chia-Network/chia-blockchain)

- clone: /tmp/ga-chia, HEAD 796739af6 at run time
- advisory default: `seeds=6 tracked=16 intact=2 regressed=0 relocated=8
  removed_with_sink=3 deliberate=0 unknown=3` (~2 min)
- message mode: `seeds=84 tracked=22 intact=6 regressed=0 relocated=10
  removed_with_sink=3 deliberate=0 unknown=3` (~1 min)
- The 3 UNKNOWNs sit on test paths (`tests/wallet/...`) and could not
  emit candidates under the runtime-only rule regardless.
- REGRESSED yield: **0**

## Hermes (beardthelion/hermes-agent)

- clone: /tmp/ga-hermes, pinned to audited SHA
  1089d3315a68ff9692a866eb462f6421e3c02257
- stock advisory run: `seeds=65 tracked=35 intact=13 regressed=0
  relocated=1 removed_with_sink=9 deliberate=3 unknown=9`, ~2 min wall.
  The audit's stock run died at ~5 min; the same repo now completes in
  ~2 min under the advisory default. **F4 met.**
- message mode, first 500 of 1501 seeds (`--max-seeds 500`):
  `seeds=500 tracked=361 intact=110 regressed=0 relocated=21
  removed_with_sink=108 deliberate=26 unknown=96` (~60 min CPU)
- message mode, seeds 501-1501 via seeds-file:
  `seeds=1023 tracked=972 intact=587 regressed=0 relocated=50
  removed_with_sink=143 deliberate=25 unknown=166` (~90 min CPU)
- REGRESSED yield across all 1500+ message seeds: **0**

## Hand-verification of near-misses

Every plausible loss a direct scan surfaced was verified by hand and is
a relocation or rename, not a silent removal:

- `_WRITE_DENIED_SECRET_DIRS` (seed 1c0d95badb): folded into the shared
  protected-subpath table by b98ff81978 — relocated.
- `_resolve_skill_target` boundary check (seed e683c9db9): moved to
  `tools/path_security.validate_within_dir` by refactor 04c1c5d53f —
  relocated, still enforced.
- `_safe_plugin_api_relpath` (seed 8bf99227f): moved from
  `hermes_cli/web_server.py` to `web_server_dashboard.py` — rename, not
  loss.
- Cron script path guard (seed 931624fed): present at pin in
  `tools/cronjob_job_args.py`; refactored (d4cec15b47) and re-hardened
  (878b1d3d33) — intact.
- `_READ_DENIED_DIRS`, `_redact_assignments`, `mask_secret`,
  `_is_secret_config_key`, sudo-prompt callback: all intact at pin.

## Verdict on the acceptance bar

- Gate leg 1 (aiohttp known-answer as REGRESSED): **met** - the
  documented anchor regression emits REGRESSED at the pinned boundary,
  runtime sink, correct seed and removal SHAs, negative control clean.
- Runtime-only candidates (no test-file rows): **met** - the previous
  leg's test-assertion row is gone; the only REGRESSED is the runtime
  guard.
- Seed quality + runtime-only scope: **met** - advisory default plus
  test-path filtering removed the noisy rows the audit flagged.
- Stock-run perf on hermes (F4): **met** - the stock advisory run
  completes in ~2 min where the audit timed out at ~5 min.
- >=1 REGRESSED on hermes or chia (F3): **NOT met**. Across every seed
  mode and full coverage of hermes' ~1500 message seeds plus chia at two
  modes, the tool emits zero REGRESSED. Hand verification of every
  near-miss the scan surfaced confirmed relocations and renames, not
  silent losses - the tool's non-candidates are calibrated, and the
  honest read is that these two repos at these pins do not drop runtime
  guards silently. The bar stays open rather than being satisfied by a
  fabricated or mislabeled row.

## Residuals

- Message-mode seeding on a 25k-commit/1.5k-seed repo runs tens of
  minutes in the single-process CLI. Stock advisory runs are bounded
  (hermes ~2 min, chia ~2 min); `--max-seeds` exists for the heavy mode.
- UNKNOWN share on hermes message run was 96/361 (~27%) — mostly
  `lost-lineage:absent-unverified` (pickaxe produced no candidacy hit)
  and ambiguous same-name member mentions. Fail-quiet by contract.
- Candidate rows carry no evidence for why coverage was proven absent;
  `coverage:removal=`/`coverage:boundary=` detail stays in the verdict
  evidence, not the emitted row.
