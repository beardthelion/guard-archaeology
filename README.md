# guard-archaeology

Finds security guards a codebase added and later silently lost. Spec-first; see SPEC.md.

## Usage

```
archaeology <repo-root> [--out <path>] [--seeds-file <path>] \
    [--since <rev>] [--until <rev>] [--caller-depth 2] \
    [--exposure-file <path>] [--also-md]
```

Runs against a local clone. No network access, no target code is executed; the pipeline is subprocessed `git` over the clone's own history.

### Flags

- `repo-root`: path to a local clone of the target repository.
- `--out`: output path, default `<repo-root>/.clawpatch/archaeology.jsonl`. Written atomically (temp + rename), so a re-run diffs clean.
- `--seeds-file`: newline-separated fix-commit SHAs, optionally `SHA ADVISORY-ID`. Advisory ids propagate to candidate rows. A listed SHA that does not resolve inside the window produces a `type:"error"` row; it is never dropped silently.
- `--since`/`--until`: rev bounds on tracked history (ancestors of `--until`, minus `--since` ancestry). These are rev bounds, not git's date flags: `--until U` replays history "as of U", which is how a removed-then-refixed guard is demonstrated.
- `--caller-depth`: how far up the caller chain a guard must be provably absent before REGRESSED is allowed (default 2). Unprovable degrades to UNKNOWN, never REGRESSED.
- `--exposure-file`: JSON map `"path:function" -> "untrusted|internal|unknown"`.
- `--also-md`: also write a markdown render beside the JSONL (`<out>` with `.md` suffix).

Stdout prints a one-line counts summary: `seeds=N tracked=T intact=I regressed=X relocated=L removed_with_sink=S deliberate=D unknown=U`. Exit is 0 on success including the zero-candidate case; nonzero on unreadable root, bad flag, or output-write failure.

### Output contract

The JSONL holds three row types, in order:

- `type:"run"`: header with counts by class (tracked, intact, regressed, relocated, removed_with_sink, deliberate, unknown), so an empty candidate list reads as checked, not skipped.
- `type:"candidate"`: one per REGRESSED site. Fields: stable `id` (`archaeology-<family>-<sha10>`), `sink {path,function,line,operation}` at the boundary commit, `missing_guard {family,shape,signature,raw_text}`, `seed {sha,advisory}`, `removal {sha,subject}`, `current` (unguarded sink excerpt at boundary), `exposure`, `siblings` (always `[]` in v1), `entry`, and `holdout`. Sorted by removal commit date, then sink path, then seed SHA; identical input history produces a byte-identical file.
- `type:"error"`: per-seed/per-file/per-commit failures (unresolvable seed, unreadable blob, classify failure); the affected guard degrades to UNKNOWN and the run continues.

Exposure resolution order: `--exposure-file` map, else `<repo-root>/.clawpatch/scope-boundary.md` `TAINT: yes` lines, else `unknown`. `unknown` is its own bucket, never assumed. If `<repo-root>/.clawpatch/holdout.jsonl` exists, candidates whose sink (path + function) matches a holdout row carry a `holdout` cross-reference `{id,family,rank_score}`.

Auto-read files under `<repo-root>/.clawpatch/` are realpath-confined to the target root; malformed or oversized input warns on stderr and is ignored.

## Verdicts

Every tracked guard closes as exactly one of: INTACT (present at the boundary, counted, never reported), REGRESSED (reported), RELOCATED, REMOVED-WITH-SINK, DELIBERATE, or UNKNOWN. Rows are candidates for kill-before-debug drain, not findings.
