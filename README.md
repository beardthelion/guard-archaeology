# guard-archaeology

Finds security guards a codebase added and later silently lost. Spec-first; see SPEC.md.

## Usage

```
archaeology <repo-root> [--out <path>] [--seeds-file <path>] \
    [--since <rev>] [--until <rev>] [--caller-depth 2] \
    [--exposure-file <path>] [--also-md]
```

Runs against a local clone and writes `.clawpatch/archaeology.jsonl` under the target root (or `--out`), one JSON row per line: a `type:"run"` header with counts by class, `type:"error"` rows for per-seed/per-commit failures, and one `type:"candidate"` row per REGRESSED site.

- `--seeds-file`: newline-separated fix-commit SHAs, optionally `SHA ADVISORY-ID`.
- `--since`/`--until`: rev bounds on tracked history (ancestors of `--until`, minus `--since` ancestry). These are rev bounds, not git's date flags.
- `--caller-depth`: how far up the caller chain a guard must be provably absent before REGRESSED is allowed (default 2).
- `--exposure-file`: JSON map `"path:function" -> "untrusted|internal|unknown"`.
- `--also-md`: also write a markdown render beside the JSONL.

Stdout prints a one-line counts summary; exit is 0 on success including the zero-candidate case.
