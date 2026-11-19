# guard-archaeology

Walks a repository's git history to find security guards that were added, usually by a fix, and later removed while the dangerous operation they protected is still there. Each candidate comes with three links of evidence: the commit that added the guard, the commit that removed it, and the unguarded code as it stands now.

Candidates, not findings. Every row needs manual triage.

## Why

Fix regressions are a real, recurring bug class: a bounds check, path check or auth check lands in a security fix, then a refactor or rewrite drops it. Patch history tells you what was fixed, not what quietly unfixed itself. guard-archaeology seeds from fix commits, tracks each guard forward with `git log -G` pickaxe searches over the file's rename lineage, and classifies what happened to it. It is deterministic: no model judgment in the verdict path, and a weak evidence chain closes quietly instead of being reported.

It reads `.py`, `.go`, `.rs`, `.ts` and `.js` files. A statement only counts as a guard when a catalogued sink (filesystem, process, network, parse or similar operation) is reachable after it in the same function, an immediate same-file callee, or an immediate same-file caller.

## Install

Python 3.10 or newer, no runtime dependencies. Needs `git` on PATH.

```bash
git clone https://github.com/beardthelion/guard-archaeology
cd guard-archaeology
pip install -e '.[dev]'
archaeology --help
```

## Example

A three-commit repo: a path-traversal fix adds `if ".." in name: raise`, and a later "simplify" commit removes it.

```
$ archaeology ./demo --out out.jsonl
seeds=1 tracked=1 intact=0 regressed=1 relocated=0 removed_with_sink=0 deliberate=0 unknown=0
```

The candidate row (trimmed):

```json
{"type": "candidate", "id": "archaeology-allowlist-c8e8d71d6a",
 "sink": {"path": "app.py", "function": "serve", "line": 3, "operation": "os.path.join("},
 "missing_guard": {"family": "allowlist", "shape": "conditional-rejection",
                   "raw_text": "    if \"..\" in name:\n        raise ValueError(\"bad path\")"},
 "seed": {"sha": "61ac34f9...", "advisory": null},
 "removal": {"sha": "45306714...", "subject": "simplify serve"},
 "exposure": "unknown", "holdout": null}
```

## Usage

```
archaeology <repo-root> [--out <path>] [--seeds-file <path>] \
    [--since <rev>] [--until <rev>] [--caller-depth 2] \
    [--seeds-mode advisory|message|all] [--include-test-seeds] \
    [--max-seeds N] [--exposure-file <path>] [--also-md]
```

Runs against a local clone. No network access, no target code is executed; the pipeline is subprocessed `git` over the clone's own history.

### Flags

- `repo-root`: path to a local clone of the target repository.
- `--out`: output path, default `<repo-root>/.clawpatch/archaeology.jsonl`. Written atomically (temp + rename), so a re-run diffs clean.
- `--seeds-file`: newline-separated fix-commit SHAs, optionally `SHA ADVISORY-ID`. Advisory ids propagate to candidate rows. A listed SHA that does not resolve inside the window produces a `type:"error"` row; it is never dropped silently.
- `--since`/`--until`: rev bounds on tracked history (ancestors of `--until`, minus `--since` ancestry). These are rev bounds, not git's date flags: `--until U` replays history "as of U", which is how a removed-then-refixed guard is demonstrated.
- `--caller-depth`: how far up the caller chain a guard must be provably absent before REGRESSED is allowed (default 2). Unprovable degrades to UNKNOWN, never REGRESSED.
- `--seeds-mode`: `advisory` (default) seeds only CVE/GHSA-linked commits, seeds-file entries, and security-marked refs. `message`/`all` also harvest fix-verb x security-term commit messages; that harvest is noisier and off by default.
- `--include-test-seeds`: keep message-signal seeds whose entire diff touches test/fixture/vendored paths. Off by default, so seeding skews to runtime fixes.
- `--max-seeds N`: cap the seed list after collection and dedup (default 0 = unbounded). Prints `seeds capped at N of M` on stderr. Use on very large histories when a full pass is not budgeted.
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

Every tracked guard closes as exactly one of: INTACT (present at the boundary, counted, never reported), REGRESSED (reported), RELOCATED, REMOVED-WITH-SINK, DELIBERATE, or UNKNOWN. Rows are candidates for manual triage, not findings.

Candidate rows are runtime-only: guards whose sink lives on a test/fixture path are classified but never emitted. Reachability counts framework dispatch registration (`add_route`, `@app.route`, `router.get`, `HandleFunc`, and similar bindings) as a caller edge, so a registered handler can prove out to REGRESSED; bindings the shape tables do not cover stay UNKNOWN.

## Tests

```bash
pytest -q
```

[docs/gate-results.md](docs/gate-results.md) and [VERDICT.md](VERDICT.md) record the known-answer gate on a public project (a historic static-file path guard that was removed and later re-fixed, found as REGRESSED with the right seed and removal commits, with a clean negative control) and runs on two large public Python projects.

## Limitations

- Low yield so far: on the two large real projects in VERDICT.md, every seed mode produced zero REGRESSED rows. Hand checks of the near misses showed relocations and renames, not silent losses.
- Language handling is lexical (pattern tables per language), not a full parser. Bindings and sinks the tables do not cover end as UNKNOWN.
- Message-mode seeding on very large histories runs tens of minutes in one process; use `--max-seeds` or seeds files.
- Candidate rows do not include the evidence for why caller coverage was judged absent.
- `siblings` is always empty in v1.

Design: [SPEC.md](SPEC.md).

## Related tools

- [holdout](https://github.com/beardthelion/holdout): finds sites that break a project's current guard consensus; its rows are cross-referenced here when present
- [release-surface-diff](https://github.com/beardthelion/release-surface-diff): flags guards added or removed between two release tags
- [cve-variant-sweep](https://github.com/beardthelion/cve-variant-sweep): turns guard-adding fixes into Semgrep rules for variant hunting
- [autocatalytic-harness](https://github.com/beardthelion/autocatalytic-harness): the audit harness that owns the `.clawpatch/` directory this tool reads and writes

## License

MIT. See [LICENSE](LICENSE).
