"""Emission: .clawpatch/archaeology.jsonl plus optional markdown (R12-R16).

Row contract (KTD5, mirroring holdout's drain shape):

- ``type:"run"`` header carrying the R13 counts by class.
- one ``type:"candidate"`` row per REGRESSED verdict: stable
  ``archaeology-<family>-<sha10>`` id from (family, sink path, sink
  function, seed SHA), sink {path,function,line,operation} at the
  boundary, missing_guard details, seed {sha,advisory},
  removal {sha,subject}, the unguarded-sink excerpt at the boundary,
  exposure bucket, ``siblings`` (always [] in v1), ``entry`` (from
  exposure resolution else null), and the ``holdout`` cross-ref (R15).
- ``type:"error"`` rows for per-file/per-commit failures across the
  seed/extract/track/classify stages (R13).

Output order is header, candidates sorted by (removal commit date, sink
path, seed SHA, row id), then errors (KTD10). ``--out`` is written
atomically (temp + rename) so a re-run on the same clone diffs clean
(R18).
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import asdict, is_dataclass

from . import callers, exposure, gitlog, shapes

_EXCERPT_CTX = 3  # context lines each side of the sink op in "current"
_MAX_HOLDOUT_BYTES = 16 * 1024 * 1024


def norm_qualname(name) -> str:
    """Dotted qualname for cross-tool joins: '::' paths read as dots so a
    Rust 'mod::fn' matches the same name spelled 'mod.fn'."""
    return (name or "").replace("::", ".").strip()


def row_id(family: str, sink_path: str, sink_function: str,
           seed_sha: str, signature: str = "") -> str:
    """archaeology-<family>-<sha10> of (family, sink path, sink function,
    seed SHA, guard signature); stable across re-runs (KTD10). The
    signature rides in the key so two guards on one sink from one seed
    cannot collide."""
    key = "|".join(
        [family or "", sink_path or "", sink_function or "",
         seed_sha or "", signature or ""]
    )
    digest = hashlib.sha256(key.encode()).hexdigest()[:10]
    return f"archaeology-{family}-{digest}"


# --- holdout cross-reference ------------------------------------------------


def load_holdout_rows(repo_root: str) -> dict:
    """Holdout cross-refs keyed (sink path, dotted qualname), or {}.

    <target>/.clawpatch/holdout.jsonl is untrusted input: it is read only
    when realpath-confined to the target root, and an oversized,
    unreadable, or malformed file warns and is ignored, never fails the
    run (R15, KTD11).
    """
    path = exposure.confined_path(
        repo_root, os.path.join(".clawpatch", "holdout.jsonl")
    )
    if path is None:
        return {}
    try:
        if os.path.getsize(path) > _MAX_HOLDOUT_BYTES:
            exposure._warn("ignoring oversized holdout.jsonl")
            return {}
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except (OSError, ValueError, RecursionError) as e:
        # UnicodeDecodeError is a ValueError; an unreadable or non-text
        # file warns and is ignored (KTD11)
        exposure._warn(f"ignoring unreadable holdout.jsonl: {e}")
        return {}
    idx = {}
    bad = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, RecursionError):
            bad += 1
            continue
        if not isinstance(row, dict) or row.get("type") != "candidate":
            continue
        sink = row.get("sink")
        if not isinstance(sink, dict):
            continue
        spath, sfunc = sink.get("path"), sink.get("function")
        if not spath or not sfunc:
            continue
        key = (spath, norm_qualname(sfunc))
        if key not in idx:
            idx[key] = {
                "id": row.get("id"),
                "family": row.get("family"),
                "rank_score": row.get("rank_score"),
            }
    if bad:
        exposure._warn(f"holdout.jsonl: skipped {bad} malformed line(s)")
    return idx


# --- candidate rows -----------------------------------------------------------


def _boundary_sink(repo, outcome):
    """(line, excerpt) of the sink op in the boundary file.

    Falls back to the tracker's recorded excerpt and None line when the
    boundary file cannot be re-materialized.
    """
    rec = outcome.guard
    text = None
    if outcome.boundary_path and outcome.boundary_sha:
        try:
            got = gitlog.show_file_cached(
                repo, outcome.boundary_sha, outcome.boundary_path
            )
        except gitlog.GitError:
            got = gitlog.NOT_FOUND
        # an oversized boundary file keeps the recorded excerpt rather
        # than paying for a second materialization pass
        if got is not gitlog.NOT_FOUND and len(got) <= gitlog.MAX_BLOB_BYTES:
            text = got
    if text is None:
        return None, outcome.boundary_excerpt
    i = callers.locate_sink_line(
        text, outcome.boundary_path or rec.sink_path,
        rec.sink_function, rec.sink_op,
    )
    if i is not None:
        lines = text.splitlines()
        lo = max(0, i - _EXCERPT_CTX)
        excerpt = "\n".join(lines[lo : i + _EXCERPT_CTX + 1])
        return i + 1, excerpt
    return None, outcome.boundary_excerpt


def candidate_row(repo, verdict, emap, hidx) -> dict:
    """One REGRESSED verdict -> a drain-format candidate row (R12)."""
    o = verdict.outcome
    rec = o.guard
    sink_path = o.boundary_path or rec.sink_path
    line, excerpt = _boundary_sink(repo, o)
    if line is None:
        line = rec.sink_line
    bucket, entry = exposure.lookup(
        emap or {}, sink_path, rec.sink_function
    )
    hold = (hidx or {}).get(
        (sink_path, norm_qualname(rec.sink_function))
    )
    return {
        "type": "candidate",
        "id": row_id(
            rec.family, sink_path, rec.sink_function, rec.seed_sha,
            rec.signature,
        ),
        "family": rec.family,
        "sink": {
            "path": sink_path,
            "function": rec.sink_function,
            "line": line,
            "operation": rec.sink_op,
        },
        "missing_guard": {
            "family": rec.family,
            "shape": rec.shape,
            "signature": rec.signature,
            "raw_text": rec.raw_text,
        },
        "seed": {"sha": rec.seed_sha, "advisory": rec.advisory_id},
        "removal": {
            "sha": verdict.removal_sha,
            "subject": verdict.removal_subject,
        },
        "current": excerpt,
        "exposure": bucket,
        "siblings": [],
        "entry": entry,
        "holdout": hold,
    }


def _candidate_sort_key(repo, verdict):
    """(removal commit date, sink path, seed SHA, row id) per KTD10."""
    sha = verdict.removal_sha
    date = 0
    if sha:
        try:
            date = gitlog.commit(repo, sha).committer_time
        except gitlog.GitError:
            date = 0
    rec = verdict.outcome.guard
    sink_path = verdict.outcome.boundary_path or rec.sink_path
    return (
        date,
        sink_path,
        rec.seed_sha or "",
        row_id(
            rec.family, sink_path, rec.sink_function, rec.seed_sha,
            rec.signature,
        ),
    )


def build_rows(repo, counts, verdicts, unresolvable=(), extract_errors=(),
               track_errors=(), classify_errors=(), emap=None,
               holdout=None) -> list:
    """The full JSONL row set: run header, sorted REGRESSED candidates,
    then per-stage error rows (R12, R13, R18)."""
    cdict = asdict(counts) if is_dataclass(counts) else dict(counts)
    regressed = [
        v for v in verdicts or ()
        if getattr(v, "verdict", None) == "regressed"
    ]
    regressed.sort(key=lambda v: _candidate_sort_key(repo, v))
    rows = [{"type": "run", **cdict}]
    emitted = 0
    for v in regressed:
        o = v.outcome
        sink_path = o.boundary_path or o.guard.sink_path
        if shapes.is_test_path(sink_path):
            # a guard whose sink lives in test/support code is never a
            # drain candidate (assert-shape guards on test files were
            # v1's false-positive class). The verdict itself stays in
            # the verdicts list; only the row and the header count drop.
            continue
        rows.append(candidate_row(repo, v, emap, holdout))
        emitted += 1
    if emitted != cdict.get("regressed"):
        # the header counts what was emitted, so a filtered test-sink
        # regression cannot report regressed>0 while producing no row
        rows[0]["regressed"] = emitted
    for u in unresolvable or ():
        rows.append(
            {
                "type": "error",
                "stage": "seeds",
                "seed": u.sha,
                "advisory_id": u.advisory_id,
                "reason": "unresolvable-in-window",
            }
        )
    for e in (*extract_errors, *track_errors, *classify_errors):
        rows.append({"type": "error", **e})
    return rows


# --- markdown (R16) -----------------------------------------------------------


def _md_clean(s) -> str:
    """Strip control characters from a value before markdown interpolation;
    repo paths and subjects are untrusted input (a newline could inject a
    forged report line)."""
    return "".join(c if c >= " " else " " for c in str(s)).replace("`", "'")


def render_markdown(counts, candidates) -> str:
    """Run counts, then one section per guard family present, candidates
    numbered in output order."""
    cdict = asdict(counts) if is_dataclass(counts) else dict(counts)
    lines = ["# archaeology candidates", ""]
    for key, val in cdict.items():
        lines.append(f"- {key}: {val}")
    lines.append("")
    fams = []
    for c in candidates:
        if c["family"] not in fams:
            fams.append(c["family"])
    for fam in fams:
        lines.append(f"## {_md_clean(fam)}")
        lines.append("")
        n = 0
        for c in candidates:
            if c["family"] != fam:
                continue
            n += 1
            s = c["sink"]
            removal = c["removal"]["sha"] or "unknown"
            lines.append(
                f"{n}. `{_md_clean(s['path'])}:"
                f"{_md_clean(s['function'])}:{s['line']}` "
                f"op `{_md_clean(s['operation'])}`; missing guard "
                f"`{_md_clean(c['missing_guard']['signature'])}`; "
                f"exposure={c['exposure']}, "
                f"seed={c['seed']['sha']}, removal={removal}"
            )
        lines.append("")
    if not candidates:
        lines.append("No regressed candidates.")
        lines.append("")
    return "\n".join(lines)


# --- writes -------------------------------------------------------------------


def _atomic_write(path: str, text: str) -> None:
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".archaeology-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_outputs(rows: list, out_path: str, also_md: bool = False,
                  md_text: str | None = None) -> None:
    text = "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows)
    _atomic_write(out_path, text)
    if also_md:
        md_path = os.path.splitext(out_path)[0] + ".md"
        _atomic_write(md_path, md_text or "")
