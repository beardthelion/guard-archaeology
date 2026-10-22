"""CLI entry point: archaeology <repo-root> [flags].

Pipeline stages are wired as module-level functions so later units can
fill them in without reshaping run(): collect_seeds -> extract_guards ->
track_guards -> classify -> build_rows -> write_outputs.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from dataclasses import asdict, dataclass

from . import extract, gitlog, seeds, track


class ArchaeologyError(Exception):
    pass


@dataclass
class RunCounts:
    seeds: int = 0
    tracked: int = 0
    intact: int = 0
    regressed: int = 0
    relocated: int = 0
    removed_with_sink: int = 0
    deliberate: int = 0
    unknown: int = 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="archaeology",
        description="Finds security guards a codebase added and later "
        "silently lost. Emits REGRESSED candidates for drain.",
    )
    p.add_argument("repo_root", help="local clone of the target repository")
    p.add_argument(
        "--out",
        default=None,
        help="JSONL output path (default <repo-root>/.clawpatch/"
        "archaeology.jsonl)",
    )
    p.add_argument(
        "--seeds-file",
        default=None,
        help="newline-separated fix-commit SHAs, optionally 'SHA ADVISORY-ID'",
    )
    p.add_argument(
        "--since",
        default=None,
        help="lower rev bound: exclude this rev and its ancestors",
    )
    p.add_argument(
        "--until",
        default=None,
        help="upper rev bound: restrict history to ancestors of this rev",
    )
    p.add_argument("--caller-depth", type=int, default=2)
    p.add_argument("--exposure-file", default=None)
    p.add_argument("--also-md", action="store_true")
    return p


def _fail(msg: str, code: int = 2) -> int:
    print(f"archaeology: stopped: {msg}", file=sys.stderr)
    return code


def _parse_args(argv):
    args = build_parser().parse_args(argv)
    if args.caller_depth < 0:
        raise ArchaeologyError("--caller-depth must be >= 0")
    return args


# --- pipeline seams -----------------------------------------------------------
# collect_seeds lives in seeds.py (U2). The remaining stages are stubs that
# later units replace; run() already calls them in final order.


def extract_guards(seed_set, repo):
    """U3: seed diffs -> guard records (extract.Extraction)."""
    return extract.extract_guards(repo, seed_set)


def track_guards(records, repo, until=None):
    """U4: guard records -> INTACT or candidate-removal outcomes."""
    return track.track_guards(repo, records, until=until)


def classify_removals(outcomes, repo, caller_depth=2) -> list:
    """U5: candidate removals -> five-verdict classification."""
    return []


def classify_counts(seed_set, records, outcomes, verdicts) -> RunCounts:
    """Fold stage outputs into the run-summary counts.

    INTACT is assigned by tracking (R6) and counted from the tracking
    outcomes; the five removal verdicts come from classify's output. A
    non-intact outcome with no verdict yet counts as unknown (U5 pending).
    """
    outcomes = outcomes or ()
    verdicts = verdicts or ()
    counts = RunCounts(seeds=len(seed_set.seeds), tracked=len(records))
    for o in outcomes:
        if getattr(o, "status", None) == "intact":
            counts.intact += 1
    for v in verdicts:
        name = getattr(v, "verdict", None)
        key = str(name).lower().replace("-", "_") if name else "unknown"
        if key == "regressed":
            counts.regressed += 1
        elif key == "relocated":
            counts.relocated += 1
        elif key == "removed_with_sink":
            counts.removed_with_sink += 1
        elif key == "deliberate":
            counts.deliberate += 1
        else:
            counts.unknown += 1
    counts.unknown += max(
        len(outcomes) - counts.intact - len(verdicts), 0
    )
    return counts


def build_rows(counts: RunCounts, unresolvable=(), extract_errors=(),
               track_errors=()) -> list:
    """JSONL rows: the run header plus per-failure error rows.

    U6 extends this with candidate rows in the drain schema.
    """
    rows = [{"type": "run", **asdict(counts)}]
    for u in unresolvable:
        rows.append(
            {
                "type": "error",
                "stage": "seeds",
                "seed": u.sha,
                "advisory_id": u.advisory_id,
                "reason": "unresolvable-in-window",
            }
        )
    for e in (*extract_errors, *track_errors):
        rows.append({"type": "error", **e})
    return rows


def render_markdown(counts: RunCounts) -> str:
    """U6 stub: markdown render of the same row set."""
    lines = ["# archaeology run", ""]
    for key, val in asdict(counts).items():
        lines.append(f"- {key}: {val}")
    lines.append("")
    return "\n".join(lines)


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
                  md_text: str = None) -> None:
    text = "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows)
    _atomic_write(out_path, text)
    if also_md:
        md_path = os.path.splitext(out_path)[0] + ".md"
        _atomic_write(md_path, md_text or "")


def summary_line(counts: RunCounts) -> str:
    c = asdict(counts)
    return (
        f"seeds={c['seeds']} tracked={c['tracked']} intact={c['intact']} "
        f"regressed={c['regressed']} relocated={c['relocated']} "
        f"removed_with_sink={c['removed_with_sink']} "
        f"deliberate={c['deliberate']} unknown={c['unknown']}"
    )


def run(
    repo_root: str,
    out: str = None,
    seeds_file: str = None,
    since: str = None,
    until: str = None,
    caller_depth: int = 2,
    exposure_file: str = None,
    also_md: bool = False,
) -> int:
    """Run the pipeline and write outputs; returns 0 or raises."""
    real = os.path.realpath(repo_root)
    if not os.path.isdir(real):
        raise ArchaeologyError(f"unreadable repo root: {repo_root}")
    if not gitlog.is_git_repo(real):
        raise ArchaeologyError(f"not a git repository: {repo_root}")
    if caller_depth < 0:
        raise ArchaeologyError("--caller-depth must be >= 0")

    out_path = out or os.path.join(real, ".clawpatch", "archaeology.jsonl")

    try:
        seed_set = seeds.collect_seeds(
            real, seeds_file=seeds_file, since=since, until=until
        )
    except (seeds.SeedsError, gitlog.GitError) as e:
        raise ArchaeologyError(str(e))

    extraction = extract_guards(seed_set, real)
    records = extraction.records
    tracking = track_guards(records, real, until=until)
    outcomes = tracking.outcomes
    verdicts = classify_removals(outcomes, real, caller_depth=caller_depth)
    counts = classify_counts(seed_set, records, outcomes, verdicts)
    rows = build_rows(
        counts, seed_set.unresolvable, extraction.errors, tracking.errors
    )

    try:
        write_outputs(
            rows,
            out_path,
            also_md=also_md,
            md_text=render_markdown(counts) if also_md else None,
        )
    except OSError as e:
        raise ArchaeologyError(f"cannot write output: {e}")

    print(summary_line(counts))
    return 0


def main(argv=None) -> int:
    try:
        args = _parse_args(argv)
    except ArchaeologyError as e:
        return _fail(str(e))
    try:
        return run(
            repo_root=args.repo_root,
            out=args.out,
            seeds_file=args.seeds_file,
            since=args.since,
            until=args.until,
            caller_depth=args.caller_depth,
            exposure_file=args.exposure_file,
            also_md=args.also_md,
        )
    except ArchaeologyError as e:
        return _fail(str(e))


if __name__ == "__main__":
    raise SystemExit(main())
