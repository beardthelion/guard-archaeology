"""CLI entry point: archaeology <repo-root> [flags].

run() wires the pipeline stages in order: collect_seeds ->
extract_guards -> track_guards -> classify_all -> build_rows ->
write_outputs.
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import asdict, dataclass

from . import classify, emit, exposure, extract, gitlog, seeds, track


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
    skipped: int = 0  # statements dropped at extraction (R5)


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
    return build_parser().parse_args(argv)


_VERDICT_KEYS = frozenset(
    {"regressed", "relocated", "removed_with_sink", "deliberate",
     "unknown"}
)


def classify_counts(seed_set, records, outcomes, verdicts) -> RunCounts:
    """Fold stage outputs into the run-summary counts.

    INTACT is assigned by tracking (R6) and counted from the tracking
    outcomes; the five removal verdicts come from classify's output. A
    non-intact outcome with no verdict still counts as unknown.
    """
    outcomes = outcomes or ()
    verdicts = verdicts or ()
    counts = RunCounts(seeds=len(seed_set.seeds), tracked=len(records))
    for o in outcomes:
        if o.status == "intact":
            counts.intact += 1
    for v in verdicts:
        name = v.verdict if v.verdict in _VERDICT_KEYS else "unknown"
        setattr(counts, name, getattr(counts, name) + 1)
    counts.unknown += max(
        len(outcomes) - counts.intact - len(verdicts), 0
    )
    return counts


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
    out: str | None = None,
    seeds_file: str | None = None,
    since: str | None = None,
    until: str | None = None,
    caller_depth: int = 2,
    exposure_file: str | None = None,
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

    # --since/--until reach git argv as revspecs: a value spelled like a
    # flag could smuggle a git option in (e.g. --until=--output=/path),
    # so it is rejected before any use and must resolve to a commit
    for flag, val in (("--since", since), ("--until", until)):
        if val is None:
            continue
        if val.startswith("-"):
            raise ArchaeologyError(f"{flag} is not a rev: {val}")
        if gitlog.resolve_commit(real, val) is None:
            raise ArchaeologyError(f"{flag} does not resolve: {val}")

    out_path = out or os.path.join(real, ".clawpatch", "archaeology.jsonl")
    out_dir = os.path.dirname(os.path.abspath(out_path))
    if out_dir == real or out_dir.startswith(real + os.sep):
        # an output path spelled inside the target root must really land
        # there: a symlinked directory (e.g. .clawpatch -> /tmp/x) must
        # not redirect the write outside it
        real_dir = os.path.realpath(out_dir)
        if real_dir != real and not real_dir.startswith(real + os.sep):
            raise ArchaeologyError(
                f"output directory escapes target root: {out_dir}"
            )

    try:
        seed_set = seeds.collect_seeds(
            real, seeds_file=seeds_file, since=since, until=until
        )
    except (seeds.SeedsError, gitlog.GitError) as e:
        raise ArchaeologyError(str(e))

    extraction = extract.extract_guards(real, seed_set)
    records = extraction.records
    tracking = track.track_guards(real, records, until=until)
    outcomes = tracking.outcomes
    classification = classify.classify_all(
        real, outcomes, caller_depth=caller_depth
    )
    counts = classify_counts(
        seed_set, records, outcomes, classification.verdicts
    )
    counts.skipped = extraction.skipped
    emap = exposure.load_exposure(real, exposure_file=exposure_file)
    hidx = emit.load_holdout_rows(real)
    rows = emit.build_rows(
        real,
        counts,
        classification.verdicts,
        unresolvable=seed_set.unresolvable,
        extract_errors=extraction.errors,
        track_errors=tracking.errors,
        classify_errors=classification.errors,
        emap=emap,
        holdout=hidx,
    )
    candidates = [r for r in rows if r.get("type") == "candidate"]

    try:
        emit.write_outputs(
            rows,
            out_path,
            also_md=also_md,
            md_text=(
                emit.render_markdown(counts, candidates)
                if also_md
                else None
            ),
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
