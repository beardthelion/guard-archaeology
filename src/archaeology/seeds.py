"""Seed collection: message signals, --seeds-file SHAs, security-tagged refs.

The seed set is the noise gate: only commits inside the R2 bounded window
with a security signal, an operator-supplied advisory entry, or a
security-marked ref become guard origins.

``seeds_mode`` sets the message harvest's breadth: ``advisory`` (the
default) keeps only advisory-linked commits (a CVE/GHSA id in subject or
body); ``message`` and ``all`` additionally harvest the noisier
fix-verb x security-term pairing. Seeds-file entries and marked refs are
unaffected by the mode: both are explicit provenance.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from . import exposure, gitlog, shapes

_MAX_SEEDS_BYTES = 1024 * 1024
_MAX_SEEDS_LINES = 10_000

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
GHSA_RE = re.compile(r"\bGHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}\b",
                     re.IGNORECASE)

# Fix verbs paired with a security term on the subject line. Reverts are
# excluded: revert-of-fix is a removal-classification signal, not a seed.
FIX_VERB_RE = re.compile(
    r"\b(fix|fixes|fixed|fixing|close|closes|closed|patch|patches|patched|"
    r"resolve|resolves|resolved|prevent|prevents|prevented|block|blocks|"
    r"blocked|address|addresses|addressed|harden|hardens|hardened)\b",
    re.IGNORECASE,
)

# Security vocabulary stems. The auth stem excludes 'author(s)' so routine
# maintainer-list commits do not seed.
SEC_TERM_RE = re.compile(
    r"\b(secur\w*|vuln\w*|overflow\w*|injection\w*|bypass\w*|traversal\w*|"
    r"auth(?!or[sd]?\b)\w*|saniti[sz]\w*|escap\w*|bounds?\w*|validat\w*)\b",
    re.IGNORECASE,
)

# Refs whose short name marks them as security-relevant (tag or branch).
SECURITY_REF_RE = re.compile(r"(?i)(secur|cve|ghsa|vuln)")

SOURCE_SEEDS_FILE = "seeds-file"
SOURCE_MESSAGE = "message"
SOURCE_REF = "ref"

SEEDS_MODES = ("advisory", "message", "all")

# A merge rollup's second-parent ancestry is scanned this far for an
# already-seeded commit before the merge itself is kept as a seed.
_MERGE_SIDE_CAP = 50


class SeedsError(Exception):
    """The seeds file could not be read or parsed."""


@dataclass(frozen=True)
class Seed:
    sha: str
    advisory_id: str | None
    source: str
    resolved: bool
    date: int = 0
    subject: str = ""


@dataclass(frozen=True)
class SeedSet:
    seeds: tuple  # resolved Seed records, sorted by commit date then SHA
    unresolvable: tuple  # Seed records for seeds-file entries that did not resolve


_REVERT_SUBJECT_RE = re.compile(r"\s*revert\b", re.IGNORECASE)


def _message_signal(subject, body=""):
    """'advisory' or 'fixverb': which signal a commit message carries.

    An advisory id (CVE/GHSA) in subject or body is the advisory signal;
    a fix verb paired with a security term on the subject is the noisier
    fixverb signal. A 'Revert ...' subject never seeds on the fixverb
    signal: revert-of-fix is a removal-classification signal, not a
    guard origin. An explicit CVE/GHSA id still seeds.
    """
    if CVE_RE.search(subject) or GHSA_RE.search(subject):
        return "advisory"
    if body and (CVE_RE.search(body) or GHSA_RE.search(body)):
        return "advisory"
    if _REVERT_SUBJECT_RE.match(subject):
        return None
    if FIX_VERB_RE.search(subject) and SEC_TERM_RE.search(subject):
        return "fixverb"
    return None


def message_has_signal(subject, body=""):
    """True when the commit message carries any security signal."""
    return _message_signal(subject, body) is not None


def parse_seeds_file(text):
    """(sha_token, advisory_id) pairs from seeds-file text, in file order."""
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        advisory = parts[1].strip() if len(parts) > 1 else None
        entries.append((parts[0], advisory))
    return entries


def _read_seeds_file(path):
    try:
        if os.path.getsize(path) > _MAX_SEEDS_BYTES:
            exposure._warn(f"ignoring oversized seeds file {path}")
            return ""
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as e:
        raise SeedsError(f"cannot read seeds file {path}: {e}")
    except UnicodeDecodeError as e:
        raise SeedsError(f"seeds file {path} is not text: {e}")
    lines = text.splitlines(keepends=True)
    if len(lines) > _MAX_SEEDS_LINES:
        exposure._warn(
            f"seeds file {path}: using first {_MAX_SEEDS_LINES} lines"
        )
        text = "".join(lines[:_MAX_SEEDS_LINES])
    return text


def _security_ref_seeds(repo, window):
    """Seed records contributed by security-marked refs.

    Each matching ref contributes its target commit plus the commits its
    release range introduced: the target's ancestors bounded by the nearest
    ancestor tag targets. With no ancestor tag to bound it, the ref yields
    its target alone, never its full ancestry.
    """
    tag_targets = {}
    for name, _obj in gitlog.for_each_ref(repo, "refs/tags"):
        target = gitlog.resolve_commit(repo, name)
        if target:
            tag_targets[name] = target

    marked = []
    for name, _obj in gitlog.for_each_ref(repo, "refs/tags", "refs/heads"):
        short = name.rsplit("/", 1)[-1]
        if SECURITY_REF_RE.search(short):
            marked.append(name)
    targets = {name: gitlog.resolve_commit(repo, name) for name in marked}

    records = []
    for name in marked:
        target = targets[name]
        if target is None or target not in window:
            continue
        # one batched call resolves every ref merged into the target
        # instead of a merge-base subprocess per tag/ref pair
        merged = gitlog.merged_ref_names(repo, target)
        bounders = [
            t
            for ref_name, t in tag_targets.items()
            if ref_name != name and t != target and ref_name in merged
        ]
        for other, t in targets.items():
            if other == name:
                continue
            if t and t != target and other in merged:
                bounders.append(t)
        if bounders:
            shas = gitlog.rev_list(repo, target, exclude=bounders)
        else:
            shas = [target]
        records.append((name, shas))
    return records


def _drop_test_only_seeds(repo, seed_list, explicit):
    """Drop message-signal seeds whose whole diff is test/vendored churn.

    A seeds-file entry or a marked-ref seed is explicit provenance and
    stays regardless of what it touched, even when its recorded source
    is 'message' because the message pass won the dedup. A
    message-harvested commit that touched only test or third-party
    paths is not a guard origin. A commit whose changed paths cannot
    be listed (a merge's empty name-only diff, a git failure) is kept:
    the drop must be proven, never guessed.
    """
    changed = {}
    out = []
    for s in seed_list:
        if s.source != SOURCE_MESSAGE or s.sha in explicit:
            out.append(s)
            continue
        if s.sha not in changed:
            try:
                changed[s.sha] = gitlog.changed_paths(repo, s.sha)
            except gitlog.GitError:
                changed[s.sha] = None
        paths = changed[s.sha]
        if paths and all(
            shapes.is_test_path(p) or shapes.is_ignored_path(p)
            for p in paths
        ):
            continue
        out.append(s)
    return out


def _drop_merge_rollups(repo, seed_list, fixverb_only, window, explicit):
    """Drop a fixverb-only merge seed whose merged side already seeded.

    A rollup merge ('merge the branch fixing the security issue')
    re-signals work whose real commits are already seeds; when a
    non-merge ancestor on the second-parent side is itself a seed, the
    merge contributes nothing. Advisory-linked, seeds-file, and ref
    seeds are never dropped here. The side ancestry scan is bounded so
    a giant merge cannot blow up the walk.
    """
    seed_shas = {s.sha for s in seed_list}
    out = []
    for s in seed_list:
        if (
            s.source != SOURCE_MESSAGE
            or s.sha not in fixverb_only
            or s.sha in explicit
        ):
            out.append(s)
            continue
        c = window.get(s.sha)
        if c is None or len(c.parents) < 2:
            out.append(s)
            continue
        try:
            side = gitlog.rev_list(
                repo, c.parents[1], exclude=[c.parents[0]]
            )[:_MERGE_SIDE_CAP]
        except gitlog.GitError:
            out.append(s)
            continue
        if any(
            len(window[sha].parents) < 2
            for sha in side
            if sha in seed_shas
        ):
            continue  # the merged work already seeds itself
        out.append(s)
    return out


def collect_seeds(repo, seeds_file=None, since=None, until=None,
                  seeds_mode="advisory", include_test_seeds=False):
    """Collect the deduplicated, windowed seed set for a repo.

    Message signals, seeds-file SHAs, and security-marked refs all feed the
    same window (ancestors of ``until``, minus ``since`` ancestry). Every
    seeds-file entry that fails to resolve inside the window produces an
    explicit unresolvable record rather than a silent drop.

    ``seeds_mode`` is 'advisory' (CVE/GHSA ids only), 'message' (adds the
    fix-verb x security-term harvest), or 'all' (same as 'message').
    ``include_test_seeds`` keeps message-signal seeds whose diff only
    touches test/vendored paths; by default they are dropped.
    """
    if seeds_mode not in SEEDS_MODES:
        raise SeedsError(f"unknown seeds mode: {seeds_mode}")
    commits = gitlog.log(repo, until=until, since=since)
    window = {c.sha: c for c in commits}

    records = {}
    unresolvable = []
    # SHAs the operator or the repo's own markings named: a commit that
    # also matched a message signal keeps its explicit provenance even
    # when the dedup records 'message' as its source
    explicit = set()

    def add(sha, advisory_id, source, resolved=True):
        if not resolved or sha not in window:
            if source == SOURCE_SEEDS_FILE:
                unresolvable.append(
                    Seed(sha=sha, advisory_id=advisory_id, source=source,
                         resolved=False)
                )
            return
        c = window[sha]
        rec = Seed(sha=sha, advisory_id=advisory_id, source=source,
                   resolved=True, date=c.committer_time, subject=c.subject)
        prev = records.get(sha)
        if prev is None or (advisory_id and not prev.advisory_id):
            records[sha] = rec

    if seeds_file is not None:
        for token, advisory_id in parse_seeds_file(_read_seeds_file(seeds_file)):
            sha = gitlog.resolve_commit(repo, token)
            add(sha if sha is not None else token, advisory_id,
                SOURCE_SEEDS_FILE, resolved=sha is not None)
            if sha is not None:
                explicit.add(sha)

    harvest_fixverb = seeds_mode != "advisory"
    fixverb_only = set()
    messages = gitlog.commit_messages(repo, until=until, since=since)
    for c in commits:
        kind = _message_signal(c.subject, messages.get(c.sha, ""))
        if kind is None or (kind == "fixverb" and not harvest_fixverb):
            continue
        if kind == "fixverb":
            fixverb_only.add(c.sha)
        add(c.sha, None, SOURCE_MESSAGE)

    for ref_name, shas in _security_ref_seeds(repo, window):
        for sha in shas:
            explicit.add(sha)
            add(sha, None, f"{SOURCE_REF}:{ref_name}")

    seed_list = sorted(records.values(), key=lambda s: (s.date, s.sha))
    if not include_test_seeds:
        seed_list = _drop_test_only_seeds(repo, seed_list, explicit)
    seed_list = _drop_merge_rollups(
        repo, seed_list, fixverb_only, window, explicit
    )
    return SeedSet(seeds=tuple(seed_list), unresolvable=tuple(unresolvable))
