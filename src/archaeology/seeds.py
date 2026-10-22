"""Seed collection: message signals, --seeds-file SHAs, security-tagged refs.

The seed set is the noise gate: only commits inside the R2 bounded window
with a security signal, an operator-supplied advisory entry, or a
security-marked ref become guard origins.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from . import gitlog

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


def message_has_signal(subject, body=""):
    """True when the commit message carries a security signal."""
    if CVE_RE.search(subject) or GHSA_RE.search(subject):
        return True
    if body and (CVE_RE.search(body) or GHSA_RE.search(body)):
        return True
    return bool(FIX_VERB_RE.search(subject) and SEC_TERM_RE.search(subject))


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
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError as e:
        raise SeedsError(f"cannot read seeds file {path}: {e}")
    except UnicodeDecodeError as e:
        raise SeedsError(f"seeds file {path} is not text: {e}")


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
        bounders = [
            t
            for ref_name, t in tag_targets.items()
            if ref_name != name and t != target
            and gitlog.is_ancestor(repo, t, target)
        ]
        for other, t in targets.items():
            if other == name:
                continue
            if t and t != target and gitlog.is_ancestor(repo, t, target):
                bounders.append(t)
        if bounders:
            shas = gitlog.rev_list(repo, target, exclude=bounders)
        else:
            shas = [target]
        records.append((name, shas))
    return records


def collect_seeds(repo, seeds_file=None, since=None, until=None):
    """Collect the deduplicated, windowed seed set for a repo.

    Message signals, seeds-file SHAs, and security-marked refs all feed the
    same window (ancestors of ``until``, minus ``since`` ancestry). Every
    seeds-file entry that fails to resolve inside the window produces an
    explicit unresolvable record rather than a silent drop.
    """
    commits = gitlog.log(repo, until=until, since=since)
    window = {c.sha: c for c in commits}

    records = {}
    unresolvable = []

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

    messages = gitlog.commit_messages(repo, until=until, since=since)
    for c in commits:
        if message_has_signal(c.subject, messages.get(c.sha, "")):
            add(c.sha, None, SOURCE_MESSAGE)

    for ref_name, shas in _security_ref_seeds(repo, window):
        for sha in shas:
            add(sha, None, f"{SOURCE_REF}:{ref_name}")

    seeds = sorted(records.values(), key=lambda s: (s.date, s.sha))
    return SeedSet(seeds=tuple(seeds), unresolvable=tuple(unresolvable))
