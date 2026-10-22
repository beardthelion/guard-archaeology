"""Subprocessed git access: every git invocation in the pipeline lives here.

Conventions:
- LC_ALL=C is pinned on every call so messages and ordering are stable.
- All failures raise GitError carrying the exact failed invocation.
- History bounds are rev bounds, never git's --since/--until date flags:
  ``until`` restricts enumeration to ancestors of that rev (inclusive) and
  ``since`` excludes it and its ancestors (``since..until`` ancestry).
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from dataclasses import dataclass


class GitError(Exception):
    """A git invocation failed. Carries argv, returncode, and stderr."""

    def __init__(self, argv, returncode, stderr):
        self.argv = list(argv)
        self.returncode = returncode
        self.stderr = stderr
        cmd = " ".join(shlex.quote(a) for a in self.argv)
        detail = stderr.strip().splitlines()
        tail = detail[-1] if detail else "no stderr"
        super().__init__(f"{cmd} failed (rc={returncode}): {tail}")


class NotFound:
    """Typed result: a path does not exist at the requested revision."""

    def __repr__(self):
        return "NOT_FOUND"

    def __bool__(self):
        return False


NOT_FOUND = NotFound()


@dataclass(frozen=True)
class Commit:
    sha: str
    parents: tuple
    author_time: int
    committer_time: int
    subject: str


@dataclass(frozen=True)
class FilePatch:
    """Per-file diff parsed from git show / git log -p output."""

    old_path: str | None
    new_path: str | None
    added: tuple  # ((new_lineno, text), ...)
    removed: tuple  # ((old_lineno, text), ...)
    is_new: bool = False
    is_delete: bool = False
    is_rename: bool = False
    is_binary: bool = False
    similarity: int | None = None
    old_mode: str | None = None
    new_mode: str | None = None


def _env():
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    return env


def _run_rc(repo, argv):
    """Run git, returning (stdout, returncode, stderr) without raising."""
    full = ["git", "-C", str(repo), *[str(a) for a in argv]]
    proc = subprocess.run(
        full, env=_env(), capture_output=True, text=True
    )
    return proc.stdout, proc.returncode, proc.stderr, full


def _run(repo, argv):
    """Run git, returning stdout; raise GitError on nonzero exit."""
    out, rc, err, full = _run_rc(repo, argv)
    if rc != 0:
        raise GitError(full, rc, err)
    return out


# --- revisions and refs -----------------------------------------------------

def rev_parse(repo, rev):
    """Resolve a rev to a SHA; raise GitError when it does not resolve."""
    return _run(repo, ["rev-parse", "--verify", rev]).strip()


def resolve(repo, rev):
    """Resolve a rev to a SHA, or None when it does not resolve."""
    out, rc, _err, _full = _run_rc(repo, ["rev-parse", "--verify", rev])
    if rc != 0:
        return None
    return out.strip()


def resolve_commit(repo, rev):
    """Resolve a rev to a commit SHA (peels annotated tags), or None."""
    return resolve(repo, f"{rev}^{{commit}}")


def is_git_repo(repo):
    try:
        _run(repo, ["rev-parse", "--git-dir"])
        return True
    except GitError:
        return False


def is_clean(repo):
    """True when the worktree has no staged, unstaged, or untracked changes."""
    return _run(repo, ["status", "--porcelain"]).strip() == ""


def is_ancestor(repo, ancestor, descendant):
    """True when ancestor is an ancestor of descendant."""
    _out, rc, err, full = _run_rc(
        repo, ["merge-base", "--is-ancestor", ancestor, descendant]
    )
    if rc == 0:
        return True
    if rc == 1:
        return False
    raise GitError(full, rc, err)


def rev_list(repo, include, exclude=None):
    """SHAs reachable from include but not from any exclude rev."""
    argv = ["rev-list", include]
    for e in exclude or ():
        argv.append(f"^{e}")
    out = _run(repo, argv)
    return [s for s in out.split() if s]


def for_each_ref(repo, *patterns):
    """(refname, objectname) pairs for refs matching the given patterns."""
    argv = ["for-each-ref", "--format=%(refname)%09%(objectname)", *patterns]
    out = _run(repo, argv)
    refs = []
    for line in out.splitlines():
        if "\t" in line:
            name, obj = line.split("\t", 1)
            refs.append((name, obj))
    return refs


# --- commit enumeration -----------------------------------------------------

_FMT = "%H%x1f%P%x1f%at%x1f%ct%x1f%s"


def _parse_commit_line(line):
    sha, parents, at, ct, subject = line.split("\x1f", 4)
    return Commit(
        sha=sha,
        parents=tuple(p for p in parents.split() if p),
        author_time=int(at),
        committer_time=int(ct),
        subject=subject,
    )


def log(repo, until=None, since=None, paths=None):
    """Commits in the bounded window, sorted by commit date then SHA.

    ``until`` (default HEAD) bounds enumeration to its own ancestors,
    inclusive; ``since`` excludes it and its ancestors. Both are rev
    bounds, not git's same-named date flags.
    """
    rev = until or "HEAD"
    if until is None and resolve(repo, "HEAD") is None:
        return []  # unborn HEAD: a repo with zero commits has an empty window
    spec = f"{since}..{rev}" if since else rev
    argv = ["log", f"--format={_FMT}", spec]
    if paths:
        argv += ["--", *paths]
    out, rc, err, full = _run_rc(repo, argv)
    if rc != 0:
        raise GitError(full, rc, err)
    commits = [_parse_commit_line(l) for l in out.splitlines() if l.strip()]
    commits.sort(key=lambda c: (c.committer_time, c.sha))
    return commits


def commit(repo, sha):
    """Single Commit record for a revision."""
    out = _run(repo, ["log", "-1", f"--format={_FMT}", sha])
    return _parse_commit_line(out.splitlines()[0])


def commit_message(repo, sha):
    """Full commit message (subject plus body)."""
    return _run(repo, ["log", "-1", "--format=%B", sha]).rstrip("\n")


def commit_messages(repo, until=None, since=None):
    """{sha: full message} for the bounded window, in one git call.

    Same rev bounds as log(); each record parses as
    ``\\x1e<sha>\\x1f<message>``.
    """
    rev = until or "HEAD"
    if until is None and resolve(repo, "HEAD") is None:
        return {}  # unborn HEAD: a repo with zero commits
    spec = f"{since}..{rev}" if since else rev
    out = _run(repo, ["log", "--format=%x1e%H%x1f%B", spec])
    messages = {}
    for rec in out.split("\x1e"):
        sha, _sep, msg = rec.partition("\x1f")
        sha = sha.strip()
        if not sha:
            continue
        messages[sha] = msg.rstrip("\n")
    return messages


def merge_constituent_shas(repo, sha):
    """SHAs a merge commit pulled in from its non-first-parent sides."""
    c = commit(repo, sha)
    if len(c.parents) < 2:
        return []
    return [s for s in rev_list(repo, sha, exclude=[c.parents[0]]) if s != sha]


def merge_constituent_messages(repo, sha):
    """Full messages of a merge's constituent commits ([] when not a merge)."""
    return [commit_message(repo, s) for s in merge_constituent_shas(repo, sha)]


# --- tree and blob reads ------------------------------------------------------

def show_file(repo, sha, path):
    """File content at <sha>:<path>, or NOT_FOUND when absent at that rev.

    An unresolvable rev raises GitError; a resolvable rev whose tree lacks
    the path returns the NOT_FOUND sentinel instead of raising.
    """
    out, rc, err, full = _run_rc(repo, ["show", f"{sha}:{path}"])
    if rc == 0:
        return out
    if resolve_commit(repo, sha) is None:
        raise GitError(full, rc, err)
    if "does not exist" in err or "not in" in err:
        return NOT_FOUND
    raise GitError(full, rc, err)


def ls_tree(repo, sha):
    """All blob paths in the tree at sha, in tree order."""
    out = _run(repo, ["ls-tree", "-r", "--name-only", sha])
    return [l for l in out.splitlines() if l]


def grep_files(repo, pattern, sha):
    """Paths under sha whose content matches pattern ([] when none match)."""
    out, rc, err, full = _run_rc(repo, ["grep", "-l", "-e", pattern, sha])
    if rc == 1:
        return []
    if rc != 0:
        raise GitError(full, rc, err)
    paths = []
    for line in out.splitlines():
        if line:
            paths.append(line.split(":", 1)[1])
    return paths


# --- patch parsing ------------------------------------------------------------

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def _unquote(token):
    """Strip a/ or b/ prefix and any quoting git put on a diff path."""
    if token == "/dev/null":
        return None
    if token.startswith('"'):
        try:
            token = shlex.split(token)[0]
        except ValueError:
            token = token.strip('"')
    for prefix in ("a/", "b/"):
        if token.startswith(prefix):
            return token[2:]
    return token


def _diff_git_paths(line):
    """Extract (old_path, new_path) from a 'diff --git a/X b/Y' line."""
    try:
        parts = shlex.split(line[len("diff --git "):])
    except ValueError:
        parts = line[len("diff --git "):].split()
    if len(parts) >= 2:
        return _unquote(parts[0]), _unquote(parts[1])
    return None, None


def parse_patch_text(text):
    """Parse 'git show' or 'git log -p' output into per-file FilePatches."""
    patches = []
    cur = None  # mutable dict while inside a diff --git section
    old_no = new_no = 0
    in_hunk = False

    def flush():
        nonlocal cur
        if cur is not None:
            patches.append(
                FilePatch(
                    old_path=cur["old_path"],
                    new_path=cur["new_path"],
                    added=tuple(cur["added"]),
                    removed=tuple(cur["removed"]),
                    is_new=cur["is_new"],
                    is_delete=cur["is_delete"],
                    is_rename=cur["is_rename"],
                    is_binary=cur["is_binary"],
                    similarity=cur["similarity"],
                    old_mode=cur["old_mode"],
                    new_mode=cur["new_mode"],
                )
            )
        cur = None

    for line in text.splitlines():
        if line.startswith("diff --git "):
            flush()
            old, new = _diff_git_paths(line)
            cur = {
                "old_path": old,
                "new_path": new,
                "added": [],
                "removed": [],
                "is_new": False,
                "is_delete": False,
                "is_rename": False,
                "is_binary": False,
                "similarity": None,
                "old_mode": None,
                "new_mode": None,
            }
            in_hunk = False
            continue
        if cur is None:
            continue
        if line.startswith("new file mode "):
            cur["is_new"] = True
            cur["new_mode"] = line.split()[-1]
        elif line.startswith("deleted file mode "):
            cur["is_delete"] = True
            cur["old_mode"] = line.split()[-1]
        elif line.startswith("old mode "):
            cur["old_mode"] = line.split()[-1]
        elif line.startswith("new mode "):
            cur["new_mode"] = line.split()[-1]
        elif line.startswith("similarity index "):
            m = re.search(r"(\d+)%", line)
            if m:
                cur["similarity"] = int(m.group(1))
        elif line.startswith("rename from "):
            cur["is_rename"] = True
            cur["old_path"] = line[len("rename from "):]
        elif line.startswith("rename to "):
            cur["is_rename"] = True
            cur["new_path"] = line[len("rename to "):]
        elif line.startswith("Binary files ") or line.startswith(
            "GIT binary patch"
        ):
            cur["is_binary"] = True
        elif line.startswith("--- "):
            cur["old_path"] = _unquote(line[4:])
        elif line.startswith("+++ "):
            cur["new_path"] = _unquote(line[4:])
        else:
            m = _HUNK_RE.match(line)
            if m:
                old_no = int(m.group(1))
                new_no = int(m.group(3))
                in_hunk = True
                continue
            if not in_hunk:
                continue
            if line.startswith("+"):
                cur["added"].append((new_no, line[1:]))
                new_no += 1
            elif line.startswith("-"):
                cur["removed"].append((old_no, line[1:]))
                old_no += 1
            elif line.startswith("\\"):
                pass  # "\ No newline at end of file"
            else:
                # context line (including the empty-line form)
                old_no += 1
                new_no += 1
    flush()
    return patches


def show_patch(repo, sha):
    """Per-file FilePatches for a single commit (-M rename detection on)."""
    out = _run(repo, ["show", "-M", "--format=", sha])
    return parse_patch_text(out)


# --- pickaxe and lineage ------------------------------------------------------

def pickaxe(repo, query, paths=None, until=None, since=None,
            fixed_string=False, topo=False):
    """SHAs touching paths whose diff matches the pickaxe, newest first.

    fixed_string=False queries with -G<regex> (diff-text regex);
    fixed_string=True queries with -S<string> (literal add/remove count).
    Both run under --full-history so merged side branches are not hidden
    by TREESAME simplification. topo=True orders --topo-order so a commit
    never precedes its parent, even under clock skew.
    """
    flag = f"-S{query}" if fixed_string else f"-G{query}"
    rev = until or "HEAD"
    spec = f"{since}..{rev}" if since else rev
    argv = ["log", "--full-history", flag, "--format=%H", spec]
    if topo:
        argv.insert(2, "--topo-order")
    if paths:
        argv += ["--", *paths]
    out = _run(repo, argv)
    return [l.strip() for l in out.splitlines() if l.strip()]


def path_events(repo, path, until=None):
    """(sha, status, old_path, new_path) records for a path, newest first.

    Built from 'git log --full-history --name-status -M -- path' so side
    branches merged into the window are not hidden by TREESAME
    simplification. The pathspec filter splits rename pairs: a rename away
    from the path shows as D, a rename in shows as A. Callers disambiguate
    those against name_status() on the same commit.
    """
    argv = [
        "log", "--full-history", "--name-status", "-M", "--format=%H",
        until or "HEAD", "--", path,
    ]
    out = _run(repo, argv)
    events = []
    sha = None
    for line in out.splitlines():
        if not line.strip():
            continue
        if re.fullmatch(r"[0-9a-f]+", line):
            sha = line
            continue
        if sha is None:
            continue
        parts = line.split("\t")
        if parts[0].startswith(("R", "C")) and len(parts) == 3:
            events.append((sha, parts[0][0], parts[1], parts[2]))
        elif len(parts) == 2:
            events.append((sha, parts[0][0], parts[1], parts[1]))
    return events


def name_status(repo, sha):
    """(status, old_path, new_path) records for one commit (-M on)."""
    out = _run(repo, ["show", "-M", "--name-status", "--format=", sha])
    records = []
    for line in out.splitlines():
        parts = line.split("\t")
        if not parts or not parts[0]:
            continue
        if parts[0].startswith(("R", "C")) and len(parts) == 3:
            records.append((parts[0][0], parts[1], parts[2]))
        elif len(parts) == 2:
            records.append((parts[0][0], parts[1], parts[1]))
    return records


def rename_lineage(repo, path, until=None):
    """Path chain for a file across renames, newest name first.

    Built from 'git log --follow --name-status -M' on the file: every R
    record whose new name is the chain tip extends the chain with its old
    name. Returns [path] when the file was never renamed.
    """
    argv = [
        "log", "--follow", "--name-status", "-M", "--format=%H",
        until or "HEAD", "--", path,
    ]
    out = _run(repo, argv)
    lineage = [path]
    for line in out.splitlines():
        if not line.startswith("R"):
            continue
        parts = line.split("\t")
        if len(parts) == 3 and parts[2] == lineage[-1]:
            lineage.append(parts[1])
    return lineage
