import os
from pathlib import Path

import pytest

from archaeology import gitlog
from conftest import commit_env, run_git

BASIC = [
    {"files": {"a.txt": "one\n"}, "message": "first"},
    {"files": {"a.txt": "two\n", "b.txt": "x\n"}, "message": "second"},
    {"files": {"b.txt": "y\n"}, "message": "third"},
    {"files": {"c.txt": "z\n"}, "message": "fourth"},
]


def test_make_repo_deterministic_shas(make_repo):
    r1 = make_repo(BASIC)
    r2 = make_repo(BASIC, name="other")
    assert r1.shas == r2.shas
    assert len(r1.shas) == 4


def test_log_order_matches_declared_order(make_repo):
    r = make_repo(BASIC)
    commits = gitlog.log(r.root)
    assert [c.sha for c in commits] == r.shas
    assert [c.subject for c in commits] == [
        "first",
        "second",
        "third",
        "fourth",
    ]


def test_log_until_bounds_ancestry(make_repo):
    r = make_repo(BASIC)
    commits = gitlog.log(r.root, until=r.shas[1])
    assert [c.sha for c in commits] == r.shas[:2]


def test_log_since_bounds_window(make_repo):
    r = make_repo(BASIC)
    commits = gitlog.log(r.root, until=r.shas[3], since=r.shas[0])
    assert [c.sha for c in commits] == r.shas[1:]


def test_log_empty_repo(tmp_path):
    # an empty repo has no commits; log returns [] rather than raising
    run_git(tmp_path, "init", "-q", "--object-format=sha1")
    assert gitlog.log(tmp_path) == []


def test_show_file_content_and_not_found(make_repo):
    r = make_repo(BASIC)
    assert gitlog.show_file(r.root, r.shas[0], "a.txt") == "one\n"
    assert gitlog.show_file(r.root, r.shas[0], "b.txt") is gitlog.NOT_FOUND
    assert gitlog.show_file(r.root, r.shas[2], "b.txt") == "y\n"


def test_show_file_bad_rev_raises(make_repo):
    r = make_repo(BASIC)
    with pytest.raises(gitlog.GitError):
        gitlog.show_file(r.root, "0" * 40, "a.txt")


def test_error_carries_invocation(make_repo):
    r = make_repo(BASIC)
    with pytest.raises(gitlog.GitError) as ei:
        gitlog.rev_parse(r.root, "not-a-rev")
    assert "not-a-rev" in " ".join(ei.value.argv)


def test_show_patch_multifile_line_numbers(make_repo):
    r = make_repo(
        [
            {
                "files": {
                    "m.py": "l1\nl2\nl3\nl4\n",
                    "gone.py": "d1\nd2\n",
                    "new.py": "n1\n",
                },
                "message": "base",
            },
            {
                "files": {
                    "m.py": "l1\nl2\ninserted\nl3\nl4\n",
                    "gone.py": "d2\n",
                    "extra.py": "e1\ne2\n",
                },
                "deletions": ["new.py"],
                "message": "change",
            },
        ]
    )
    patches = gitlog.show_patch(r.root, r.shas[1])
    by_new = {p.new_path: p for p in patches}
    by_old = {p.old_path: p for p in patches}

    m = by_new["m.py"]
    assert m.added == ((3, "inserted"),)
    assert m.removed == ()
    assert not m.is_new and not m.is_delete

    g = by_new["gone.py"]
    assert g.removed == ((1, "d1"),)

    n = by_old["new.py"]
    assert n.is_delete and n.new_path is None
    assert n.removed == ((1, "n1"),)

    e = by_new["extra.py"]
    assert e.is_new
    assert e.added == ((1, "e1"), (2, "e2"))


def test_show_patch_rename_and_binary_and_mode(make_repo):
    r = make_repo(
        [
            {
                "files": {
                    "old.py": "x = 1\n",
                    "tool.sh": "#!/bin/sh\necho hi\n",
                    "blob.bin": b"\x00\x01\x02\x03",
                },
                "message": "base",
            },
            {
                "files": {
                    "tool.sh": "#!/bin/sh\necho hi\n",
                    "blob.bin": b"\x00\x01\x02\x04",
                },
                "renames": [("old.py", "renamed.py")],
                "modes": {"tool.sh": 0o755},
                "message": "move and chmod",
            },
        ]
    )
    patches = gitlog.show_patch(r.root, r.shas[1])
    by_new = {p.new_path: p for p in patches}

    rn = by_new["renamed.py"]
    assert rn.is_rename and rn.old_path == "old.py"

    b = by_new["blob.bin"]
    assert b.is_binary and b.added == () and b.removed == ()

    t = by_new["tool.sh"]
    assert t.old_mode == "100644" and t.new_mode == "100755"


def test_pickaxe_finds_add_and_removal(make_repo):
    guard = "if len(data) > MAX:\n    return None\n"
    r = make_repo(
        [
            {"files": {"svc.py": "def f(d):\n    sink(d)\n"}, "message": "base"},
            {
                "files": {"svc.py": f"def f(d):\n    {guard}    sink(d)\n"},
                "message": "add guard",
            },
            {
                "files": {"svc.py": "def f(d):\n    sink(d)\n"},
                "message": "drop guard",
            },
        ]
    )
    hits = gitlog.pickaxe(r.root, r"len\(data\) > MAX", paths=["svc.py"])
    assert set(hits) == {r.shas[1], r.shas[2]}


def test_rename_lineage_and_pickaxe_across_rename(make_repo):
    guard = "if len(data) > MAX:\n    return None\n"
    r = make_repo(
        [
            {
                "files": {"svc.py": f"def f(d):\n    {guard}    sink(d)\n"},
                "message": "add guard",
            },
            {
                "files": {},
                "renames": [("svc.py", "lib/checks.py")],
                "message": "move",
            },
            {
                "files": {"lib/checks.py": "def f(d):\n    sink(d)\n"},
                "message": "drop guard",
            },
        ]
    )
    lineage = gitlog.rename_lineage(r.root, "lib/checks.py")
    assert lineage == ["lib/checks.py", "svc.py"]
    hits = gitlog.pickaxe(r.root, r"len\(data\) > MAX", paths=lineage)
    assert set(hits) == {r.shas[0], r.shas[2]}


def test_ls_tree_and_grep_files(make_repo):
    r = make_repo(BASIC)
    paths = gitlog.ls_tree(r.root, r.shas[-1])
    assert set(paths) == {"a.txt", "b.txt", "c.txt"}
    assert gitlog.grep_files(r.root, "two", r.shas[-1]) == ["a.txt"]
    assert gitlog.grep_files(r.root, "no-such-string", r.shas[-1]) == []


def test_commit_message_and_merge_constituents(make_repo, tmp_path):
    r = make_repo(BASIC)
    assert gitlog.commit_message(r.root, r.shas[0]) == "first"
    assert gitlog.merge_constituent_messages(r.root, r.shas[0]) == []

    root = r.root
    run_git(root, "checkout", "-q", "-b", "side", r.shas[0])
    Path(root, "side.py").write_text("s\n")
    run_git(root, "add", "side.py")
    run_git(
        root,
        "commit",
        "-q",
        "-m",
        "side work",
        env_extra=commit_env(100),
    )
    run_git(root, "checkout", "-q", "main")
    run_git(
        root,
        "merge",
        "--no-ff",
        "-m",
        "merge side",
        "side",
        env_extra=commit_env(101),
    )
    merge_sha = run_git(root, "rev-parse", "HEAD").stdout.strip()
    msgs = gitlog.merge_constituent_messages(root, merge_sha)
    assert any("side work" in m for m in msgs)


def test_resolve_rev_parse_and_clean(make_repo):
    r = make_repo(BASIC)
    assert gitlog.resolve(r.root, "HEAD") == r.shas[-1]
    assert gitlog.resolve_commit(r.root, r.shas[0]) == r.shas[0]
    assert gitlog.resolve(r.root, "nonsense") is None
    assert gitlog.is_git_repo(r.root)
    assert gitlog.is_clean(r.root)
    Path(r.root, "dirty.txt").write_text("x\n")
    assert not gitlog.is_clean(r.root)


def test_resolve_refuses_option_spelling(make_repo):
    # a rev spelled like a flag never reaches git argv
    r = make_repo(BASIC)
    assert gitlog.resolve(r.root, "--output=/tmp/x") is None
    assert gitlog.resolve(r.root, "-Gfoo") is None


def test_non_utf8_blob_decodes_with_replacement(make_repo):
    # a latin-1 blob in 'git show' output must never raise
    # UnicodeDecodeError; it decodes with replacement chars
    blob = "# caf\xe9\n".encode("latin-1") + b"x = 1\n"
    r = make_repo(
        [
            {"files": {"a.py": b"x = 0\n"}, "message": "base"},
            {"files": {"a.py": blob}, "message": "latin-1 comment"},
        ]
    )
    text = gitlog.show_file(r.root, r.shas[-1], "a.py")
    assert "x = 1" in text
    patches = gitlog.show_patch(r.root, r.shas[-1])
    assert patches[0].new_path == "a.py"


def test_missing_git_binary_is_giterror(make_repo, monkeypatch):
    import subprocess

    r = make_repo(BASIC)

    def boom(*a, **kw):
        raise FileNotFoundError("no git")

    monkeypatch.setattr(subprocess, "run", boom)
    with pytest.raises(gitlog.GitError):
        gitlog.rev_parse(r.root, "HEAD")


def test_git_timeout_is_giterror(make_repo, monkeypatch):
    import subprocess

    r = make_repo(BASIC)

    def boom(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="git", timeout=300)

    monkeypatch.setattr(subprocess, "run", boom)
    with pytest.raises(gitlog.GitError):
        gitlog.rev_parse(r.root, "HEAD")


def test_git_env_vars_do_not_redirect_repo(make_repo, monkeypatch):
    # ambient GIT_* must not steer 'git -C' at a different repo/config
    r = make_repo(BASIC)
    other = make_repo(
        [{"files": {"z.txt": "z\n"}, "message": "other"}], name="other"
    )
    monkeypatch.setenv("GIT_DIR", os.path.join(other.root, ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", other.root)
    assert gitlog.log(r.root)[0].sha == r.shas[0]


def test_grep_files_pattern_is_literal(make_repo):
    # 'foo$' under BRE anchors end-of-line and misses 'foo$(x)': the
    # narrowing must be a fixed-string match
    r = make_repo(
        [
            {
                "files": {
                    "a.js": "function use(d) {\n  return foo$(d);\n}\n"
                },
                "message": "init",
            }
        ]
    )
    assert gitlog.grep_files(r.root, "foo$", r.shas[-1]) == ["a.js"]
    assert gitlog.grep_files(r.root, "foo$(", r.shas[-1]) == ["a.js"]


def test_commit_messages_nul_separated_records(make_repo):
    # message bytes cannot spoof a record boundary: a \x1e in the
    # subject does not forge a commit entry
    forged = "1" * 40
    r = make_repo(
        [
            {"files": {"a.txt": "one\n"}, "message": "first"},
            {
                "files": {"b.txt": "x\n"},
                "message": f"real\x1e{forged}\x1fforged body",
            },
        ]
    )
    msgs = gitlog.commit_messages(r.root)
    assert set(msgs) == set(r.shas)
    assert forged not in msgs
    assert "\x1e" in msgs[r.shas[1]]


def test_parse_patch_plus_minus_content_keeps_paths(make_repo):
    # content lines starting '++ '/'-- ' inside a hunk are not file
    # headers and must not corrupt old/new paths
    r = make_repo(
        [
            {"files": {"f.py": "a\n-- gone\nb\n"}, "message": "base"},
            {
                "files": {"f.py": "a\n++ new\nb\n"},
                "message": "swap marker lines",
            },
        ]
    )
    patches = gitlog.show_patch(r.root, r.shas[1])
    assert len(patches) == 1
    p = patches[0]
    assert p.old_path == "f.py"
    assert p.new_path == "f.py"
    assert (2, "++ new") in p.added
    assert (2, "-- gone") in p.removed


def test_commit_patch_merge_diffs_first_parent(make_repo):
    r = make_repo(
        [
            {
                "files": {"app.py": "def recv(body):\n    return open(body).read()\n"},
                "message": "base",
            }
        ]
    )
    run_git(r.root, "checkout", "-q", "-b", "side")
    Path(r.root, "app.py").write_text(
        "def recv(body):\n"
        "    if len(body) > MAX_LEN:\n"
        '        raise ValueError("big")\n'
        "    return open(body).read()\n"
    )
    run_git(r.root, "add", "app.py")
    run_git(
        r.root, "commit", "-q", "-m", "side guards",
        env_extra=commit_env(10),
    )
    run_git(r.root, "checkout", "-q", "main")
    run_git(
        r.root, "merge", "--no-ff", "-m", "fix overflow bounds check",
        "side", env_extra=commit_env(11),
    )
    merge_sha = run_git(r.root, "rev-parse", "HEAD").stdout.strip()
    patches = gitlog.commit_patch(r.root, merge_sha)
    added = [
        (p.new_path, t) for p in patches for _n, t in p.added
    ]
    assert ("app.py", "    if len(body) > MAX_LEN:") in added
