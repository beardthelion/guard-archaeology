from pathlib import Path

from archaeology import cli, extract, gitlog, seeds, track
from conftest import commit_env, run_git

BASE = "def recv(body):\n    return open(body).read()\n"

GUARDED = (
    "def recv(body):\n"
    "    if len(body) > MAX_LEN:\n"
    '        raise ValueError("big")\n'
    "    return open(body).read()\n"
)

# Same guard under different identifiers: the normalized signature is
# identical, so pickaxe hits but verification clears it.
RENAMED = (
    "def recv(payload):\n"
    "    if len(payload) > LIMIT:\n"
    '        raise ValueError("big")\n'
    "    return open(payload).read()\n"
)

# Same guard with the raise split across lines: statement-level
# normalization joins it back to the identical signature.
REFLOWED = (
    "def recv(body):\n"
    "    if len(body) > MAX_LEN:\n"
    "        raise ValueError(\n"
    '            "big")\n'
    "    return open(body).read()\n"
)

FRESH = "def g(d):\n    return os.popen(d).read()\n"

SEED_MSG = "fix overflow bounds check"


def _track(make_repo, commits, until=None):
    """Build the fixture, run seeds + extract + track, return all three."""
    r = make_repo(commits)
    seed_set = seeds.collect_seeds(r.root)
    ext = extract.extract_guards(r.root, seed_set)
    assert len(ext.records) == 1
    tr = track.track_guards(r.root, ext.records, until=until)
    return r, ext, tr


def test_intact_when_untouched(make_repo):
    r, ext, tr = _track(
        make_repo,
        [
            {"files": {"app.py": BASE}, "message": "base"},
            {"files": {"app.py": GUARDED}, "message": SEED_MSG},
            {"files": {"notes.txt": "x\n"}, "message": "docs"},
        ],
    )
    assert tr.errors == ()
    out = tr.outcomes[0]
    assert out.status == "intact"
    assert out.candidate_sha is None
    assert out.add_confirmed
    assert out.path_chain == ("app.py",)
    assert out.boundary_present
    assert out.boundary_path == "app.py"
    assert out.boundary_sha == r.shas[-1]
    assert "open(" in out.boundary_excerpt
    assert out.lineage_break is None


def test_rename_then_removed_finds_true_removal(make_repo):
    r, ext, tr = _track(
        make_repo,
        [
            {"files": {"app.py": BASE}, "message": "base"},
            {"files": {"app.py": GUARDED}, "message": SEED_MSG},
            {
                "renames": [("app.py", "lib/checks.py")],
                "message": "move",
            },
            {"files": {"lib/checks.py": BASE}, "message": "refactor"},
        ],
    )
    out = tr.outcomes[0]
    assert out.status == "candidate"
    assert out.candidate_sha == r.shas[3]
    assert out.removal_parent_sha == r.shas[2]
    assert out.path_chain == ("app.py", "lib/checks.py")
    assert out.boundary_path == "lib/checks.py"
    assert out.boundary_present
    assert out.add_confirmed


def test_renamed_variable_stays_intact(make_repo):
    r, ext, tr = _track(
        make_repo,
        [
            {"files": {"app.py": BASE}, "message": "base"},
            {"files": {"app.py": GUARDED}, "message": SEED_MSG},
            {"files": {"app.py": RENAMED}, "message": "rename vars"},
        ],
    )
    out = tr.outcomes[0]
    assert out.status == "intact"
    assert out.candidate_sha is None
    assert [e.sha for e in out.mutation_events] == [r.shas[2]]


def test_line_split_reflow_stays_intact(make_repo):
    r, ext, tr = _track(
        make_repo,
        [
            {"files": {"app.py": BASE}, "message": "base"},
            {"files": {"app.py": GUARDED}, "message": SEED_MSG},
            {"files": {"app.py": REFLOWED}, "message": "wrap lines"},
        ],
    )
    out = tr.outcomes[0]
    assert out.status == "intact"
    assert out.candidate_sha is None


def test_mutation_then_removed_continues_track(make_repo):
    # a cleared candidacy at A does not stop the track: B is the
    # candidate removal
    r, ext, tr = _track(
        make_repo,
        [
            {"files": {"app.py": BASE}, "message": "base"},
            {"files": {"app.py": GUARDED}, "message": SEED_MSG},
            {"files": {"app.py": RENAMED}, "message": "rename vars"},
            {"files": {"app.py": BASE}, "message": "refactor"},
        ],
    )
    out = tr.outcomes[0]
    assert out.status == "candidate"
    assert out.candidate_sha == r.shas[3]
    assert [e.sha for e in out.mutation_events] == [r.shas[2]]


def test_until_before_removal_is_intact(make_repo):
    commits = [
        {"files": {"app.py": BASE}, "message": "base"},
        {"files": {"app.py": GUARDED}, "message": SEED_MSG},
        {"files": {"notes.txt": "x\n"}, "message": "docs"},
        {"files": {"app.py": BASE}, "message": "refactor"},
    ]
    r, ext, tr = _track(make_repo, commits, until=None)
    assert tr.outcomes[0].status == "candidate"
    before = track.track_guards(r.root, ext.records, until=r.shas[2])
    assert before.outcomes[0].status == "intact"
    at = track.track_guards(r.root, ext.records, until=r.shas[3])
    assert at.outcomes[0].status == "candidate"
    assert at.outcomes[0].candidate_sha == r.shas[3]


def test_terminal_delete_is_deleted_evidence(make_repo):
    r, ext, tr = _track(
        make_repo,
        [
            {"files": {"app.py": BASE}, "message": "base"},
            {"files": {"app.py": GUARDED}, "message": SEED_MSG},
            {"deletions": ["app.py"], "message": "drop app.py"},
        ],
    )
    out = tr.outcomes[0]
    assert out.status == "deleted"
    assert out.lineage_break is not None
    assert out.lineage_break.kind == "delete"
    assert out.lineage_break.sha == r.shas[2]
    assert not out.boundary_present
    assert out.candidate_sha is None


def test_delete_recreate_is_lost_lineage(make_repo):
    r, ext, tr = _track(
        make_repo,
        [
            {"files": {"app.py": BASE}, "message": "base"},
            {"files": {"app.py": GUARDED}, "message": SEED_MSG},
            {"deletions": ["app.py"], "message": "drop app.py"},
            {"files": {"app.py": FRESH}, "message": "re-add app.py"},
        ],
    )
    out = tr.outcomes[0]
    assert out.status == "severed"
    assert out.lineage_break is not None
    assert out.lineage_break.kind == "delete-recreate"
    assert out.lineage_break.sha == r.shas[3]
    # the boundary file exists but is a different identity
    assert out.boundary_present
    assert out.candidate_sha is None


def test_recreate_through_merge_is_lost_lineage(make_repo):
    r = make_repo(
        [
            {"files": {"app.py": BASE}, "message": "base"},
            {"files": {"app.py": GUARDED}, "message": SEED_MSG},
            {"deletions": ["app.py"], "message": "drop app.py"},
        ]
    )
    # the same name is recreated on a side branch and merged in
    run_git(r.root, "checkout", "-q", "-b", "side", r.shas[1])
    run_git(r.root, "rm", "-q", "app.py")
    run_git(
        r.root, "commit", "-q", "-m", "side deletes",
        env_extra=commit_env(10),
    )
    Path(r.root, "app.py").write_text(FRESH)
    run_git(r.root, "add", "app.py")
    run_git(
        r.root, "commit", "-q", "-m", "side recreates fresh",
        env_extra=commit_env(11),
    )
    run_git(r.root, "checkout", "-q", "main")
    run_git(
        r.root, "merge", "--no-ff", "-m", "merge side", "side",
        env_extra=commit_env(12), check=False,
    )
    run_git(r.root, "checkout", "side", "--", "app.py")
    run_git(r.root, "add", "app.py")
    run_git(
        r.root, "commit", "-q", "-m", "merge resolved to side",
        env_extra=commit_env(13),
    )
    seed_set = seeds.collect_seeds(r.root)
    ext = extract.extract_guards(r.root, seed_set)
    tr = track.track_guards(r.root, ext.records)
    out = tr.outcomes[0]
    assert out.status == "severed"
    assert out.lineage_break.kind == "delete-recreate"


def test_squash_merge_recreate_is_lost_lineage(make_repo):
    r = make_repo(
        [
            {"files": {"app.py": BASE}, "message": "base"},
            {"files": {"app.py": GUARDED}, "message": SEED_MSG},
            {"deletions": ["app.py"], "message": "drop app.py"},
        ]
    )
    run_git(r.root, "checkout", "-q", "-b", "side", r.shas[0])
    Path(r.root, "app.py").write_text(FRESH)
    run_git(r.root, "add", "app.py")
    run_git(
        r.root, "commit", "-q", "-m", "side rewrites app.py",
        env_extra=commit_env(10),
    )
    run_git(r.root, "checkout", "-q", "main")
    run_git(
        r.root, "merge", "--squash", "side",
        env_extra=commit_env(11), check=False,
    )
    run_git(r.root, "add", "app.py")
    run_git(
        r.root, "commit", "-q", "-m", "squash side in",
        env_extra=commit_env(12),
    )
    seed_set = seeds.collect_seeds(r.root)
    ext = extract.extract_guards(r.root, seed_set)
    tr = track.track_guards(r.root, ext.records)
    out = tr.outcomes[0]
    assert out.status == "severed"
    assert out.lineage_break is not None
    assert out.lineage_break.kind == "delete-recreate"
    assert out.boundary_present


def test_squash_merge_removal_is_candidate(make_repo):
    # a guard dropped by a squash-merged side branch is attributed to the
    # squash commit itself (the dropping commit is unreachable)
    r = make_repo(
        [
            {"files": {"app.py": BASE}, "message": "base"},
            {"files": {"app.py": GUARDED}, "message": SEED_MSG},
        ]
    )
    run_git(r.root, "checkout", "-q", "-b", "side")
    Path(r.root, "app.py").write_text(BASE)
    run_git(r.root, "add", "app.py")
    run_git(
        r.root, "commit", "-q", "-m", "side drops guard",
        env_extra=commit_env(10),
    )
    run_git(r.root, "checkout", "-q", "main")
    run_git(
        r.root, "merge", "--squash", "side",
        env_extra=commit_env(11), check=False,
    )
    run_git(r.root, "add", "app.py")
    run_git(
        r.root, "commit", "-q", "-m", "squash side in",
        env_extra=commit_env(12),
    )
    squash_sha = run_git(r.root, "rev-parse", "HEAD").stdout.strip()
    seed_set = seeds.collect_seeds(r.root)
    ext = extract.extract_guards(r.root, seed_set)
    tr = track.track_guards(r.root, ext.records)
    out = tr.outcomes[0]
    assert out.status == "candidate"
    assert out.candidate_sha == squash_sha


def test_removal_through_merged_side_branch_is_candidate(make_repo):
    # the removal commit on the side branch is named, not the merge
    r = make_repo(
        [
            {"files": {"app.py": BASE}, "message": "base"},
            {"files": {"app.py": GUARDED}, "message": SEED_MSG},
            {"files": {"notes.txt": "x\n"}, "message": "main work"},
        ]
    )
    run_git(r.root, "checkout", "-q", "-b", "side", r.shas[1])
    Path(r.root, "app.py").write_text(BASE)
    run_git(r.root, "add", "app.py")
    run_git(
        r.root, "commit", "-q", "-m", "side drops guard",
        env_extra=commit_env(10),
    )
    run_git(r.root, "checkout", "-q", "main")
    # main never touched app.py, so the merge resolves cleanly to side's
    run_git(
        r.root, "merge", "--no-ff", "-m", "merge side", "side",
        env_extra=commit_env(11),
    )
    side_sha = run_git(r.root, "rev-parse", "side").stdout.strip()
    seed_set = seeds.collect_seeds(r.root)
    ext = extract.extract_guards(r.root, seed_set)
    tr = track.track_guards(r.root, ext.records)
    out = tr.outcomes[0]
    assert out.status == "candidate"
    assert out.candidate_sha == side_sha


GO_BASE = (
    "package m\n\nfunc Load(p string) error {\n\treturn os.ReadFile(p)\n}\n"
)
GO_GUARDED = (
    "package m\n\nfunc Load(p string) error {\n"
    "\tp = filepath.Clean(p)\n\treturn os.ReadFile(p)\n}\n"
)

TS_BASE = (
    "function serve(req, res) {\n  res.send(render(req.host));\n}\n"
)
TS_GUARDED = (
    "function serve(req, res) {\n"
    "  if (!allowedHosts.has(req.host)) {\n"
    '    throw new Error("bad host");\n'
    "  }\n  res.send(render(req.host));\n}\n"
)
TS_REFLOWED = (
    "function serve(req, res) {\n"
    "  if (!allowedHosts.has(req.host))\n"
    "  {\n"
    '    throw new Error("bad host");\n'
    "  }\n  res.send(render(req.host));\n}\n"
)


def test_go_validation_call_removed_is_candidate(make_repo):
    r, ext, tr = _track(
        make_repo,
        [
            {"files": {"srv.go": GO_BASE}, "message": "base"},
            {"files": {"srv.go": GO_GUARDED}, "message": SEED_MSG},
            {"files": {"srv.go": GO_BASE}, "message": "refactor"},
        ],
    )
    out = tr.outcomes[0]
    assert out.guard.shape == "validation-call"
    assert out.status == "candidate"
    assert out.candidate_sha == r.shas[2]


def test_ts_brace_reflow_stays_intact(make_repo):
    r, ext, tr = _track(
        make_repo,
        [
            {"files": {"srv.ts": TS_BASE}, "message": "base"},
            {"files": {"srv.ts": TS_GUARDED}, "message": SEED_MSG},
            {"files": {"srv.ts": TS_REFLOWED}, "message": "reformat"},
        ],
    )
    out = tr.outcomes[0]
    assert out.status == "intact"
    assert [e.sha for e in out.mutation_events] == [r.shas[2]]


def test_track_failure_records_error_and_unverifiable(
    make_repo, monkeypatch
):
    r = make_repo(
        [
            {"files": {"app.py": BASE}, "message": "base"},
            {"files": {"app.py": GUARDED}, "message": SEED_MSG},
        ]
    )
    seed_set = seeds.collect_seeds(r.root)
    ext = extract.extract_guards(r.root, seed_set)

    def boom(repo, sha, path):
        raise gitlog.GitError(["git", "show"], 128, "boom")

    monkeypatch.setattr(gitlog, "show_file", boom)
    tr = track.track_guards(r.root, ext.records)
    assert len(tr.errors) == 1
    assert tr.errors[0]["stage"] == "track"
    out = tr.outcomes[0]
    assert out.status == "unverifiable"
    assert "track-error" in out.markers


def test_cli_intact_count_and_no_candidates(
    make_repo, tmp_path, capsys, read_jsonl
):
    r = make_repo(
        [
            {"files": {"app.py": BASE}, "message": "base"},
            {"files": {"app.py": GUARDED}, "message": SEED_MSG},
        ]
    )
    out = tmp_path / "o.jsonl"
    assert cli.main([r.root, "--out", str(out)]) == 0
    line = capsys.readouterr().out.strip()
    assert "tracked=1" in line
    assert "intact=1" in line
    rows = read_jsonl(out)
    assert not any(row["type"] == "candidate" for row in rows)


def test_cli_track_error_row(make_repo, tmp_path, capsys, read_jsonl,
                             monkeypatch):
    r = make_repo(
        [
            {"files": {"app.py": BASE}, "message": "base"},
            {"files": {"app.py": GUARDED}, "message": SEED_MSG},
        ]
    )

    def boom(repo, path, until=None):
        raise gitlog.GitError(["git", "log"], 128, "boom")

    monkeypatch.setattr(gitlog, "path_events", boom)
    out = tmp_path / "o.jsonl"
    assert cli.main([r.root, "--out", str(out)]) == 0
    rows = read_jsonl(out)
    assert any(
        row["type"] == "error" and row["stage"] == "track" for row in rows
    )
    line = capsys.readouterr().out.strip()
    assert "unknown=1" in line
