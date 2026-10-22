"""classify.py: the five-verdict removal classifier (R8-R11, KD2).

Every verdict class is exercised through planted fixture histories run
end-to-end (seeds -> extract -> track -> classify); assertions pin the
evidence record, not just the label.
"""

from pathlib import Path

from archaeology import classify, cli, extract, gitlog, seeds, track
from conftest import commit_env, run_git

BASE = "def recv(body):\n    return open(body).read()\n"

GUARDED = (
    "def recv(body):\n"
    "    if len(body) > MAX_LEN:\n"
    '        raise ValueError("big")\n'
    "    return open(body).read()\n"
)

# a different-shape guard of the same family (validation): the
# conditional rejection is replaced by a sanitizing call
GUARDED_VALIDATION = (
    "def recv(body):\n"
    "    if not is_valid(body):\n"
    '        raise ValueError("bad")\n'
    "    return open(body).read()\n"
)
REPLACED_SAME_FAMILY = (
    "def recv(body):\n"
    "    body = validate_body(body)\n"
    "    return open(body).read()\n"
)
REPLACED_OTHER_FAMILY = (
    "def recv(body):\n"
    "    body = escape_html(body)\n"
    "    return open(body).read()\n"
)

# relocated: the same bounds guard moved into a caller in another file
CALLER_D1 = (
    "from app import recv\n\n"
    "def handle(body):\n"
    "    if len(body) > MAX_LEN:\n"
    '        raise ValueError("big")\n'
    "    return recv(body)\n"
)
CALLER_D2 = (
    "from app import recv\n\n"
    "def mid(body):\n"
    "    return recv(body)\n\n"
    "def handle(body):\n"
    "    if len(body) > MAX_LEN:\n"
    '        raise ValueError("big")\n'
    "    return mid(body)\n"
)
MID_PLAIN = (
    "from app import recv\n\n"
    "def mid(body):\n"
    "    return recv(body)\n\n"
    "def handle(body):\n"
    "    return mid(body)\n"
)
ENTRY_GUARDED = (
    "from mid import handle\n\n"
    "def entry(body):\n"
    "    if len(body) > MAX_LEN:\n"
    '        raise ValueError("big")\n'
    "    return handle(body)\n"
)

# relocated: the guard moved into a shared helper on the sink path
HELPER_FILE = (
    "def check_len(data):\n"
    "    if len(data) > MAX_LEN:\n"
    '        raise ValueError("big")\n'
)
CALLS_HELPER = (
    "from helpers import check_len\n\n"
    "def recv(body):\n"
    "    check_len(body)\n"
    "    return open(body).read()\n"
)

# a caller resolvable only through getattr/dispatch
DISPATCH = (
    "import app\n\n"
    "def use(data):\n"
    "    return getattr(app, 'recv')(data)\n"
)

SEED_MSG = "fix overflow bounds check"


def _classify(make_repo, commits, depth=2, until=None):
    """Planted history -> (BuiltRepo, Extraction, Tracking, Classification)."""
    r = make_repo(commits)
    seed_set = seeds.collect_seeds(r.root)
    ext = extract.extract_guards(r.root, seed_set)
    assert len(ext.records) == 1
    tr = track.track_guards(r.root, ext.records, until=until)
    cl = classify.classify_all(r.root, tr.outcomes, caller_depth=depth)
    return r, ext, tr, cl


def test_regressed_silent_removal(make_repo):
    # an exported function with zero in-repo callers is provable on its
    # own scope, so it can still reach REGRESSED
    r, ext, tr, cl = _classify(
        make_repo,
        [
            {"files": {"app.py": BASE}, "message": "base"},
            {"files": {"app.py": GUARDED}, "message": SEED_MSG},
            {"files": {"app.py": BASE}, "message": "refactor"},
        ],
    )
    assert cl.errors == ()
    v = cl.verdicts[0]
    assert v.verdict == "regressed"
    assert v.removal_sha == r.shas[2]
    assert v.removal_subject == "refactor"
    ev = set(v.evidence)
    assert f"removal={r.shas[2]}" in ev
    assert "coverage:removal=absent" in ev
    assert "coverage:boundary=absent" in ev
    assert "family-absent:removal+boundary" in ev
    assert "sink-present:boundary" in ev


def test_removed_with_sink_function_deleted(make_repo):
    r, _e, tr, cl = _classify(
        make_repo,
        [
            {"files": {"app.py": BASE}, "message": "base"},
            {"files": {"app.py": GUARDED}, "message": SEED_MSG},
            {
                "files": {"app.py": "def other():\n    return 1\n"},
                "message": "drop the feature",
            },
        ],
    )
    assert tr.outcomes[0].status == "candidate"
    v = cl.verdicts[0]
    assert v.verdict == "removed_with_sink"
    assert "sink-absent:removal" in v.evidence


def test_removed_with_sink_file_deleted(make_repo):
    r, _e, tr, cl = _classify(
        make_repo,
        [
            {"files": {"app.py": BASE}, "message": "base"},
            {"files": {"app.py": GUARDED}, "message": SEED_MSG},
            {"deletions": ["app.py"], "message": "drop app.py"},
        ],
    )
    assert tr.outcomes[0].status == "deleted"
    v = cl.verdicts[0]
    assert v.verdict == "removed_with_sink"
    assert any(e.startswith("lineage-delete:") for e in v.evidence)


def test_deliberate_revert_wording_sink_alive(make_repo):
    r, _e, tr, cl = _classify(
        make_repo,
        [
            {"files": {"app.py": BASE}, "message": "base"},
            {"files": {"app.py": GUARDED}, "message": SEED_MSG},
            {
                "files": {"app.py": BASE},
                "message": "revert the bounds check",
            },
        ],
    )
    assert tr.outcomes[0].status == "candidate"
    v = cl.verdicts[0]
    assert v.verdict == "deliberate"
    assert "deliberate:revert-language" in v.evidence


def test_deliberate_seed_sha_in_message(make_repo):
    r, _e, tr, cl = _classify(
        make_repo,
        [
            {"files": {"app.py": BASE}, "message": "base"},
            {"files": {"app.py": GUARDED}, "message": SEED_MSG},
        ],
    )
    seed_sha = r.shas[1]
    run_git(r.root, "rm", "-q", "app.py")
    Path(r.root, "app.py").write_text(BASE)
    run_git(r.root, "add", "app.py")
    run_git(
        r.root, "commit", "-q", "-m", f"roll back {seed_sha[:10]}",
        env_extra=commit_env(9),
    )
    tr = track.track_guards(r.root, _ext_guards(r.root))
    cl = classify.classify_all(r.root, tr.outcomes)
    assert cl.verdicts[0].verdict == "deliberate"
    assert "deliberate:seed-sha" in cl.verdicts[0].evidence


def _ext_guards(root):
    seed_set = seeds.collect_seeds(root)
    return extract.extract_guards(root, seed_set).records


def test_deliberate_via_merge_constituent(make_repo):
    # the removal commit is a merge; a constituent commit's message
    # carries the deliberate wording (R10: the only linked-PR language a
    # local clone carries)
    r = make_repo(
        [
            {"files": {"app.py": BASE}, "message": "base"},
            {"files": {"app.py": GUARDED}, "message": SEED_MSG},
        ]
    )
    run_git(r.root, "checkout", "-q", "-b", "side")
    Path(r.root, "notes.txt").write_text("x\n")
    run_git(r.root, "add", "notes.txt")
    run_git(
        r.root, "commit", "-q", "-m",
        "drop the bounds check, no longer needed",
        env_extra=commit_env(10),
    )
    run_git(r.root, "checkout", "-q", "main")
    run_git(
        r.root, "merge", "--no-ff", "-m", "merge side", "side",
        env_extra=commit_env(11),
    )
    merge_sha = run_git(r.root, "rev-parse", "HEAD").stdout.strip()
    texts = classify.removal_texts(r.root, merge_sha)
    assert any("no longer needed" in t for t in texts)
    recs, _skips = extract.extract_file("python", "app.py", GUARDED, [2, 3])
    outcome = track.TrackOutcome(
        guard=recs[0],
        status="candidate",
        path_chain=("app.py",),
        renames=(),
        boundary_sha=merge_sha,
        boundary_path="app.py",
        boundary_present=True,
        boundary_excerpt=None,
        add_confirmed=True,
        candidate_sha=merge_sha,
        removal_parent_sha=None,
        mutation_events=(),
        lineage_break=None,
        markers=(),
    )
    v = classify.classify_outcome(r.root, outcome)
    assert v.verdict == "deliberate"
    assert any(e.startswith("deliberate:") for e in v.evidence)


def test_relocated_guard_in_caller_depth1(make_repo):
    r, _e, tr, cl = _classify(
        make_repo,
        [
            {"files": {"app.py": BASE}, "message": "base"},
            {"files": {"app.py": GUARDED}, "message": SEED_MSG},
            {
                "files": {"app.py": BASE, "handlers.py": CALLER_D1},
                "message": "move check into caller",
            },
        ],
    )
    assert tr.outcomes[0].status == "candidate"
    v = cl.verdicts[0]
    assert v.verdict == "relocated"
    assert "family-covered:removal+boundary" in v.evidence
    assert any(e.startswith("caller:handlers.py") for e in v.evidence)


def test_relocated_guard_in_shared_helper(make_repo):
    r, _e, tr, cl = _classify(
        make_repo,
        [
            {"files": {"app.py": BASE, "helpers.py": HELPER_FILE},
             "message": "base"},
            {"files": {"app.py": GUARDED}, "message": SEED_MSG},
            {
                "files": {"app.py": CALLS_HELPER},
                "message": "move check into helper",
            },
        ],
    )
    v = cl.verdicts[0]
    assert v.verdict == "relocated"
    assert any("callee" in e for e in v.evidence)


def test_relocated_guard_at_depth2_not_depth1(make_repo):
    commits = [
        {"files": {"app.py": BASE}, "message": "base"},
        {"files": {"app.py": GUARDED}, "message": SEED_MSG},
        {
            "files": {"app.py": BASE, "mid.py": CALLER_D2},
            "message": "move check two hops up",
        },
    ]
    _r, _e, _t, deep = _classify(make_repo, commits, depth=2)
    assert deep.verdicts[0].verdict == "relocated"
    _r, _e, _t, shallow = _classify(make_repo, commits, depth=1)
    assert shallow.verdicts[0].verdict == "regressed"


def test_different_shape_same_family_relocated(make_repo):
    r, _e, tr, cl = _classify(
        make_repo,
        [
            {"files": {"app.py": BASE}, "message": "base"},
            {"files": {"app.py": GUARDED_VALIDATION}, "message": SEED_MSG},
            {
                "files": {"app.py": REPLACED_SAME_FAMILY},
                "message": "refactor validation",
            },
        ],
    )
    assert tr.outcomes[0].status == "candidate"
    v = cl.verdicts[0]
    assert v.verdict == "relocated"
    assert any(e.startswith("coverage:") for e in v.evidence)


def test_different_family_replacement_is_regressed(make_repo):
    r, _e, tr, cl = _classify(
        make_repo,
        [
            {"files": {"app.py": BASE}, "message": "base"},
            {"files": {"app.py": GUARDED_VALIDATION}, "message": SEED_MSG},
            {
                "files": {"app.py": REPLACED_OTHER_FAMILY},
                "message": "refactor validation",
            },
        ],
    )
    v = cl.verdicts[0]
    assert v.verdict == "regressed"


def test_delete_recreate_is_unknown_not_removed_with_sink(make_repo):
    fresh = "def g(d):\n    return os.popen(d).read()\n"
    r, _e, tr, cl = _classify(
        make_repo,
        [
            {"files": {"app.py": BASE}, "message": "base"},
            {"files": {"app.py": GUARDED}, "message": SEED_MSG},
            {"deletions": ["app.py"], "message": "drop app.py"},
            {"files": {"app.py": fresh}, "message": "re-add app.py"},
        ],
    )
    assert tr.outcomes[0].status == "severed"
    v = cl.verdicts[0]
    assert v.verdict == "unknown"
    assert any(e.startswith("lost-lineage:") for e in v.evidence)


def test_getattr_dispatch_caller_is_unknown(make_repo):
    r, _e, tr, cl = _classify(
        make_repo,
        [
            {
                "files": {"app.py": BASE, "helpers.py": DISPATCH},
                "message": "base",
            },
            {"files": {"app.py": GUARDED}, "message": SEED_MSG},
            {"files": {"app.py": BASE}, "message": "refactor"},
        ],
    )
    assert tr.outcomes[0].status == "candidate"
    v = cl.verdicts[0]
    assert v.verdict == "unknown"
    assert "coverage:boundary=unprovable" in v.evidence


def test_intact_outcome_never_reaches_classifier(make_repo):
    r, ext, tr, cl = _classify(
        make_repo,
        [
            {"files": {"app.py": BASE}, "message": "base"},
            {"files": {"app.py": GUARDED}, "message": SEED_MSG},
        ],
    )
    assert tr.outcomes[0].status == "intact"
    assert cl.verdicts == ()


def test_classify_error_degrades_to_unknown(make_repo, monkeypatch):
    r = make_repo(
        [
            {"files": {"app.py": BASE}, "message": "base"},
            {"files": {"app.py": GUARDED}, "message": SEED_MSG},
            {"files": {"app.py": BASE}, "message": "refactor"},
        ]
    )
    ext = extract.extract_guards(r.root, seeds.collect_seeds(r.root))
    tr = track.track_guards(r.root, ext.records)

    def boom(repo, pattern, sha):
        raise gitlog.GitError(["git", "grep"], 128, "boom")

    monkeypatch.setattr(gitlog, "grep_files", boom)
    cl = classify.classify_all(r.root, tr.outcomes)
    assert len(cl.errors) == 1
    assert cl.errors[0]["stage"] == "classify"
    assert cl.verdicts[0].verdict == "unknown"


def test_cli_summary_reports_real_verdicts(make_repo, tmp_path, capsys):
    # one intact guard plus one silently removed guard: the summary line
    # reports both real classes, not stubbed counts
    other_base = "def load(p):\n    return os.popen(p).read()\n"
    other_guarded = (
        "def load(p):\n"
        "    if len(p) > CAP:\n"
        "        raise ValueError('big')\n"
        "    return os.popen(p).read()\n"
    )
    r = make_repo(
        [
            {
                "files": {"app.py": BASE, "b.py": other_base},
                "message": "base",
            },
            {"files": {"app.py": GUARDED}, "message": SEED_MSG},
            {
                "files": {"b.py": other_guarded},
                "message": "fix command injection vuln",
            },
            {"files": {"app.py": BASE}, "message": "refactor"},
        ]
    )
    out = tmp_path / "o.jsonl"
    assert cli.main([r.root, "--out", str(out)]) == 0
    line = capsys.readouterr().out.strip()
    assert "tracked=2" in line
    assert "intact=1" in line
    assert "regressed=1" in line


def test_cli_caller_depth_flag_changes_verdict(
    make_repo, tmp_path, capsys
):
    # guard three hops up: REGRESSED under the default bound, RELOCATED
    # once --caller-depth reaches it
    commits = [
        {"files": {"app.py": BASE}, "message": "base"},
        {"files": {"app.py": GUARDED}, "message": SEED_MSG},
        {
            "files": {
                "app.py": BASE,
                "mid.py": MID_PLAIN,
                "entry.py": ENTRY_GUARDED,
            },
            "message": "move check three hops up",
        },
    ]
    r = make_repo(commits)
    out = tmp_path / "o.jsonl"
    assert cli.main([r.root, "--out", str(out)]) == 0
    assert "regressed=1" in capsys.readouterr().out
    assert cli.main(
        [r.root, "--out", str(out), "--caller-depth", "3"]
    ) == 0
    assert "relocated=1" in capsys.readouterr().out
