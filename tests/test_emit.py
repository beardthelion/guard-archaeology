"""emit.py: archaeology.jsonl rows, determinism, exposure + holdout join
(R12-R16, R18, KTD10, KTD11)."""

import json
import os
import re

from archaeology import cli, emit

BASE = "def recv(body):\n    return open(body).read()\n"
GUARDED = (
    "def recv(body):\n"
    "    if len(body) > MAX_LEN:\n"
    '        raise ValueError("big")\n'
    "    return open(body).read()\n"
)
SEED_MSG = "fix overflow bounds check CVE-2024-42424"

REGRESSED_COMMITS = [
    {"files": {"app.py": BASE}, "message": "base"},
    {"files": {"app.py": GUARDED}, "message": SEED_MSG},
    {"files": {"app.py": BASE}, "message": "refactor"},
]

B2_BASE = "def load(p):\n    return os.popen(p).read()\n"
B2_GUARDED = (
    "def load(p):\n"
    "    if len(p) > CAP:\n"
    "        raise ValueError('big')\n"
    "    return os.popen(p).read()\n"
)

EXPECTED = os.path.join(
    os.path.dirname(__file__), "fixtures", "expected-archaeology.jsonl"
)


def _plant_clawpatch(root, name, text):
    cp = os.path.join(root, ".clawpatch")
    os.makedirs(cp, exist_ok=True)
    path = os.path.join(cp, name)
    with open(path, "w") as fh:
        fh.write(text)
    return path


def _plant_holdout(root, rows):
    return _plant_clawpatch(
        root, "holdout.jsonl", "".join(json.dumps(r) + "\n" for r in rows)
    )


def test_golden_jsonl_byte_identical(make_repo, tmp_path, run_cli):
    r = make_repo(REGRESSED_COMMITS)
    out = tmp_path / "a.jsonl"
    run_cli(r.root, out)
    first = out.read_bytes()
    run_cli(r.root, out)
    assert out.read_bytes() == first
    with open(EXPECTED, "rb") as fh:
        assert first == fh.read()


def test_header_counts_sum_to_tracked(
    make_repo, tmp_path, run_cli, read_jsonl
):
    r = make_repo(REGRESSED_COMMITS)
    out = tmp_path / "a.jsonl"
    run_cli(r.root, out)
    hdr = read_jsonl(out)[0]
    assert hdr["type"] == "run"
    total = (
        hdr["intact"]
        + hdr["regressed"]
        + hdr["relocated"]
        + hdr["removed_with_sink"]
        + hdr["deliberate"]
        + hdr["unknown"]
    )
    assert total == hdr["tracked"]


def test_candidate_row_shape(
    make_repo, tmp_path, run_cli, read_jsonl, candidates
):
    r = make_repo(REGRESSED_COMMITS)
    out = tmp_path / "a.jsonl"
    run_cli(r.root, out)
    rows = read_jsonl(out)
    cands = candidates(rows)
    assert len(cands) == 1
    c = cands[0]
    assert re.fullmatch(r"archaeology-\w+-[0-9a-f]{10}", c["id"])
    assert c["family"]
    assert c["sink"]["path"] == "app.py"
    assert c["sink"]["function"] == "recv"
    assert isinstance(c["sink"]["line"], int) and c["sink"]["line"] > 0
    assert "open(" in c["sink"]["operation"]
    assert c["missing_guard"]["signature"]
    assert c["missing_guard"]["shape"] == "conditional-rejection"
    assert c["seed"] == {"sha": r.shas[1], "advisory": None}
    assert c["removal"] == {"sha": r.shas[2], "subject": "refactor"}
    assert "open(body).read()" in c["current"]
    assert c["exposure"] == "unknown"
    assert c["siblings"] == []
    assert c["entry"] is None
    assert c["holdout"] is None


def test_candidates_sorted_by_removal_date(
    make_repo, tmp_path, run_cli, read_jsonl, candidates
):
    r = make_repo(
        [
            {
                "files": {"app.py": BASE, "b.py": B2_BASE},
                "message": "base",
            },
            {"files": {"app.py": GUARDED}, "message": SEED_MSG},
            {
                "files": {"b.py": B2_GUARDED},
                "message": "fix command injection vuln CVE-2024-42425",
            },
            {"files": {"b.py": B2_BASE}, "message": "cleanup b"},
            {"files": {"app.py": BASE}, "message": "refactor"},
        ]
    )
    out = tmp_path / "a.jsonl"
    run_cli(r.root, out)
    cands = candidates(read_jsonl(out))
    assert [c["sink"]["path"] for c in cands] == ["b.py", "app.py"]
    assert cands[0]["removal"]["sha"] == r.shas[3]
    assert cands[1]["removal"]["sha"] == r.shas[4]


def test_error_row_for_unresolvable_seed_exits_zero(
    make_repo, tmp_path, read_jsonl
):
    r = make_repo(REGRESSED_COMMITS)
    seeds_file = tmp_path / "seeds.txt"
    seeds_file.write_text("0" * 40 + " GHSA-xxxx-xxxx-xxxx\n")
    out = tmp_path / "a.jsonl"
    assert (
        cli.main(
            [r.root, "--out", str(out), "--seeds-file", str(seeds_file)]
        )
        == 0
    )
    rows = read_jsonl(out)
    errs = [x for x in rows if x["type"] == "error"]
    assert len(errs) == 1
    assert errs[0]["stage"] == "seeds"
    assert errs[0]["reason"] == "unresolvable-in-window"
    assert errs[0]["advisory_id"] == "GHSA-xxxx-xxxx-xxxx"


def test_scope_boundary_applies_to_candidate(
    make_repo, tmp_path, run_cli, read_jsonl, candidates
):
    r = make_repo(REGRESSED_COMMITS)
    _plant_clawpatch(
        r.root,
        "scope-boundary.md",
        "- app.py:recv TAINT: yes entry=POST /recv\n",
    )
    out = tmp_path / "a.jsonl"
    run_cli(r.root, out)
    c = candidates(read_jsonl(out))[0]
    assert c["exposure"] == "untrusted"
    assert c["entry"] == "POST"


def test_exposure_file_wins_for_candidate(
    make_repo, tmp_path, run_cli, read_jsonl, candidates
):
    r = make_repo(REGRESSED_COMMITS)
    _plant_clawpatch(
        r.root, "scope-boundary.md", "- app.py:recv TAINT: yes\n"
    )
    ef = tmp_path / "exp.json"
    ef.write_text(json.dumps({"app.py:recv": "internal"}))
    out = tmp_path / "a.jsonl"
    run_cli(r.root, out, "--exposure-file", str(ef))
    c = candidates(read_jsonl(out))[0]
    assert c["exposure"] == "internal"
    assert c["entry"] is None


def test_holdout_join_on_matching_sink(
    make_repo, tmp_path, run_cli, read_jsonl, candidates
):
    r = make_repo(REGRESSED_COMMITS)
    _plant_holdout(
        r.root,
        [
            {
                "type": "candidate",
                "id": "holdout-bounds-0123456789",
                "family": "bounds",
                "rank_score": 0.9,
                "sink": {
                    "path": "app.py",
                    "function": "recv",
                    "line": 1,
                    "operation": "open",
                },
            },
            {
                "type": "candidate",
                "id": "holdout-other",
                "family": "auth",
                "rank_score": 0.1,
                "sink": {
                    "path": "other.py",
                    "function": "f",
                    "line": 1,
                    "operation": "y",
                },
            },
            {"type": "family", "family": "bounds", "sites": 3},
        ],
    )
    out = tmp_path / "a.jsonl"
    run_cli(r.root, out)
    c = candidates(read_jsonl(out))[0]
    assert c["holdout"] == {
        "id": "holdout-bounds-0123456789",
        "family": "bounds",
        "rank_score": 0.9,
    }


def test_holdout_index_normalizes_qualnames(tmp_path):
    root = tmp_path / "repo"
    (root / ".clawpatch").mkdir(parents=True)
    _plant_holdout(
        str(root),
        [
            {
                "type": "candidate",
                "id": "h1",
                "family": "bounds",
                "rank_score": 0.5,
                "sink": {
                    "path": "a.rs",
                    "function": "m::serve",
                    "line": 1,
                    "operation": "x",
                },
            }
        ],
    )
    idx = emit.load_holdout_rows(str(root))
    assert ("a.rs", "m.serve") in idx
    assert emit.norm_qualname("pkg::Type::method") == "pkg.Type.method"
    assert emit.norm_qualname("Class.method") == "Class.method"


def test_malformed_holdout_warns_field_null(
    make_repo, tmp_path, capsys, run_cli, read_jsonl, candidates
):
    r = make_repo(REGRESSED_COMMITS)
    _plant_clawpatch(r.root, "holdout.jsonl", "{not json\n")
    out = tmp_path / "a.jsonl"
    run_cli(r.root, out)
    assert "holdout" in capsys.readouterr().err
    c = candidates(read_jsonl(out))[0]
    assert c["holdout"] is None


def test_holdout_symlink_escape_ignored(
    make_repo, tmp_path, capsys, run_cli, read_jsonl, candidates
):
    r = make_repo(REGRESSED_COMMITS)
    outside = tmp_path / "outside.jsonl"
    outside.write_text(
        json.dumps(
            {
                "type": "candidate",
                "id": "h",
                "family": "bounds",
                "rank_score": 1,
                "sink": {"path": "app.py", "function": "recv"},
            }
        )
        + "\n"
    )
    cp = os.path.join(r.root, ".clawpatch")
    os.makedirs(cp, exist_ok=True)
    os.symlink(outside, os.path.join(cp, "holdout.jsonl"))
    out = tmp_path / "a.jsonl"
    run_cli(r.root, out)
    assert "outside target root" in capsys.readouterr().err
    c = candidates(read_jsonl(out))[0]
    assert c["holdout"] is None


def test_non_utf8_holdout_warns_and_is_ignored(
    make_repo, tmp_path, capsys, run_cli, read_jsonl, candidates
):
    r = make_repo(REGRESSED_COMMITS)
    cp = os.path.join(r.root, ".clawpatch")
    os.makedirs(cp, exist_ok=True)
    with open(os.path.join(cp, "holdout.jsonl"), "wb") as fh:
        fh.write(b"\xff\xfe not utf-8\n")
    out = tmp_path / "a.jsonl"
    run_cli(r.root, out)
    assert "unreadable holdout.jsonl" in capsys.readouterr().err
    c = candidates(read_jsonl(out))[0]
    assert c["holdout"] is None


def test_deeply_nested_holdout_line_warns_and_is_ignored(
    make_repo, tmp_path, capsys, run_cli, read_jsonl, candidates
):
    r = make_repo(REGRESSED_COMMITS)
    depth = 10000  # deep enough that json.loads raises RecursionError
    _plant_holdout(r.root, [])
    path = os.path.join(r.root, ".clawpatch", "holdout.jsonl")
    with open(path, "w") as fh:
        fh.write("[" * depth + "]" * depth + "\n")
    out = tmp_path / "a.jsonl"
    run_cli(r.root, out)
    assert "malformed" in capsys.readouterr().err
    c = candidates(read_jsonl(out))[0]
    assert c["holdout"] is None


def test_row_id_distinguishes_sibling_guards_on_one_sink():
    # two guards on the same sink from one seed differ only in
    # signature; the id input includes it
    a = emit.row_id("bounds", "app.py", "recv", "s" * 40, "sig-a")
    b = emit.row_id("bounds", "app.py", "recv", "s" * 40, "sig-b")
    assert a != b
    assert a == emit.row_id(
        "bounds", "app.py", "recv", "s" * 40, "sig-a"
    )


def test_boundary_sink_ignores_comment_lookalike(
    make_repo, tmp_path, run_cli, read_jsonl, candidates
):
    # a comment mentioning 'open(' far above the sink function must not
    # anchor the sink line or excerpt
    commented = (
        "# do not call open( without checks\n"
        "\n\n\n\n"
        + BASE
    )
    r = make_repo(
        [
            {"files": {"app.py": commented}, "message": "base"},
            {
                "files": {
                    "app.py": (
                        "# do not call open( without checks\n"
                        "\n\n\n\n"
                        + GUARDED
                    )
                },
                "message": SEED_MSG,
            },
            {"files": {"app.py": commented}, "message": "refactor"},
        ]
    )
    out = tmp_path / "a.jsonl"
    run_cli(r.root, out)
    c = candidates(read_jsonl(out))[0]
    assert c["sink"]["line"] == 7
    assert "return open(body).read()" in c["current"]


def test_also_md_renders_same_row_set(
    make_repo, tmp_path, run_cli, read_jsonl, candidates
):
    r = make_repo(REGRESSED_COMMITS)
    out = tmp_path / "a.jsonl"
    run_cli(r.root, out, "--also-md")
    md_path = tmp_path / "a.md"
    assert md_path.exists()
    md = md_path.read_text()
    rows = read_jsonl(out)
    hdr = rows[0]
    assert f"- regressed: {hdr['regressed']}" in md
    assert f"- tracked: {hdr['tracked']}" in md
    c = candidates(rows)[0]
    loc = (
        f"{c['sink']['path']}:{c['sink']['function']}:{c['sink']['line']}"
    )
    assert loc in md
    assert f"## {c['family']}" in md
    assert c["removal"]["sha"] in md


TBASE = "def t(body):\n    return open(body).read()\n"
TGUARDED = (
    "def t(body):\n"
    "    if len(body) > MAX_LEN:\n"
    '        raise ValueError("big")\n'
    "    return open(body).read()\n"
)
ASSERT_GUARDED = (
    "def recv(body):\n"
    "    assert_len(body, MAX_LEN)\n"
    "    return open(body).read()\n"
)


def test_test_path_sink_produces_no_candidate(
    make_repo, tmp_path, run_cli, read_jsonl, candidates, capsys
):
    # the seed also touches app.py, so the test-only seed drop does not
    # remove it; extraction still records the test-file guard, but
    # emission filters it and the header reports regressed=0
    r = make_repo(
        [
            {
                "files": {"app.py": BASE, "tests/test_recv.py": TBASE},
                "message": "base",
            },
            {
                "files": {
                    "app.py": "# a note\n" + BASE,
                    "tests/test_recv.py": TGUARDED,
                },
                "message": SEED_MSG,
            },
            {
                "files": {"app.py": BASE, "tests/test_recv.py": TBASE},
                "message": "refactor",
            },
        ]
    )
    out = tmp_path / "a.jsonl"
    run_cli(r.root, out)
    rows = read_jsonl(out)
    hdr = rows[0]
    assert hdr["tracked"] == 1
    assert hdr["regressed"] == 0
    assert candidates(rows) == []
    assert "regressed=0" in capsys.readouterr().out


def test_mixed_test_and_code_sinks_emit_only_code_candidate(
    make_repo, tmp_path, run_cli, read_jsonl, candidates
):
    r = make_repo(
        [
            {
                "files": {"app.py": BASE, "tests/test_recv.py": TBASE},
                "message": "base",
            },
            {
                "files": {"app.py": GUARDED, "tests/test_recv.py": TGUARDED},
                "message": SEED_MSG,
            },
            {
                "files": {"app.py": BASE, "tests/test_recv.py": TBASE},
                "message": "refactor",
            },
        ]
    )
    out = tmp_path / "a.jsonl"
    run_cli(r.root, out)
    rows = read_jsonl(out)
    cands = candidates(rows)
    assert [c["sink"]["path"] for c in cands] == ["app.py"]
    assert rows[0]["regressed"] == 1


def test_assert_call_guard_on_non_test_path_still_regresses(
    make_repo, tmp_path, run_cli, read_jsonl, candidates
):
    # an assert-shaped guard on a runtime path is a legit guard shape
    # (a runtime invariant), only test-path sinks are filtered
    r = make_repo(
        [
            {"files": {"app.py": BASE}, "message": "base"},
            {"files": {"app.py": ASSERT_GUARDED}, "message": SEED_MSG},
            {"files": {"app.py": BASE}, "message": "refactor"},
        ]
    )
    out = tmp_path / "a.jsonl"
    run_cli(r.root, out)
    cands = candidates(read_jsonl(out))
    assert len(cands) == 1
    assert cands[0]["sink"]["path"] == "app.py"
    assert cands[0]["family"] == "validation"
