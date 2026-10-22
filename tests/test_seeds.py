import json

import pytest

from archaeology import cli, seeds

SIGNAL_SCRIPT = [
    {"files": {"a.py": "x = 1\n"}, "message": "initial import"},
    {
        "files": {"b.py": "x = 1\n"},
        "message": "fix security overflow in parser",
    },
    {
        "files": {"c.py": "x = 1\n"},
        "message": "patch CVE-2024-12345 handling",
    },
    {"files": {"d.py": "x = 1\n"}, "message": "improve validation messages"},
    {"files": {"e.py": "x = 1\n"}, "message": "fix typo in comment"},
    {
        "files": {"f.py": "x = 1\n"},
        "message": "resolve GHSA-1234-abcd-5678 issue",
    },
]


def _seeds(repo_root, **kw):
    return seeds.collect_seeds(repo_root, **kw)


def test_message_signals_select_exact_commits(make_repo):
    r = make_repo(SIGNAL_SCRIPT)
    # advisory (default): only the CVE/GHSA-linked commits seed; the
    # fix-verb x security-term harvest is off
    ss = _seeds(r.root)
    assert [s.sha for s in ss.seeds] == [r.shas[2], r.shas[5]]
    assert not ss.unresolvable
    # message/all restore the fix-verb x security-term harvest
    for mode in ("message", "all"):
        ss = _seeds(r.root, seeds_mode=mode)
        assert [s.sha for s in ss.seeds] == [
            r.shas[1], r.shas[2], r.shas[5],
        ]
        assert not ss.unresolvable


def test_unknown_seeds_mode_is_a_typed_error(make_repo):
    r = make_repo(SIGNAL_SCRIPT)
    with pytest.raises(seeds.SeedsError):
        _seeds(r.root, seeds_mode="everything")


def test_cve_and_ghsa_seed_but_lone_terms_do_not(make_repo):
    r = make_repo(SIGNAL_SCRIPT)
    shas = {s.sha for s in _seeds(r.root).seeds}
    assert r.shas[2] in shas  # CVE id
    assert r.shas[5] in shas  # GHSA id
    assert r.shas[3] not in shas  # security term, no fix verb
    assert r.shas[4] not in shas  # fix verb, no security term
    assert r.shas[0] not in shas


def test_signal_unit_checks():
    assert seeds.message_has_signal("fix auth bypass in login")
    assert seeds.message_has_signal("close traversal in path join")
    assert seeds.message_has_signal("", "see CVE-2024-9999 for details")
    assert not seeds.message_has_signal("improve validation messages")
    assert not seeds.message_has_signal("update author list")
    assert not seeds.message_has_signal("fix typo")


def test_seeds_file_with_advisory_ids(make_repo, tmp_path):
    r = make_repo(SIGNAL_SCRIPT)
    f = tmp_path / "seeds.txt"
    f.write_text(
        f"{r.shas[0]} GHSA-9999-aaaa-1111\n"
        f"{r.shas[3]}\n"
        "# a comment line\n"
        "\n"
    )
    ss = _seeds(r.root, seeds_file=str(f))
    by_sha = {s.sha: s for s in ss.seeds}
    # a never-signaled commit still seeds on advisory authority
    assert r.shas[0] in by_sha
    assert r.shas[3] in by_sha
    assert by_sha[r.shas[0]].advisory_id == "GHSA-9999-aaaa-1111"
    assert by_sha[r.shas[3]].advisory_id is None
    assert by_sha[r.shas[0]].source == seeds.SOURCE_SEEDS_FILE


def test_dedup_prefers_advisory_record(make_repo, tmp_path):
    r = make_repo(SIGNAL_SCRIPT)
    f = tmp_path / "seeds.txt"
    f.write_text(f"{r.shas[1]} CVE-2024-7777\n")
    ss = _seeds(r.root, seeds_file=str(f))
    recs = [s for s in ss.seeds if s.sha == r.shas[1]]
    assert len(recs) == 1
    assert recs[0].advisory_id == "CVE-2024-7777"
    assert recs[0].source == seeds.SOURCE_SEEDS_FILE


def test_unresolvable_seed_produces_explicit_record(make_repo, tmp_path):
    r = make_repo(SIGNAL_SCRIPT)
    f = tmp_path / "seeds.txt"
    f.write_text("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef GHSA-0000-0000-0000\n")
    ss = _seeds(r.root, seeds_file=str(f))
    assert len(ss.unresolvable) == 1
    u = ss.unresolvable[0]
    assert u.sha == "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    assert u.advisory_id == "GHSA-0000-0000-0000"
    assert not u.resolved
    assert all(s.sha != u.sha for s in ss.seeds)


def test_until_excludes_later_seeds(make_repo):
    r = make_repo(SIGNAL_SCRIPT)
    ss = _seeds(r.root, until=r.shas[2], seeds_mode="message")
    assert [s.sha for s in ss.seeds] == [r.shas[1], r.shas[2]]
    ss = _seeds(r.root, until=r.shas[1], seeds_mode="message")
    assert [s.sha for s in ss.seeds] == [r.shas[1]]
    # advisory mode under the same bounds keeps only advisory-linked seeds
    ss = _seeds(r.root, until=r.shas[2])
    assert [s.sha for s in ss.seeds] == [r.shas[2]]
    ss = _seeds(r.root, until=r.shas[1])
    assert ss.seeds == ()


def test_seeds_file_entry_outside_window_is_unresolvable(make_repo, tmp_path):
    r = make_repo(SIGNAL_SCRIPT)
    f = tmp_path / "seeds.txt"
    # shas[5] is a real commit but sits after the --until boundary
    f.write_text(f"{r.shas[5]} CVE-2024-0001\n")
    ss = _seeds(r.root, seeds_file=str(f), until=r.shas[3])
    assert len(ss.unresolvable) == 1
    assert ss.unresolvable[0].sha == r.shas[5]


def test_since_excludes_boundary_rev_from_window(make_repo, tmp_path):
    r = make_repo(SIGNAL_SCRIPT)
    f = tmp_path / "seeds.txt"
    f.write_text(f"{r.shas[0]}\n")
    # S..U ancestry excludes S itself, so the boundary rev is unresolvable
    ss = _seeds(r.root, seeds_file=str(f), since=r.shas[0])
    assert len(ss.unresolvable) == 1
    assert ss.unresolvable[0].sha == r.shas[0]


def test_security_tag_seeds_release_range(make_repo):
    r = make_repo(
        [
            {"files": {"a.py": "x = 1\n"}, "message": "work a", "tag": "v0.9"},
            {"files": {"b.py": "x = 1\n"}, "message": "work b"},
            {
                "files": {"c.py": "x = 1\n"},
                "message": "work c",
                "tag": "v1.0-security",
            },
            {"files": {"d.py": "x = 1\n"}, "message": "work d"},
        ]
    )
    ss = _seeds(r.root)
    # the security tag seeds its target plus the range since the prior tag;
    # the plain tag contributes nothing
    assert {s.sha for s in ss.seeds} == {r.shas[1], r.shas[2]}
    assert all(s.source.startswith("ref:") for s in ss.seeds)


def test_security_tag_without_prior_tag_bounds_to_target(make_repo):
    r = make_repo(
        [
            {"files": {"a.py": "x = 1\n"}, "message": "work a"},
            {"files": {"b.py": "x = 1\n"}, "message": "work b"},
            {
                "files": {"c.py": "x = 1\n"},
                "message": "work c",
                "tag": "security-fix",
            },
        ]
    )
    ss = _seeds(r.root)
    # no ancestor tag to bound the range: target only, never full ancestry
    assert {s.sha for s in ss.seeds} == {r.shas[2]}


def test_rerun_seed_order_deterministic(make_repo, tmp_path):
    r = make_repo(SIGNAL_SCRIPT)
    f = tmp_path / "seeds.txt"
    f.write_text(f"{r.shas[0]} GHSA-1111-2222-3333\n")
    a = _seeds(r.root, seeds_file=str(f))
    b = _seeds(r.root, seeds_file=str(f))
    assert [(s.sha, s.advisory_id, s.source) for s in a.seeds] == [
        (s.sha, s.advisory_id, s.source) for s in b.seeds
    ]


def test_seeds_sorted_by_date_then_sha(make_repo):
    r = make_repo(SIGNAL_SCRIPT)
    ss = _seeds(r.root)
    keys = [(s.date, s.sha) for s in ss.seeds]
    assert keys == sorted(keys)


def test_revert_subject_never_seeds_on_verb_term(make_repo):
    # 'Revert "fix bounds vuln"' carries the fix verb and a security
    # term but is a removal-classification signal, not a guard origin
    assert not seeds.message_has_signal('Revert "fix bounds vuln"')
    assert not seeds.message_has_signal("revert fix security overflow")
    # an explicit advisory id still seeds a revert commit
    assert seeds.message_has_signal('Revert "x": CVE-2024-9999')
    r = make_repo(
        [
            {"files": {"a.py": "x = 1\n"}, "message": "work"},
            {
                "files": {"b.py": "x = 1\n"},
                "message": 'Revert "fix traversal guard"',
            },
        ]
    )
    assert _seeds(r.root).seeds == ()


def test_security_ref_seeds_no_per_pair_merge_base(
    make_repo, monkeypatch
):
    # bounders resolve through one batched --merged call per marked ref,
    # never an is_ancestor subprocess per tag/ref pair
    from archaeology import gitlog

    monkeypatch.setattr(
        gitlog,
        "is_ancestor",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("called")),
    )
    r = make_repo(
        [
            {"files": {"a.py": "x = 1\n"}, "message": "work a", "tag": "v0.9"},
            {"files": {"b.py": "x = 1\n"}, "message": "work b"},
            {
                "files": {"c.py": "x = 1\n"},
                "message": "work c",
                "tag": "v1.0-security",
            },
            {"files": {"d.py": "x = 1\n"}, "message": "work d"},
        ]
    )
    ss = _seeds(r.root)
    assert {s.sha for s in ss.seeds} == {r.shas[1], r.shas[2]}


def test_oversized_seeds_file_warns_and_is_ignored(
    make_repo, tmp_path, capsys
):
    r = make_repo(SIGNAL_SCRIPT)
    f = tmp_path / "seeds.txt"
    f.write_bytes(b"# " + b"x" * (1024 * 1024) + b"\n")
    ss = _seeds(r.root, seeds_file=str(f))
    assert "oversized" in capsys.readouterr().err
    # only the advisory-linked seeds remain under the default mode
    assert {s.sha for s in ss.seeds} == {r.shas[2], r.shas[5]}
    assert not ss.unresolvable


def test_seeds_file_entry_cap(make_repo, tmp_path, capsys):
    r = make_repo(SIGNAL_SCRIPT)
    f = tmp_path / "seeds.txt"
    # a real seed beyond the 10k line cap is dropped with a warning
    lines = [f"{r.shas[0]}\n"] * 10_000 + [f"{r.shas[4]}\n"]
    f.write_text("".join(lines))
    ss = _seeds(r.root, seeds_file=str(f))
    assert "10000" in capsys.readouterr().err.replace("_", "")
    by_sha = {s.sha for s in ss.seeds} | {s.sha for s in ss.unresolvable}
    assert r.shas[4] not in by_sha


def test_cli_summary_seed_count(make_repo, tmp_path, capsys):
    r = make_repo(SIGNAL_SCRIPT)
    f = tmp_path / "seeds.txt"
    f.write_text(f"{r.shas[0]} GHSA-1111-2222-3333\n")
    out = tmp_path / "o.jsonl"
    rc = cli.main([r.root, "--out", str(out), "--seeds-file", str(f)])
    assert rc == 0
    line = capsys.readouterr().out.strip()
    # 2 advisory-signaled + shas[0] from the seeds file = 3 resolved seeds
    assert "seeds=3" in line
    rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
    header = rows[0]
    assert header["type"] == "run" and header["seeds"] == 3
    assert header["tracked"] == 0
    # --seeds-mode message brings back the fix-verb harvest
    assert (
        cli.main(
            [r.root, "--out", str(out), "--seeds-file", str(f),
             "--seeds-mode", "message"]
        )
        == 0
    )
    line = capsys.readouterr().out.strip()
    assert "seeds=4" in line


def test_cli_emits_unresolvable_seed_row(make_repo, tmp_path):
    r = make_repo(SIGNAL_SCRIPT)
    f = tmp_path / "seeds.txt"
    f.write_text("1" * 40 + "\n")
    out = tmp_path / "o.jsonl"
    assert cli.main([r.root, "--out", str(out), "--seeds-file", str(f)]) == 0
    rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
    errs = [row for row in rows if row["type"] == "error"]
    assert len(errs) == 1
    assert errs[0]["seed"] == "1" * 40
    assert errs[0]["stage"] == "seeds"


def test_test_only_and_vendored_message_seeds_dropped(make_repo):
    r = make_repo(
        [
            {"files": {"app.py": "x = 1\n"}, "message": "init"},
            {
                "files": {"tests/test_app.py": "assert True\n"},
                "message": "fix security overflow in parser",
            },
            {
                "files": {"app.py": "y = 2\n"},
                "message": "fix traversal vuln in loader",
            },
            {
                "files": {"vendor/lib.py": "x = 1\n"},
                "message": "patch CVE-2024-9999 in vendored lib",
            },
            {
                "files": {
                    "app.py": "z = 3\n",
                    "tests/test_app.py": "assert True\n",
                },
                "message": "fix auth bypass CVE-2024-8888",
            },
        ]
    )
    ss = _seeds(r.root, seeds_mode="message")
    # tests-only and vendor-only diffs are not guard origins, however
    # strong the message signal; a mixed test+code diff still seeds
    assert [s.sha for s in ss.seeds] == [r.shas[2], r.shas[4]]
    ss = _seeds(r.root, seeds_mode="message", include_test_seeds=True)
    assert {s.sha for s in ss.seeds} == {
        r.shas[1], r.shas[2], r.shas[3], r.shas[4],
    }


def test_seeds_file_seed_kept_despite_test_only_diff(make_repo, tmp_path):
    r = make_repo(
        [
            {"files": {"app.py": "x = 1\n"}, "message": "init"},
            {
                "files": {"tests/test_app.py": "assert True\n"},
                "message": "touch up tests",
            },
        ]
    )
    f = tmp_path / "seeds.txt"
    f.write_text(f"{r.shas[1]} CVE-2024-0001\n")
    # explicit provenance is never dropped by the test-only check
    ss = _seeds(r.root, seeds_file=str(f))
    assert [s.sha for s in ss.seeds] == [r.shas[1]]


def _merge_repo(make_repo, side_msg, merge_msg):
    """Side branch with one commit, merged --no-ff into main."""
    from pathlib import Path

    from conftest import commit_env, run_git

    r = make_repo([{"files": {"app.py": "x = 1\n"}, "message": "base"}])
    run_git(r.root, "checkout", "-q", "-b", "side")
    Path(r.root, "app.py").write_text("x = 2\n")
    run_git(r.root, "add", "app.py")
    run_git(r.root, "commit", "-q", "-m", side_msg, env_extra=commit_env(10))
    side_sha = run_git(r.root, "rev-parse", "side").stdout.strip()
    run_git(r.root, "checkout", "-q", "main")
    run_git(
        r.root, "merge", "--no-ff", "-m", merge_msg, "side",
        env_extra=commit_env(11),
    )
    merge_sha = run_git(r.root, "rev-parse", "HEAD").stdout.strip()
    return r, side_sha, merge_sha


def test_merge_rollup_seed_deduped_against_seeded_side(make_repo):
    r, side_sha, merge_sha = _merge_repo(
        make_repo,
        "fix traversal vuln in helper",
        "merge branch fixing security issues",
    )
    ss = _seeds(r.root, seeds_mode="message")
    shas = {s.sha for s in ss.seeds}
    # the merge's message matched the fix-verb harvest but its merged
    # side already seeds: the rollup contributes nothing
    assert side_sha in shas
    assert merge_sha not in shas


def test_merge_rollup_kept_when_side_carries_no_seed(make_repo):
    r, side_sha, merge_sha = _merge_repo(
        make_repo, "tweak helper internals", "fix security overflow"
    )
    ss = _seeds(r.root, seeds_mode="message")
    shas = {s.sha for s in ss.seeds}
    assert merge_sha in shas
    assert side_sha not in shas


def test_merge_rollup_advisory_seed_never_deduped(make_repo):
    # the merge carries an advisory id: explicit signal, never dropped
    r, side_sha, merge_sha = _merge_repo(
        make_repo, "fix traversal vuln in helper", "merge fix CVE-2024-9999"
    )
    ss = _seeds(r.root, seeds_mode="message")
    shas = {s.sha for s in ss.seeds}
    assert merge_sha in shas
    assert side_sha in shas


def test_cli_max_seeds_truncates_with_note(make_repo, tmp_path, capsys):
    r = make_repo(SIGNAL_SCRIPT)
    out = tmp_path / "o.jsonl"
    rc = cli.main(
        [
            r.root, "--out", str(out),
            "--seeds-mode", "message", "--max-seeds", "1",
        ]
    )
    assert rc == 0
    assert "seeds capped at 1" in capsys.readouterr().err
    rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
    assert rows[0]["seeds"] == 1


def test_cli_max_seeds_zero_is_unbounded(make_repo, tmp_path, capsys):
    r = make_repo(SIGNAL_SCRIPT)
    out = tmp_path / "o.jsonl"
    rc = cli.main(
        [r.root, "--out", str(out), "--seeds-mode", "message",
         "--max-seeds", "0"]
    )
    assert rc == 0
    assert "capped" not in capsys.readouterr().err
    rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
    assert rows[0]["seeds"] == 3


def test_cli_include_test_seeds_flag(make_repo, tmp_path, read_jsonl):
    r = make_repo(
        [
            {"files": {"app.py": "x = 1\n"}, "message": "init"},
            {
                "files": {"tests/test_app.py": "assert True\n"},
                "message": "fix CVE-2024-9999 in test helper",
            },
        ]
    )
    out = tmp_path / "o.jsonl"
    assert cli.main([r.root, "--out", str(out)]) == 0
    assert read_jsonl(out)[0]["seeds"] == 0
    assert (
        cli.main(
            [r.root, "--out", str(out), "--include-test-seeds"]
        )
        == 0
    )
    assert read_jsonl(out)[0]["seeds"] == 1
