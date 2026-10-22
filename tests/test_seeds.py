import json

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
    ss = _seeds(r.root)
    assert [s.sha for s in ss.seeds] == [r.shas[1], r.shas[2], r.shas[5]]
    assert not ss.unresolvable


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
    ss = _seeds(r.root, until=r.shas[2])
    assert [s.sha for s in ss.seeds] == [r.shas[1], r.shas[2]]
    ss = _seeds(r.root, until=r.shas[1])
    assert [s.sha for s in ss.seeds] == [r.shas[1]]


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


def test_cli_summary_seed_count(make_repo, tmp_path, capsys):
    r = make_repo(SIGNAL_SCRIPT)
    f = tmp_path / "seeds.txt"
    f.write_text(f"{r.shas[0]} GHSA-1111-2222-3333\n")
    out = tmp_path / "o.jsonl"
    rc = cli.main([r.root, "--out", str(out), "--seeds-file", str(f)])
    assert rc == 0
    line = capsys.readouterr().out.strip()
    # 3 message-signaled + shas[0] from the seeds file = 4 resolved seeds
    assert "seeds=4" in line
    rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
    header = rows[0]
    assert header["type"] == "run" and header["seeds"] == 4
    assert header["tracked"] == 0


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
