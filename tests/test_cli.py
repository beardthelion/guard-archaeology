import os
import re

import pytest

from archaeology import cli

BASIC = [
    {"files": {"a.py": "x = 1\n"}, "message": "work"},
    {"files": {"b.py": "y = 2\n"}, "message": "more work"},
]

SUMMARY_RE = re.compile(
    r"^seeds=\d+ tracked=\d+ intact=\d+ regressed=\d+ relocated=\d+ "
    r"removed_with_sink=\d+ deliberate=\d+ unknown=\d+$"
)


def test_help_exits_zero():
    with pytest.raises(SystemExit) as e:
        cli.main(["--help"])
    assert e.value.code == 0


def test_bad_flag_exits_nonzero_with_usage(make_repo, capsys):
    r = make_repo(BASIC)
    with pytest.raises(SystemExit) as e:
        cli.main([r.root, "--no-such-flag"])
    assert e.value.code != 0
    assert "usage" in capsys.readouterr().err.lower()


def test_unreadable_root(tmp_path, capsys):
    rc = cli.main([str(tmp_path / "missing")])
    assert rc != 0
    assert "unreadable" in capsys.readouterr().err


def test_not_a_repo(tmp_path, capsys):
    plain = tmp_path / "plain"
    plain.mkdir()
    rc = cli.main([str(plain)])
    assert rc != 0
    assert "not a git repository" in capsys.readouterr().err


def test_happy_path_summary_and_header(make_repo, tmp_path, capsys, read_jsonl):
    r = make_repo(BASIC)
    out = tmp_path / "o.jsonl"
    rc = cli.main([r.root, "--out", str(out)])
    assert rc == 0
    line = capsys.readouterr().out.strip()
    assert SUMMARY_RE.match(line)
    rows = read_jsonl(out)
    assert rows[0]["type"] == "run"
    assert f"seeds={rows[0]['seeds']}" in line


def test_default_out_path(make_repo):
    r = make_repo(BASIC)
    rc = cli.main([r.root])
    assert rc == 0
    default = os.path.join(r.root, ".clawpatch", "archaeology.jsonl")
    assert os.path.exists(default)


def test_zero_candidate_run_still_emits_header(make_repo, tmp_path, read_jsonl):
    r = make_repo(BASIC)
    out = tmp_path / "o.jsonl"
    assert cli.main([r.root, "--out", str(out)]) == 0
    rows = read_jsonl(out)
    assert rows[0]["type"] == "run"
    assert not any(row["type"] == "candidate" for row in rows)


def test_bad_until_rev_is_typed_error(make_repo, tmp_path, capsys):
    r = make_repo(BASIC)
    out = tmp_path / "o.jsonl"
    rc = cli.main([r.root, "--out", str(out), "--until", "not-a-rev"])
    assert rc != 0
    err = capsys.readouterr().err
    assert "archaeology: stopped:" in err
    assert "Traceback" not in err


def test_missing_seeds_file_is_typed_error(make_repo, tmp_path, capsys):
    r = make_repo(BASIC)
    out = tmp_path / "o.jsonl"
    rc = cli.main(
        [r.root, "--out", str(out), "--seeds-file", str(tmp_path / "nope")]
    )
    assert rc != 0
    assert "seeds" in capsys.readouterr().err


def test_write_failure_exits_nonzero(make_repo, tmp_path, capsys):
    r = make_repo(BASIC)
    blocker = tmp_path / "blocker"
    blocker.write_text("not a dir\n")
    rc = cli.main([r.root, "--out", str(blocker / "o.jsonl")])
    assert rc != 0
    assert "cannot write output" in capsys.readouterr().err


def test_caller_depth_negative_rejected(make_repo, tmp_path):
    r = make_repo(BASIC)
    assert (
        cli.main(
            [r.root, "--out", str(tmp_path / "o.jsonl"), "--caller-depth", "-1"]
        )
        != 0
    )


def test_also_md_written(make_repo, tmp_path):
    r = make_repo(BASIC)
    out = tmp_path / "o.jsonl"
    assert cli.main([r.root, "--out", str(out), "--also-md"]) == 0
    assert (tmp_path / "o.md").exists()


def test_rerun_output_byte_identical(make_repo, tmp_path):
    r = make_repo(BASIC)
    out = tmp_path / "o.jsonl"
    assert cli.main([r.root, "--out", str(out)]) == 0
    first = out.read_bytes()
    assert cli.main([r.root, "--out", str(out)]) == 0
    assert out.read_bytes() == first


def test_until_option_injection_refused(make_repo, tmp_path, capsys):
    # '--until=--output=...' would smuggle a git flag into the revspec:
    # rejected before any git call, and no file is created
    r = make_repo(BASIC)
    evil = tmp_path / "evil.txt"
    rc = cli.main([r.root, f"--until=--output={evil}"])
    assert rc != 0
    assert not evil.exists()
    assert "archaeology: stopped:" in capsys.readouterr().err


def test_since_option_injection_refused(make_repo, tmp_path):
    r = make_repo(BASIC)
    assert cli.main([r.root, "--since=--all"]) != 0


def test_unresolvable_since_is_typed_error(make_repo, tmp_path, capsys):
    r = make_repo(BASIC)
    rc = cli.main([r.root, "--since", "deadbeef" * 5])
    assert rc != 0
    assert "archaeology: stopped:" in capsys.readouterr().err


def test_default_out_dir_symlink_escape_refused(
    make_repo, tmp_path, capsys
):
    # .clawpatch -> outside dir must not redirect the default --out write
    r = make_repo(BASIC)
    evil = tmp_path / "evil"
    evil.mkdir()
    os.symlink(evil, os.path.join(r.root, ".clawpatch"))
    rc = cli.main([r.root])
    assert rc != 0
    assert "escapes target root" in capsys.readouterr().err
    assert not (evil / "archaeology.jsonl").exists()


def test_run_header_reports_skipped(make_repo, tmp_path, read_jsonl):
    # extraction skips are distinguishable from checked seeds in the
    # run row: an unclassifiable added statement counts as skipped
    r = make_repo(
        [
            {"files": {"app.py": "x = 1\n"}, "message": "base"},
            {
                "files": {"app.py": "x = 1\ny = transform(x)\n"},
                "message": "fix overflow bounds check CVE-2024-42424",
            },
        ]
    )
    out = tmp_path / "o.jsonl"
    assert cli.main([r.root, "--out", str(out)]) == 0
    hdr = read_jsonl(out)[0]
    assert hdr["type"] == "run"
    assert hdr["skipped"] >= 1


def test_latin1_blob_run_completes(make_repo, tmp_path, capsys):
    # a non-UTF-8 blob in git output decodes with replacement; the run
    # exits zero without a traceback
    blob = "# caf\xe9\n".encode("latin-1") + (
        b"def recv(body):\n"
        b"    if len(body) > MAX_LEN:\n"
        b"        raise ValueError('big')\n"
        b"    return open(body).read()\n"
    )
    r = make_repo(
        [
            {"files": {"app.py": b"x = 1\n"}, "message": "base"},
            {
                "files": {"app.py": blob},
                "message": "fix overflow bounds check CVE-2024-42424",
            },
        ]
    )
    out = tmp_path / "o.jsonl"
    assert cli.main([r.root, "--out", str(out)]) == 0
    assert "Traceback" not in capsys.readouterr().err
