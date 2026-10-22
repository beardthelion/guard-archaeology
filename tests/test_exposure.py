"""exposure.py: --exposure-file / scope-boundary.md resolution (R14, KTD11)."""

import json
import os

from archaeology import exposure

FIXTURE = os.path.join(
    os.path.dirname(__file__), "fixtures", "scope-boundary.md"
)


def _repo(tmp_path):
    root = tmp_path / "repo"
    (root / ".clawpatch").mkdir(parents=True)
    return str(root)


def test_exposure_file_wins_over_scope_boundary(tmp_path):
    root = _repo(tmp_path)
    with open(
        os.path.join(root, ".clawpatch", "scope-boundary.md"), "w"
    ) as fh:
        fh.write("- app.py:recv TAINT: yes\n")
    ef = tmp_path / "exp.json"
    ef.write_text(json.dumps({"app.py:recv": "internal"}))
    emap = exposure.load_exposure(root, str(ef))
    assert emap["app.py:recv"] == "internal"


def test_scope_boundary_fixture_taint_lines(tmp_path):
    root = _repo(tmp_path)
    with open(FIXTURE) as fh:
        text = fh.read()
    with open(
        os.path.join(root, ".clawpatch", "scope-boundary.md"), "w"
    ) as fh:
        fh.write(text)
    emap = exposure.load_exposure(root)
    assert emap["app/web.py:handle"] == "untrusted"
    assert emap["app/api.py:rpc"] == "untrusted"
    assert emap["entry:app/api.py:rpc"] == "POST"
    assert "app/internal.py:helper" not in emap  # TAINT: no


def test_absent_both_resolves_empty_map(tmp_path):
    root = _repo(tmp_path)
    assert exposure.load_exposure(root) == {}
    assert exposure.lookup({}, "a.py", "f") == ("unknown", None)


def test_lookup_entry_and_unknown_default():
    emap = {"a.py:f": "untrusted", "entry:a.py:f": "POST"}
    assert exposure.lookup(emap, "a.py", "f") == ("untrusted", "POST")
    assert exposure.lookup(emap, "a.py", "g") == ("unknown", None)


def test_malformed_exposure_file_warns_and_falls_through(tmp_path, capsys):
    root = _repo(tmp_path)
    with open(
        os.path.join(root, ".clawpatch", "scope-boundary.md"), "w"
    ) as fh:
        fh.write("- a.py:f TAINT: yes\n")
    ef = tmp_path / "bad.json"
    ef.write_text("{not json")
    emap = exposure.load_exposure(root, str(ef))
    assert "ignoring exposure file" in capsys.readouterr().err
    assert emap["a.py:f"] == "untrusted"


def test_oversized_exposure_file_warns_and_is_ignored(tmp_path, capsys):
    root = _repo(tmp_path)
    ef = tmp_path / "big.json"
    ef.write_bytes(b" " * (exposure._MAX_BYTES + 1))
    emap = exposure.load_exposure(root, str(ef))
    assert emap == {}
    assert "ignoring exposure file" in capsys.readouterr().err


def test_bad_bucket_warns_and_is_ignored(tmp_path, capsys):
    root = _repo(tmp_path)
    ef = tmp_path / "exp.json"
    ef.write_text(json.dumps({"a.py:f": "everything"}))
    emap = exposure.load_exposure(root, str(ef))
    assert emap == {}
    assert "ignoring exposure file" in capsys.readouterr().err


def test_non_object_exposure_file_warns_and_is_ignored(tmp_path, capsys):
    root = _repo(tmp_path)
    ef = tmp_path / "exp.json"
    ef.write_text(json.dumps(["a.py:f"]))
    emap = exposure.load_exposure(root, str(ef))
    assert emap == {}
    assert "ignoring exposure file" in capsys.readouterr().err


def test_malformed_scope_boundary_warns_and_is_ignored(tmp_path, capsys):
    root = _repo(tmp_path)
    sb = os.path.join(root, ".clawpatch", "scope-boundary.md")
    with open(sb, "wb") as fh:
        fh.write(b"\xff\xfe binary not utf8")
    emap = exposure.load_exposure(root)
    assert emap == {}
    assert "scope-boundary" in capsys.readouterr().err


def test_scope_boundary_symlink_escape_ignored(tmp_path, capsys):
    root = _repo(tmp_path)
    outside = tmp_path / "outside.md"
    outside.write_text("- a.py:f TAINT: yes\n")
    os.symlink(outside, os.path.join(root, ".clawpatch", "scope-boundary.md"))
    emap = exposure.load_exposure(root)
    assert emap == {}
    assert "outside target root" in capsys.readouterr().err


def test_scope_boundary_symlink_inside_root_allowed(tmp_path):
    root = _repo(tmp_path)
    real = os.path.join(root, "real-sb.md")
    with open(real, "w") as fh:
        fh.write("- a.py:f TAINT: yes\n")
    os.symlink(real, os.path.join(root, ".clawpatch", "scope-boundary.md"))
    emap = exposure.load_exposure(root)
    assert emap["a.py:f"] == "untrusted"
