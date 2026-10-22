"""U7 gate stand-in: a scripted "regression" fixture repo through the
full CLI (R21's shape, at fixture level).

The planted history mirrors the real known-answer leg: a guard added by
a security-signaled commit, silently removed by a later refactor while
its sink lives on, then re-added by a second fix. ``--until`` replays
history "as of just before the second fix" so the REGRESSED row must
surface with the true seed and removal commits; a run at HEAD, where
the re-fix has landed, must emit zero candidates. Re-runs must be
byte-identical (R18).
"""

import json
import re

from archaeology import cli

BASE = "def recv(body):\n    return open(body).read()\n"
GUARDED = (
    "def recv(body):\n"
    "    if len(body) > MAX_LEN:\n"
    '        raise ValueError("big")\n'
    "    return open(body).read()\n"
)

SEED_MSG = "Fix CVE-2025-12345: reject oversized request body"
REMOVE_MSG = "simplify recv internals"
REFIX_MSG = "Fix CVE-2025-12345 regression: restore bounds check"

# c0 base -> c1 security fix adds the guard -> c2 silent removal ->
# c3 unrelated commit (boundary: "just before the second fix") ->
# c4 second fix re-adds the guard
GATE_COMMITS = [
    {"files": {"server.py": BASE}, "message": "initial import"},
    {"files": {"server.py": GUARDED}, "message": SEED_MSG},
    {"files": {"server.py": BASE}, "message": REMOVE_MSG},
    {"files": {"NOTES.md": "deployment notes\n"}, "message": "docs: notes"},
    {"files": {"server.py": GUARDED}, "message": REFIX_MSG},
]


def _seeds_file(tmp_path, sha, advisory="CVE-2025-12345"):
    p = tmp_path / "seeds.txt"
    p.write_text(f"{sha} {advisory}\n")
    return p


def _run(root, out, *extra):
    rc = cli.main([root, "--out", str(out), *extra])
    assert rc == 0
    return out


def _rows(path):
    with open(path) as fh:
        return [json.loads(l) for l in fh if l.strip()]


def _candidates(rows):
    return [r for r in rows if r["type"] == "candidate"]


def test_gate_regressed_row_end_to_end(make_repo, tmp_path):
    """The lost guard surfaces as a REGRESSED candidate with the true
    seed and removal commits, run under --until (R21, gate leg 1)."""
    r = make_repo(GATE_COMMITS)
    boundary = r.shas[3]  # the commit just before the second fix
    seeds = _seeds_file(tmp_path, r.shas[1])
    out = tmp_path / "gate.jsonl"
    _run(
        r.root, out,
        "--until", boundary,
        "--seeds-file", str(seeds),
    )
    rows = _rows(out)

    hdr = rows[0]
    assert hdr["type"] == "run"
    assert hdr["seeds"] == 1
    assert hdr["tracked"] == 1
    assert hdr["regressed"] == 1
    # nothing else may reach candidate status
    assert hdr["relocated"] == 0
    assert hdr["unknown"] == 0

    cands = _candidates(rows)
    assert len(cands) == 1
    c = cands[0]

    assert re.fullmatch(r"archaeology-\w+-[0-9a-f]{10}", c["id"])
    assert c["type"] == "candidate"
    assert c["family"]
    # sink alive at the boundary
    assert c["sink"]["path"] == "server.py"
    assert c["sink"]["function"] == "recv"
    assert "open(" in c["sink"]["operation"]
    assert "open(body).read()" in c["current"]
    # the lost guard, with raw text and a normalized signature
    assert c["missing_guard"]["shape"] == "conditional-rejection"
    assert c["missing_guard"]["signature"]
    assert "MAX_LEN" in c["missing_guard"]["raw_text"]
    # three-link evidence: true seed and true removal
    assert c["seed"]["sha"] == r.shas[1]
    assert c["seed"]["advisory"] == "CVE-2025-12345"
    assert c["removal"]["sha"] == r.shas[2]
    assert c["removal"]["subject"] == REMOVE_MSG
    assert c["siblings"] == []
    assert c["exposure"] == "unknown"
    assert c["entry"] is None
    assert c["holdout"] is None


def test_gate_refix_closes_the_regression(make_repo, tmp_path):
    """At HEAD the second fix has landed: the same history must emit
    zero candidates (the negative half of the gate shape)."""
    r = make_repo(GATE_COMMITS)
    out = tmp_path / "head.jsonl"
    _run(r.root, out)
    rows = _rows(out)
    hdr = rows[0]
    assert hdr["type"] == "run"
    assert hdr["seeds"] == 2  # both fix commits signal
    assert hdr["regressed"] == 0
    assert _candidates(rows) == []


def test_gate_until_before_removal_is_quiet(make_repo, tmp_path):
    """--until pinned to the seed commit itself: the guard still lives
    at the boundary, so no removal can be claimed."""
    r = make_repo(GATE_COMMITS)
    out = tmp_path / "before.jsonl"
    _run(r.root, out, "--until", r.shas[1])
    rows = _rows(out)
    assert rows[0]["intact"] == 1
    assert rows[0]["regressed"] == 0
    assert _candidates(rows) == []


def test_gate_rerun_byte_identical(make_repo, tmp_path):
    """Determinism: two runs over the same clone diff clean (R18)."""
    r = make_repo(GATE_COMMITS)
    boundary = r.shas[3]
    out_a = tmp_path / "a.jsonl"
    out_b = tmp_path / "b.jsonl"
    _run(r.root, out_a, "--until", boundary)
    _run(r.root, out_a, "--until", boundary)  # same path, re-run
    _run(r.root, out_b, "--until", boundary)  # different path, re-run
    assert out_a.read_bytes() == out_b.read_bytes()
