import pytest

from archaeology import cli, extract, gitlog, seeds


# --- per-shape extraction: three shapes in four languages -------------------------

PY_COND = '''def recv(body):
    if len(body) > MAX_LEN:
        raise ValueError("big")
    return open(body).read()
'''

GO_COND = '''package m

func Recv(d []byte) error {
	if len(d) > MaxSize {
		return fmt.Errorf("big")
	}
	return os.ReadFile("/tmp/x")
}
'''

RS_COND = '''fn serve(input: &[u8]) -> Result<(), String> {
    if input.len() > MAX {
        return Err("too long".into());
    }
    fs::write("/tmp/out", input)
}
'''

TS_COND = '''function serve(req, res) {
  if (!allowedHosts.has(req.host)) {
    throw new Error("bad host");
  }
  res.send(render(req.host));
}
'''

PY_CALL = '''def fetch(url):
    url = sanitize_url(url)
    return requests.get(url)
'''

GO_CALL = '''package m

func Load(p string) error {
	p = filepath.Clean(p)
	return os.ReadFile(p)
}
'''

RS_CALL = '''fn load(p: &str) -> std::io::Result<Vec<u8>> {
    let p = sanitize_path(p);
    fs::read(p)
}
'''

TS_CALL = '''function load(p) {
  const safe = escapeHtml(p);
  document.write(safe);
}
'''

PY_CONST = '''MAX_UPLOAD = 512

def recv(body):
    if len(body) > MAX_UPLOAD:
        raise ValueError("big")
    return open(body).read()
'''

GO_CONST = '''package m

const MaxUpload = 4096

func Recv(d []byte) error {
	if len(d) > MaxUpload {
		return fmt.Errorf("big")
	}
	return os.ReadFile("/tmp/x")
}
'''

RS_CONST = '''const MAX_INPUT: usize = 512;

fn recv(d: &[u8]) -> Result<(), String> {
    if d.len() > MAX_INPUT {
        return Err("big".into());
    }
    fs::write("/tmp/r", d)
}
'''

TS_CONST = '''const MAX_BODY = 8192;

function recv(req, res) {
  if (req.body.length > MAX_BODY) {
    throw new Error("big");
  }
  res.send(req.body);
}
'''

EXTRACTION_CASES = [
    ("python", "a.py", PY_COND, [2, 3], "conditional-rejection", "bounds",
     "recv"),
    ("go", "b.go", GO_COND, [4, 5], "conditional-rejection", "bounds",
     "Recv"),
    ("rust", "c.rs", RS_COND, [2, 3], "conditional-rejection", "bounds",
     "serve"),
    ("tsjs", "d.ts", TS_COND, [2, 3], "conditional-rejection", "allowlist",
     "serve"),
    ("python", "e.py", PY_CALL, [2], "validation-call", "validation",
     "fetch"),
    ("go", "f.go", GO_CALL, [4], "validation-call", "validation", "Load"),
    ("rust", "g.rs", RS_CALL, [2], "validation-call", "validation", "load"),
    ("tsjs", "h.ts", TS_CALL, [2], "validation-call", "escape", "load"),
    ("python", "i.py", PY_CONST, [1], "constant-limit", "bounds", "recv"),
    ("go", "j.go", GO_CONST, [3], "constant-limit", "bounds", "Recv"),
    ("rust", "k.rs", RS_CONST, [1], "constant-limit", "bounds", "recv"),
    ("tsjs", "l.ts", TS_CONST, [1], "constant-limit", "bounds", "recv"),
]


@pytest.mark.parametrize(
    "lang,path,text,added,shape,family,sink_fn", EXTRACTION_CASES
)
def test_three_shapes_four_languages(
    lang, path, text, added, shape, family, sink_fn
):
    recs, skips = extract.extract_file(lang, path, text, added)
    assert len(recs) == 1
    rec = recs[0]
    assert rec.shape == shape
    assert rec.family == family
    assert rec.sink_function == sink_fn
    assert rec.sink_path == path
    assert rec.signature
    assert rec.raw_text


# --- drops: unclassifiable, guard without sink -----------------------------------------


def test_unclassifiable_input_dropped_and_counted():
    text = '''def handle(x):
    y = transform(x)
    return open(x).read()
'''
    recs, skips = extract.extract_file("python", "a.py", text, [2])
    assert recs == []
    assert skips["unclassified"] == 1


def test_guard_without_sink_not_extracted():
    text = '''def handle(x):
    if len(x) > 10:
        raise ValueError("big")
    return x
'''
    recs, skips = extract.extract_file("python", "a.py", text, [2, 3])
    assert recs == []
    assert skips["no-sink"] == 1


def test_sink_only_in_comment_does_not_count():
    text = '''def handle(x):
    if len(x) > 10:
        raise ValueError("big")
    # os.system(x) used to be here
    return x
'''
    recs, skips = extract.extract_file("python", "a.py", text, [2, 3])
    assert recs == []
    assert skips["no-sink"] == 1


# --- sink association paths ----------------------------------------------------------


def test_sink_in_immediate_callee():
    text = '''def handle(p):
    if len(p) > 10:
        raise ValueError("big")
    return run(p)

def run(p):
    return os.system("cat " + p)
'''
    recs, skips = extract.extract_file("python", "a.py", text, [2, 3])
    assert len(recs) == 1
    assert recs[0].sink_function == "run"
    assert recs[0].sink_op == "os.system("


def test_sink_in_immediate_caller():
    text = '''def is_safe(p):
    if ".." in p:
        return False
    return True

def handle(p):
    if not is_safe(p):
        return None
    return open(p).read()
'''
    recs, skips = extract.extract_file("python", "a.py", text, [2, 3])
    assert len(recs) == 1
    assert recs[0].sink_function == "handle"
    assert recs[0].sink_op == "open("


def test_pathlib_path_op_is_a_sink():
    # gate leg 1 finding: aiohttp's anchor-check guard was dropped
    # no-sink because pathlib ops were not catalogued
    text = '''def handle(rel_url):
    name = Path(rel_url)
    if name.anchor:
        raise ValueError("absolute")
    return root.joinpath(name).resolve()
'''
    recs, skips = extract.extract_file("python", "a.py", text, [3, 4])
    assert len(recs) == 1
    assert recs[0].sink_function == "handle"
    assert recs[0].sink_op in (".joinpath(", ".resolve(")


def test_pathlib_write_read_text_are_sinks():
    text = '''def handle(p):
    if ".." in p:
        return None
    return p.write_text(data)
'''
    recs, skips = extract.extract_file("python", "a.py", text, [2, 3])
    assert len(recs) == 1
    assert recs[0].sink_op == ".write_text("


def test_sink_function_attribution_methods():
    text = '''package m

type Srv struct{}

func (s *Srv) Do(x string) error {
	if !s.allowed(x) {
		return fmt.Errorf("denied")
	}
	return exec.Command(x).Run()
}
'''
    recs, skips = extract.extract_file("go", "e.go", text, [6, 7])
    assert len(recs) == 1
    assert recs[0].sink_function == "Srv.Do"


def test_sink_function_attribution_class_method_python():
    text = '''class H:
    def run(self, p):
        if len(p) > 3:
            raise ValueError("big")
        return os.path.join("/", p)
'''
    recs, skips = extract.extract_file("python", "e.py", text, [3, 4])
    assert len(recs) == 1
    assert recs[0].sink_function == "H.run"


def test_sink_function_attribution_tsjs_class_method():
    text = '''class Svc {
  handle(req, res) {
    if (req.body.length > MAX) {
      throw new Error("big");
    }
    res.send(req.body);
  }
}
'''
    recs, skips = extract.extract_file("tsjs", "e.ts", text, [3, 4])
    assert len(recs) == 1
    assert recs[0].sink_function == "Svc.handle"


def test_if_head_wrapping_existing_body_completes():
    # only the 'if' line is added; the rejection body predates it and is
    # still part of the guard statement
    text = '''def f(x):
    if len(x) > 5:
        return None
    return open(x).read()
'''
    recs, skips = extract.extract_file("python", "a.py", text, [2])
    assert len(recs) == 1
    assert recs[0].shape == "conditional-rejection"
    assert "return None" in recs[0].raw_text


def test_single_line_brace_body():
    text = '''function f(x) {
  if (x > 5)
    return;
  eval(x);
}
'''
    recs, skips = extract.extract_file("tsjs", "a.js", text, [2])
    assert len(recs) == 1
    assert recs[0].signature == "if(ID>NUM)return;"
    assert recs[0].sink_op == "eval("


def test_constant_declared_inside_function():
    text = '''def recv(body):
    LIMIT = 64
    if len(body) > LIMIT:
        raise ValueError("big")
    return open(body).read()
'''
    recs, skips = extract.extract_file("python", "a.py", text, [2])
    assert len(recs) == 1
    assert recs[0].shape == "constant-limit"
    assert recs[0].sink_function == "recv"


def test_constant_never_consulted_is_dropped():
    text = '''UNUSED_MAX = 5

def recv(body):
    return open(body).read()
'''
    recs, skips = extract.extract_file("python", "a.py", text, [1])
    assert recs == []
    assert skips["no-sink"] == 1


def test_classified_guard_outside_function_is_no_sink():
    text = '''if x > 1:
    raise ValueError("no")

def f(y):
    return open(y).read()
'''
    recs, skips = extract.extract_file("python", "a.py", text, [1, 2])
    assert recs == []
    assert skips["no-sink"] == 1


def test_await_wrapped_guard_call():
    text = '''async def f(u):
    await check_perms(u)
    return open(u).read()
'''
    recs, skips = extract.extract_file("python", "a.py", text, [2])
    assert len(recs) == 1
    assert recs[0].shape == "validation-call"
    assert recs[0].family == "auth"


def test_garbage_line_never_raises():
    text = "def f(x):\n    \x00\x01 @@ binary junk\n    return open(x).read()\n"
    recs, skips = extract.extract_file("python", "a.py", text, [2])
    assert recs == []
    assert skips["unclassified"] == 1


# --- go const block -------------------------------------------------------------------


def test_go_const_block_bare_decl():
    text = '''package m

const (
	One = 1
	MaxUpload = 4096
)

func Recv(d []byte) error {
	if len(d) > MaxUpload {
		return fmt.Errorf("big")
	}
	return os.ReadFile("/tmp/x")
}
'''
    recs, skips = extract.extract_file("go", "b.go", text, [5])
    assert len(recs) == 1
    assert recs[0].shape == "constant-limit"
    assert recs[0].signature == "ID=NUM"


# --- normalization invariance at the record level -----------------------------------------


def test_record_signature_invariant_under_renames():
    a = '''def f(data):
    if len(data) > MAX:
        raise ValueError("x")
    return open(data).read()
'''
    b = '''def f(payload):
    if len(payload) > LIMIT:
        raise ValueError("y")
    return open(payload).read()
'''
    ra, _ = extract.extract_file("python", "a.py", a, [2, 3])
    rb, _ = extract.extract_file("python", "a.py", b, [2, 3])
    assert ra[0].signature == rb[0].signature


# --- end to end through seeds -------------------------------------------------------------


def _seeded_repo(make_repo):
    return make_repo(
        [
            {
                "files": {
                    "app.py": "def recv(body):\n    return open(body).read()\n"
                },
                "message": "add receiver",
            },
            {
                "files": {
                    "app.py": (
                        "def recv(body):\n"
                        "    if len(body) > MAX_LEN:\n"
                        '        raise ValueError("big")\n'
                        "    return open(body).read()\n"
                    )
                },
                "message": "fix overflow bounds check CVE-2024-42424",
            },
        ]
    )


def test_extract_guards_over_seed_set(make_repo):
    r = _seeded_repo(make_repo)
    seed_set = seeds.collect_seeds(r.root)
    assert len(seed_set.seeds) == 1
    out = extract.extract_guards(r.root, seed_set)
    assert len(out.records) == 1
    rec = out.records[0]
    assert rec.seed_sha == r.shas[1]
    assert rec.advisory_id is None
    assert rec.shape == "conditional-rejection"
    assert rec.family == "bounds"
    assert rec.sink_function == "recv"
    assert rec.signature == "if CALL:size(ID)>ID:raise CALL:valueerror(STR)"
    assert rec.signature_anchor == "if CALL:size(ID)>ID:"


def test_advisory_id_propagates(make_repo, tmp_path):
    r = _seeded_repo(make_repo)
    sf = tmp_path / "seeds.txt"
    sf.write_text(f"{r.shas[1]} GHSA-xxxx-1111\n")
    seed_set = seeds.collect_seeds(r.root, seeds_file=str(sf))
    out = extract.extract_guards(r.root, seed_set)
    assert len(out.records) == 1
    assert out.records[0].advisory_id == "GHSA-xxxx-1111"


def test_unsupported_extension_counts_skip(make_repo):
    r = make_repo(
        [
            {
                "files": {
                    "main.c": "int main() { return 0; }\n",
                },
                "message": "init",
            },
            {
                "files": {
                    "main.c": (
                        "int main() {\n"
                        "    if (n > MAX) return 1;\n"
                        "    return system(cmd);\n"
                        "}\n"
                    )
                },
                "message": "fix overflow bounds check CVE-2024-42424",
            },
        ]
    )
    seed_set = seeds.collect_seeds(r.root)
    out = extract.extract_guards(r.root, seed_set)
    assert out.records == ()
    assert out.skip_reasons["unsupported"] == 1


def test_unreadable_patch_records_error(make_repo, monkeypatch):
    r = _seeded_repo(make_repo)
    seed_set = seeds.collect_seeds(r.root)

    def boom(repo, sha):
        raise gitlog.GitError(["git", "show", sha], 128, "boom")

    monkeypatch.setattr(gitlog, "show_patch", boom)
    out = extract.extract_guards(r.root, seed_set)
    assert out.records == ()
    assert len(out.errors) == 1
    assert out.errors[0]["stage"] == "extract"
    assert out.errors[0]["seed"] == r.shas[1]


def test_absent_path_records_error(make_repo, monkeypatch):
    r = _seeded_repo(make_repo)
    seed_set = seeds.collect_seeds(r.root)
    monkeypatch.setattr(gitlog, "show_file", lambda repo, sha, p: gitlog.NOT_FOUND)
    out = extract.extract_guards(r.root, seed_set)
    assert out.records == ()
    assert out.skip_reasons["unreadable"] == 1
    assert any(e.get("path") == "app.py" for e in out.errors)


def test_mixed_language_seed_commit(make_repo):
    r = make_repo(
        [
            {
                "files": {
                    "app.py": "def recv(body):\n    return open(body).read()\n",
                    "main.c": "int main() { return 0; }\n",
                },
                "message": "init",
            },
            {
                "files": {
                    "app.py": (
                        "def recv(body):\n"
                        "    if len(body) > MAX_LEN:\n"
                        '        raise ValueError("big")\n'
                        "    return open(body).read()\n"
                    ),
                    "main.c": (
                        "int main() {\n"
                        "    if (n > MAX) return 1;\n"
                        "    return system(cmd);\n"
                        "}\n"
                    ),
                },
                "message": "fix overflow bounds check CVE-2024-42424",
            },
        ]
    )
    seed_set = seeds.collect_seeds(r.root)
    out = extract.extract_guards(r.root, seed_set)
    assert len(out.records) == 1
    assert out.records[0].path == "app.py"
    assert out.skip_reasons["unsupported"] == 1


def test_new_file_seed_extracts(make_repo):
    r = make_repo(
        [
            {"files": {"README": "x\n"}, "message": "init"},
            {
                "files": {
                    "srv.go": (
                        "package m\n\n"
                        "func Recv(d []byte) error {\n"
                        "\tif len(d) > MaxSize {\n"
                        '\t\treturn fmt.Errorf("big")\n'
                        "\t}\n"
                        "\treturn os.ReadFile(\"/tmp/x\")\n"
                        "}\n"
                    )
                },
                "message": "fix path traversal vulnerability "
                "CVE-2024-42424",
            },
        ]
    )
    seed_set = seeds.collect_seeds(r.root)
    assert len(seed_set.seeds) == 1
    out = extract.extract_guards(r.root, seed_set)
    assert len(out.records) == 1
    assert out.records[0].sink_function == "Recv"


def test_cli_extract_error_row_and_zero_exit(
    make_repo, tmp_path, capsys, monkeypatch, read_jsonl
):
    r = _seeded_repo(make_repo)
    out = tmp_path / "o.jsonl"

    def boom(repo, sha):
        raise gitlog.GitError(["git", "show", sha], 128, "boom")

    monkeypatch.setattr(gitlog, "show_patch", boom)
    assert cli.main([r.root, "--out", str(out)]) == 0
    rows = read_jsonl(out)
    assert any(
        row["type"] == "error" and row["stage"] == "extract" for row in rows
    )


def test_cli_tracked_count_reflects_extraction(make_repo, tmp_path, capsys):
    r = _seeded_repo(make_repo)
    out = tmp_path / "o.jsonl"
    assert cli.main([r.root, "--out", str(out)]) == 0
    line = capsys.readouterr().out.strip()
    assert "seeds=1" in line
    assert "tracked=1" in line


def test_show_file_failure_is_per_file_error_not_abort(
    make_repo, monkeypatch
):
    # a GitError from show_file inside the per-file loop produces an
    # error row, not a run abort
    r = _seeded_repo(make_repo)
    seed_set = seeds.collect_seeds(r.root)

    def boom(repo, sha, path):
        raise gitlog.GitError(["git", "show", f"{sha}:{path}"], 128, "boom")

    monkeypatch.setattr(gitlog, "show_file", boom)
    out = extract.extract_guards(r.root, seed_set)
    assert out.records == ()
    assert len(out.errors) == 1
    assert out.errors[0]["stage"] == "extract"
    assert out.errors[0]["path"] == "app.py"


def test_show_file_failure_cli_still_exits_zero(
    make_repo, tmp_path, monkeypatch, read_jsonl
):
    r = _seeded_repo(make_repo)

    def boom(repo, sha, path):
        raise gitlog.GitError(["git", "show"], 128, "boom")

    monkeypatch.setattr(gitlog, "show_file", boom)
    out = tmp_path / "o.jsonl"
    assert cli.main([r.root, "--out", str(out)]) == 0
    rows = read_jsonl(out)
    assert any(
        row["type"] == "error"
        and row["stage"] == "extract"
        and row.get("path") == "app.py"
        for row in rows
    )


def test_constant_consulted_in_method_resolves_method_qualname():
    # a class-level constant consulted inside a method attributes the
    # sink to the method, never the unresolvable class container
    text = '''class H:
    MAX = 512

    def run(self, body):
        if len(body) > H.MAX:
            raise ValueError("big")
        return open(body).read()
'''
    recs, skips = extract.extract_file("python", "a.py", text, [2])
    assert len(recs) == 1
    assert recs[0].shape == "constant-limit"
    assert recs[0].sink_function == "H.run"
    assert recs[0].decl_name == "MAX"


def test_record_carries_guard_function_and_decl_name():
    text = '''def recv(body):
    if len(body) > MAX_LEN:
        raise ValueError("big")
    return open(body).read()
'''
    recs, _ = extract.extract_file("python", "a.py", text, [2, 3])
    assert recs[0].guard_function == "recv"
    assert recs[0].decl_name is None


def test_merge_seed_extracts_guard(make_repo):
    # a merge commit's diff is combined output the patch parser cannot
    # read; diffing the first parent still yields the guard records
    from conftest import commit_env, run_git
    from pathlib import Path

    base = "def recv(body):\n    return open(body).read()\n"
    guarded = (
        "def recv(body):\n"
        "    if len(body) > MAX_LEN:\n"
        '        raise ValueError("big")\n'
        "    return open(body).read()\n"
    )
    r = make_repo([{"files": {"app.py": base}, "message": "base"}])
    run_git(r.root, "checkout", "-q", "-b", "side")
    Path(r.root, "app.py").write_text(guarded)
    run_git(r.root, "add", "app.py")
    run_git(
        r.root, "commit", "-q", "-m", "side", env_extra=commit_env(10)
    )
    run_git(r.root, "checkout", "-q", "main")
    run_git(
        r.root, "merge", "--no-ff", "-m",
        "fix overflow bounds check CVE-2024-42424",
        "side", env_extra=commit_env(11),
    )
    seed_set = seeds.collect_seeds(r.root)
    assert len(seed_set.seeds) == 1
    out = extract.extract_guards(r.root, seed_set)
    assert len(out.records) == 1
    assert out.records[0].sink_function == "recv"


def test_oversized_blob_counts_skip(make_repo):
    # a blob over the size cap is never materialized into a record;
    # it counts as an extraction skip instead
    pad = "# " + "x" * gitlog.MAX_BLOB_BYTES + "\n"
    r = make_repo(
        [
            {"files": {"app.py": "x = 1\n"}, "message": "init"},
            {
                "files": {
                    "app.py": (
                        "def recv(body):\n"
                        "    if len(body) > MAX_LEN:\n"
                        '        raise ValueError("big")\n'
                        "    return open(body).read()\n" + pad
                    )
                },
                "message": "fix overflow bounds check CVE-2024-42424",
            },
        ]
    )
    seed_set = seeds.collect_seeds(r.root)
    out = extract.extract_guards(r.root, seed_set)
    assert out.records == ()
    assert out.skip_reasons["oversized"] == 1


def test_vendored_path_counts_ignored_skip(make_repo):
    # vendored code is not corpus input; the first-party sibling file in
    # the same commit still extracts
    guarded = (
        "def recv(body):\n"
        "    if len(body) > MAX_LEN:\n"
        '        raise ValueError("big")\n'
        "    return open(body).read()\n"
    )
    r = make_repo(
        [
            {"files": {"app.py": "x = 1\n"}, "message": "init"},
            {
                "files": {
                    "vendor/lib.py": guarded,
                    "app.py": guarded,
                },
                "message": "fix overflow bounds check CVE-2024-42424",
            },
        ]
    )
    seed_set = seeds.collect_seeds(r.root)
    out = extract.extract_guards(r.root, seed_set)
    assert len(out.records) == 1
    assert out.records[0].path == "app.py"
    assert out.skip_reasons["ignored"] == 1
