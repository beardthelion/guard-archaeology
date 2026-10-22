import re

import pytest

from archaeology import shapes


# --- language detection ---------------------------------------------------------


def test_language_for_path_covers_four_languages():
    assert shapes.language_for_path("a/b.go") == "go"
    assert shapes.language_for_path("a/b.rs") == "rust"
    assert shapes.language_for_path("a/b.py") == "python"
    for ext in (".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs"):
        assert shapes.language_for_path("a/x" + ext) == "tsjs"


def test_language_for_path_unsupported():
    assert shapes.language_for_path("main.c") is None
    assert shapes.language_for_path("README") is None
    assert shapes.language_for_path("Makefile.am") is None
    assert shapes.language_for_path(None) is None


# --- golden signatures: three shapes in four languages ----------------------------

GOLDENS = [
    (
        "python",
        'if len(data) > MAX_LEN:\n    raise ValueError("too large")',
        "if CALL:size(ID)>ID:raise CALL:valueerror(STR)",
        ("conditional-rejection", "bounds"),
    ),
    (
        "go",
        'if len(d) > MaxSize {\n\treturn fmt.Errorf("too large")\n}',
        "if CALL:size(ID)>ID{return CALL:errorf(STR)}",
        ("conditional-rejection", "bounds"),
    ),
    (
        "rust",
        'if input.len() > MAX {\n    return Err("too long".into());\n}',
        "if CALL:size()>ID{return CALL:err(STR.CALL:into());}",
        ("conditional-rejection", "bounds"),
    ),
    (
        "tsjs",
        'if (!allowedHosts.has(host)) {\n  throw new Error("bad host");\n}',
        "if(!CALL:check(ID)){throw new CALL:error(STR);}",
        ("conditional-rejection", "allowlist"),
    ),
    (
        "python",
        "name = sanitize_name(raw)",
        "ID=CALL:sanitize(ID)",
        ("validation-call", "validation"),
    ),
    (
        "go",
        "p = filepath.Clean(p)",
        "ID=CALL:sanitize(ID)",
        ("validation-call", "validation"),
    ),
    (
        "rust",
        "let v = validate_input(raw)?;",
        "let ID=CALL:check(ID)?;",
        ("validation-call", "validation"),
    ),
    (
        "tsjs",
        "const safe = escapeHtml(input);",
        "const ID=CALL:escape(ID);",
        ("validation-call", "escape"),
    ),
    (
        "python",
        "MAX_UPLOAD = 1024 * 1024",
        "ID=NUM*NUM",
        ("constant-limit", "bounds"),
    ),
    (
        "go",
        "const MaxUpload = 4096",
        "const ID=NUM",
        ("constant-limit", "bounds"),
    ),
    (
        "rust",
        "const MAX_INPUT: usize = 512;",
        "const ID:ID=NUM;",
        ("constant-limit", "bounds"),
    ),
    (
        "tsjs",
        "const MAX_BODY = 8192;",
        "const ID=NUM;",
        ("constant-limit", "bounds"),
    ),
]


@pytest.mark.parametrize("lang,stmt,sig,cls", GOLDENS)
def test_golden_signature_and_shape(lang, stmt, sig, cls):
    assert shapes.normalize_statement(lang, stmt) == sig
    got = shapes.classify_statement(lang, stmt)
    assert got is not None
    assert got[0] == cls[0]
    assert got[1] == cls[1]


# --- normalization invariance --------------------------------------------------------


def test_signature_invariant_under_identifier_renames():
    a = shapes.normalize_statement(
        "python", 'if len(data) > MAX_LEN:\n    raise ValueError("big")'
    )
    b = shapes.normalize_statement(
        "python", 'if len(payload) > LIMIT_BYTES:\n    raise ValueError("huge")'
    )
    assert a == b


def test_signature_invariant_under_literal_changes():
    a = shapes.normalize_statement("tsjs", "const MAX_BODY = 8192;")
    b = shapes.normalize_statement("tsjs", "const MAX_BODY = 4096;")
    assert a == b


def test_signature_invariant_under_line_split():
    one = shapes.normalize_statement(
        "python", 'if (len(data) > MAX_LEN):\n    raise ValueError("big")'
    )
    split = shapes.normalize_statement(
        "python",
        'if (len(data) >\n        MAX_LEN):\n    raise ValueError("big")',
    )
    assert one == split == "if(CALL:size(ID)>ID):raise CALL:valueerror(STR)"


def test_comparison_direction_kept():
    a = shapes.normalize_statement("go", "if len(d) > max {\n\treturn e\n}")
    b = shapes.normalize_statement("go", "if len(d) < max {\n\treturn e\n}")
    assert a != b
    assert ">" in a and "<" in b


# --- classification negatives ---------------------------------------------------------


def test_if_without_rejection_not_classified():
    stmt = 'if len(d) > 5 {\n\tseen = true\n}'
    assert shapes.classify_statement("go", stmt) is None


def test_if_without_guard_cue_not_classified():
    # a bare truthy check is not a guard shape
    stmt = 'if debug {\n\treturn err\n}'
    assert shapes.classify_statement("go", stmt) is None


def test_member_access_with_bare_return_not_a_guard():
    # 'if cfg.offline: return' is a feature toggle: the member-access
    # cue only counts when the body hard-rejects
    assert (
        shapes.classify_statement(
            "python", "if cfg.offline:\n    return None"
        )
        is None
    )
    assert (
        shapes.classify_statement(
            "tsjs", "if (cfg.offline) {\n  return;\n}"
        )
        is None
    )


def test_member_access_with_raise_still_classifies():
    got = shapes.classify_statement(
        "python", 'if name.anchor:\n    raise ValueError("abs")'
    )
    assert got is not None
    assert got[0] == "conditional-rejection"
    got = shapes.classify_statement(
        "tsjs", 'if (cfg.offline) {\n  throw new Error("x");\n}'
    )
    assert got is not None
    assert got[0] == "conditional-rejection"


def test_non_guard_call_not_classified():
    assert shapes.classify_statement("python", "result = transform(x)") is None
    assert shapes.classify_statement("tsjs", "renderPage(ctx);") is None


def test_assignment_of_call_not_a_constant():
    # RHS with a non-constructor call is not a literal constant
    got = shapes.classify_statement("python", "value = compute()")
    assert got is None


def test_allowlist_constant_family():
    got = shapes.classify_statement(
        "python", 'ALLOWED_HOSTS = {"a.com", "b.com"}'
    )
    assert got is not None
    assert got[0] == "constant-limit"
    assert got[1] == "allowlist"
    assert got[2]["name"] == "ALLOWED_HOSTS"


def test_auth_family_from_condition():
    got = shapes.classify_statement(
        "python",
        'if not is_admin(user):\n    raise Forbidden("no")',
    )
    assert got is not None
    assert got[1] == "auth"


def test_symlink_family_from_condition():
    got = shapes.classify_statement(
        "python",
        'if os.path.islink(path):\n    raise ValueError("link")',
    )
    assert got is not None
    assert got[1] == "symlink"


# --- call families -----------------------------------------------------------------


@pytest.mark.parametrize(
    "name,fam",
    [
        ("len", "size"),
        ("input.len", "size"),
        ("filepath.Clean", "sanitize"),
        ("sanitize_input", "sanitize"),
        ("html.escape", "escape"),
        ("check_perms", "auth"),
        ("require_auth", "auth"),
        ("isinstance", "type"),
        ("fmt.Errorf", "errorf"),
    ],
)
def test_call_family(name, fam):
    assert shapes.call_family(name) == fam


# --- -G regex compiler --------------------------------------------------------------


def test_signature_regex_expands_token_classes():
    rx = shapes.signature_regex("if CALL:size(ID)>ID:")
    assert re.search(rx, "if len(payload) > MAX:")
    assert re.search(rx, "if count(user_input)>  LIMIT:")
    assert not re.search(rx, "if len(payload) < MAX:")


def test_signature_regex_does_not_match_token_names():
    # the -G pattern must match source text, never the abstract tokens
    rx = shapes.signature_regex("if CALL:size(ID)>ID:")
    assert not re.search(rx, "if CALL:size(ID)>ID:")


def test_signature_regex_string_and_number_classes():
    rx = shapes.signature_regex("raise CALL:valueerror(STR)")
    assert re.search(rx, 'raise ValueError("gone")')
    assert re.search(rx, "raise TypeError('gone')")
    rx = shapes.signature_regex("const ID=NUM")
    assert re.search(rx, "const MaxUpload = 4096")


def test_signature_regex_multiline_anchor_is_first_line():
    # a multi-line signature compiles from its first-line skeleton (KTD3)
    anchor = shapes.normalize_statement(
        "go", "if len(d) > MaxSize {"
    )
    full = shapes.normalize_statement(
        "go", 'if len(d) > MaxSize {\n\treturn fmt.Errorf("big")\n}'
    )
    assert anchor != full
    rx = shapes.signature_regex(anchor)
    assert re.search(rx, "if len(payload) > Cap {")
    assert not re.search(rx, "return fmt.Errorf(")


# --- function attribution -------------------------------------------------------------


def test_find_functions_go():
    text = (
        "package m\n\n"
        "type Srv struct{}\n\n"
        "func (s *Srv) Do(x string) error {\n"
        "\treturn nil\n"
        "}\n\n"
        "func Plain() {\n}\n"
    )
    funcs = shapes.find_functions("go", text)
    names = {f.qualname for f in funcs}
    assert "Srv.Do" in names
    assert "Plain" in names


def test_find_functions_rust_impl_and_mod():
    text = (
        "mod inner {\n"
        "    impl Conn {\n"
        "        fn send(&self) {\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    funcs = shapes.find_functions("rust", text)
    names = {f.qualname for f in funcs}
    assert "inner::Conn::send" in names


def test_find_functions_python_qualnames():
    text = (
        "class H:\n"
        "    def run(self):\n"
        "        def inner():\n"
        "            pass\n"
        "        return inner()\n"
        "\n"
        "def top():\n"
        "    pass\n"
    )
    funcs = shapes.find_functions("python", text)
    names = {f.qualname for f in funcs}
    assert "H.run" in names
    assert "H.run.<locals>.inner" in names
    assert "top" in names


def test_find_functions_tsjs():
    text = (
        "class Svc {\n"
        "  handle(req) {\n"
        "    return 1;\n"
        "  }\n"
        "}\n"
        "function top() {}\n"
        "const arrow = (x) => {\n"
        "  return x;\n"
        "};\n"
    )
    funcs = shapes.find_functions("tsjs", text)
    names = {f.qualname for f in funcs}
    assert "Svc.handle" in names
    assert "top" in names
    assert "arrow" in names


def test_control_keywords_not_functions():
    funcs = shapes.find_functions(
        "tsjs", "if (x) {\n  while (y) {\n  }\n}\n"
    )
    assert funcs == []


# --- sink catalog -----------------------------------------------------------------


@pytest.mark.parametrize(
    "lang,line,op",
    [
        ("go", 'exec.Command("sh", p)', "exec.Command("),
        ("go", "os.ReadFile(p)", "os.ReadFile("),
        ("rust", "fs::read(path)?;", "fs::read"),
        ("rust", "Command::new(bin)", "Command::new"),
        ("python", "os.system(cmd)", "os.system("),
        ("python", "open(path).read()", "open("),
        ("python", "root.joinpath(name).resolve()", ".joinpath("),
        ("python", "p.write_text(data)", ".write_text("),
        ("python", "p.symlink_to(target)", ".symlink_to("),
        ("python", "os.readlink(p)", "os.readlink("),
        ("tsjs", 'document.write(x);', "document.write("),
        ("tsjs", "res.send(body);", "res.send("),
    ],
)
def test_sink_op(lang, line, op):
    assert shapes.sink_op(lang, line) == op


def test_sink_op_masked_strings_do_not_fire():
    # a sink op inside a string literal is not a real sink
    line = 'fmt.Println("os.ReadFile(p)")'
    assert shapes.sink_op("go", line) is None
    assert shapes.sink_op("go", "fmt.Println(x)") is None


# --- masks --------------------------------------------------------------------------


def test_mask_code_blanks_strings_and_comments():
    masked = shapes.mask_code('x = "a { b" // { comment', "tsjs")
    assert masked.count("{") == 0
    masked = shapes.mask_code('x = 1  # { comment', "python")
    assert masked.count("{") == 0


# --- path predicates -------------------------------------------------------------


def test_is_test_path_dir_segments_and_basenames():
    for p in (
        "tests/test_app.py",
        "x/test/y.py",
        "a/testing/b.py",
        "pkg/spec/s.py",
        "e2e/run.js",
        "tests/integration/deep.py",
        "integration_tests/x.py",
        "src/__mocks__/x.js",
        "a/fixtures/b.py",
        "mocks/f.py",
        "helpers/stubs/s.py",
        "foo/test_main.py",
        "main_test.py",
        "main_test.go",
        "TestFoo.go",
        "foo.test.ts",
        "foo.spec.js",
        "conftest.py",
        "tests.py",
    ):
        assert shapes.is_test_path(p), p


def test_is_test_path_negative():
    for p in (
        "app.py",
        "src/parser.py",
        "lib/contest.py",
        "protest/x.py",
        "src/attest/helpers.py",
        "my_best_notes.txt",
        "speculator.py",
    ):
        assert not shapes.is_test_path(p), p
    assert not shapes.is_test_path("")
    assert not shapes.is_test_path(None)


def test_is_ignored_path_vendored_and_env_dirs():
    for p in (
        "vendor/lib.py",
        "node_modules/pkg/index.js",
        "src/node_modules/pkg/index.js",
        "venv/lib/python3.12/site.py",
        ".venv/x.py",
        "third_party/y.go",
        "deps/site-packages/z.py",
    ):
        assert shapes.is_ignored_path(p), p
    for p in ("app.py", "vendorless/x.py", "src/env_setup.py"):
        assert not shapes.is_ignored_path(p), p
