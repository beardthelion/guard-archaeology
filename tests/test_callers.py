"""callers.py: the KTD7 commit-scoped corpus and bounded caller walk.

family_coverage answers covered / absent / unprovable for the guard
family on the sink path at a single commit; tests pin which scope or
ambiguity produced each answer.
"""

from archaeology import callers


UNGUARDED = "def recv(body):\n    return open(body).read()\n"

GUARDED_FN = (
    "def recv(body):\n"
    "    if len(body) > MAX_LEN:\n"
    '        raise ValueError("big")\n'
    "    return open(body).read()\n"
)

# a direct caller (depth 1) whose bound guard covers the path
CALLER_D1 = (
    "from app import recv\n\n"
    "def handle(body):\n"
    "    if len(body) > MAX_LEN:\n"
    '        raise ValueError("big")\n'
    "    return recv(body)\n"
)

# guard two hops up: recv <- mid <- handle
CALLER_D2 = (
    "from app import recv\n\n"
    "def mid(body):\n"
    "    return recv(body)\n\n"
    "def handle(body):\n"
    "    if len(body) > MAX_LEN:\n"
    '        raise ValueError("big")\n'
    "    return mid(body)\n"
)

# guard three hops up: recv <- mid <- handle <- entry
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

# a caller resolvable only through getattr/dispatch
DISPATCH = (
    "import app\n\n"
    "def use(data):\n"
    "    return getattr(app, 'recv')(data)\n"
)

# the guard moved into a shared helper the sink function calls
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

# a module-level call entry guarded at module scope
MODULE_GUARDED = (
    "def recv(body):\n"
    "    return open(body).read()\n\n"
    "if len(input_data) > MAX_LEN:\n"
    '    raise ValueError("big")\n'
    "result = recv(input_data)\n"
)


def _repo(make_repo, files):
    r = make_repo([{"files": files, "message": "init"}])
    return r.root, r.shas[-1]


def _cov(repo, sha, path="app.py", fn="recv", op="open(", family="bounds",
         depth=2):
    return callers.family_coverage(repo, sha, path, fn, op, family, depth)


def test_function_scope_guard_covers(make_repo):
    root, sha = _repo(make_repo, {"app.py": GUARDED_FN})
    cov = _cov(root, sha)
    assert cov.state == callers.COVERED
    assert "function-scope" in cov.detail


def test_zero_callers_is_provable_absent(make_repo):
    # an exported function with no in-repo callers is provable on its
    # own scope: the empty chain cannot hide a guard (KTD7)
    root, sha = _repo(make_repo, {"app.py": UNGUARDED})
    cov = _cov(root, sha)
    assert cov.state == callers.ABSENT
    assert "caller-chain-exhausted" in cov.detail


def test_guard_in_caller_depth1_covers(make_repo):
    root, sha = _repo(
        make_repo, {"app.py": UNGUARDED, "handlers.py": CALLER_D1}
    )
    cov = _cov(root, sha)
    assert cov.state == callers.COVERED
    assert any(d.startswith("caller:handlers.py:handle") for d in cov.detail)


def test_guard_in_caller_depth2_covers(make_repo):
    root, sha = _repo(
        make_repo, {"app.py": UNGUARDED, "mid.py": CALLER_D2}
    )
    assert _cov(root, sha, depth=2).state == callers.COVERED


def test_depth_bound_respected(make_repo):
    root, sha = _repo(
        make_repo,
        {"app.py": UNGUARDED, "mid.py": MID_PLAIN,
         "entry.py": ENTRY_GUARDED},
    )
    # the guard sits three hops up: inside --caller-depth 2 the chain is
    # provably bare; at depth 3 it covers
    assert _cov(root, sha, depth=2).state == callers.ABSENT
    assert _cov(root, sha, depth=3).state == callers.COVERED


def test_guard_in_shared_helper_covers(make_repo):
    root, sha = _repo(
        make_repo, {"app.py": CALLS_HELPER, "helpers.py": HELPER_FILE}
    )
    cov = _cov(root, sha)
    assert cov.state == callers.COVERED
    assert "callee-scope" in cov.detail


def test_getattr_dispatch_is_unprovable(make_repo):
    root, sha = _repo(
        make_repo, {"app.py": UNGUARDED, "helpers.py": DISPATCH}
    )
    cov = _cov(root, sha)
    assert cov.state == callers.UNPROVABLE
    assert any("dynamic-ref" in d for d in cov.detail)


def test_alias_binding_is_unprovable(make_repo):
    alias = (
        "from app import recv\n\n"
        "def use(data):\n"
        "    f = recv\n"
        "    return f(data)\n"
    )
    root, sha = _repo(
        make_repo, {"app.py": UNGUARDED, "helpers.py": alias}
    )
    cov = _cov(root, sha)
    assert cov.state == callers.UNPROVABLE


def test_attribute_call_is_unprovable(make_repo):
    attr = "import app\n\ndef use(data):\n    return app.recv(data)\n"
    root, sha = _repo(
        make_repo, {"app.py": UNGUARDED, "helpers.py": attr}
    )
    cov = _cov(root, sha)
    assert cov.state == callers.UNPROVABLE


def test_module_level_guard_covers_module_call(make_repo):
    root, sha = _repo(make_repo, {"app.py": MODULE_GUARDED})
    cov = _cov(root, sha)
    assert cov.state == callers.COVERED
    assert any(d.startswith("module-scope") for d in cov.detail)


def test_unsupported_candidate_file_is_not_evidence(make_repo):
    # a .c file mentioning the name is outside the four-language corpus:
    # skipped, never a caller and never an ambiguity
    root, sha = _repo(
        make_repo,
        {"app.py": UNGUARDED, "old.c": "int f() { return recv(x); }\n"},
    )
    assert _cov(root, sha).state == callers.ABSENT


def test_guard_on_unrelated_name_does_not_cover(make_repo):
    caller = (
        "from app import recv\n\n"
        "def handle(body, other):\n"
        "    if len(other) > MAX_LEN:\n"
        '        raise ValueError("big")\n'
        "    return recv(body)\n"
    )
    root, sha = _repo(
        make_repo, {"app.py": UNGUARDED, "handlers.py": caller}
    )
    # the caller's guard binds 'other', not the sink argument
    assert _cov(root, sha).state == callers.ABSENT


def test_shadowed_def_binds_locally_not_ambiguous(make_repo):
    local = (
        "def recv(body):\n    return 1\n\n"
        "def use(d):\n    return recv(d)\n"
    )
    root, sha = _repo(
        make_repo, {"app.py": UNGUARDED, "other.py": local}
    )
    # other.py defines its own recv; its calls resolve there, and the
    # tracked function's chain stays provably empty
    assert _cov(root, sha).state == callers.ABSENT


def test_ambiguous_same_named_defs_unprovable(make_repo):
    # the sink function name resolves to two defs in its own file
    two = (
        "def recv(body):\n    return open(body).read()\n\n"
        "def recv(body):\n    return body\n"
    )
    root, sha = _repo(make_repo, {"app.py": two})
    cov = _cov(root, sha)
    assert cov.state == callers.UNPROVABLE
    assert "sink-function-ambiguous" in cov.detail


# --- sink_present ---------------------------------------------------------


def test_sink_present_true(make_repo):
    root, sha = _repo(make_repo, {"app.py": UNGUARDED})
    assert callers.sink_present(root, sha, "app.py", "recv", "open(")


def test_sink_present_function_gone(make_repo):
    gone = "def other():\n    return 1\n"
    root, sha = _repo(make_repo, {"app.py": gone})
    assert callers.sink_present(root, sha, "app.py", "recv", "open(") is False


def test_sink_present_file_gone(make_repo):
    root, sha = _repo(make_repo, {"app.py": UNGUARDED})
    assert (
        callers.sink_present(root, sha, "gone.py", "recv", "open(")
        is False
    )


def test_sink_present_renamed_function_is_unprovable(make_repo):
    # the recorded function name is gone but the sink op still exists:
    # the walk cannot re-attribute it
    moved = "def receive(body):\n    return open(body).read()\n"
    root, sha = _repo(make_repo, {"app.py": moved})
    assert callers.sink_present(root, sha, "app.py", "recv", "open(") is None
