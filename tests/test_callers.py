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


def test_unsupported_candidate_file_is_unprovable(make_repo):
    # a .vue/.pyx/.pyi file mentioning the name may hold a caller the
    # corpus cannot examine: an ambiguity, never claimed absence
    root, sha = _repo(
        make_repo,
        {"app.py": UNGUARDED, "old.vue": "int f() { return recv(x); }\n"},
    )
    cov = _cov(root, sha)
    assert cov.state == callers.UNPROVABLE
    assert any(d.startswith("unsupported-ext:") for d in cov.detail)


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


def test_guard_on_non_root_sink_arg_name_covers(make_repo):
    # 'name' binds to open(base + '/' + name) as much as 'base' does: a
    # guard on the non-root identifier still covers the sink path
    guarded = (
        "def recv(base, name):\n"
        "    if '..' in name:\n"
        "        raise ValueError('bad')\n"
        "    return open(base + '/' + name).read()\n"
    )
    root, sha = _repo(make_repo, {"app.py": guarded})
    cov = callers.family_coverage(
        root, sha, "app.py", "recv", "open(", "allowlist", 2
    )
    assert cov.state == callers.COVERED
    assert "function-scope" in cov.detail


def test_depth_zero_with_callers_is_unprovable(make_repo):
    # a zero bound cannot examine the callers it found: unprovable,
    # never claimed absent
    root, sha = _repo(
        make_repo, {"app.py": UNGUARDED, "handlers.py": CALLER_D1}
    )
    cov = _cov(root, sha, depth=0)
    assert cov.state == callers.UNPROVABLE
    assert "depth-bound:callers" in cov.detail


def test_depth_zero_without_callers_is_absent(make_repo):
    root, sha = _repo(make_repo, {"app.py": UNGUARDED})
    assert _cov(root, sha, depth=0).state == callers.ABSENT


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


# --- dispatch-registration bindings -----------------------------------------

# aiohttp-style: a request handler bound via a member-access argument,
# 'self.add_route("GET", self._handle, self)', inside the same file.
# Not a name-call, but a registered handler is reachable through
# framework dispatch: a resolvable caller edge that carries no guard.
HANDLER_GUARDED = (
    "class H:\n"
    "    def wire(self):\n"
    '        self.add_route("GET", self._handle, self)\n\n'
    "    def _handle(self, request):\n"
    "        if len(request.path) > MAX_LEN:\n"
    '            raise ValueError("big")\n'
    "        return open(request.path).read()\n"
)
HANDLER_BARE = (
    "class H:\n"
    "    def wire(self):\n"
    '        self.add_route("GET", self._handle, self)\n\n'
    "    def _handle(self, request):\n"
    "        return open(request.path).read()\n"
)

# a flask-style decorator binding directly above the def
DECORATED_HANDLER = (
    '@app.route("/x")\n'
    "def handler(request):\n"
    "    return open(request.path).read()\n"
)

# a binding shape the dispatch table does not cover: still an
# unresolvable mention, never claimed absent
LIST_BOUND = (
    "from app import handler\n\n"
    "HANDLERS = []\n"
    "HANDLERS.append(handler)\n"
)

# a dispatch registration in a different file than the sink def
ROUTES_FILE = (
    "from app import handler\n\n"
    'router.get("/x", handler)\n'
)


def test_dispatch_binding_boundary_is_absent(make_repo):
    # the guard existed, then a removal commit dropped it: at the
    # boundary the registered handler is reachable and unguarded, so
    # coverage is provably ABSENT, not unprovable on the
    # attribute-access mention
    r = make_repo(
        [
            {"files": {"web.py": HANDLER_GUARDED}, "message": "add"},
            {"files": {"web.py": HANDLER_BARE}, "message": "drop guard"},
        ]
    )
    before = callers.family_coverage(
        r.root, r.shas[0], "web.py", "H._handle", "open(", "bounds", 2
    )
    assert before.state == callers.COVERED
    cov = callers.family_coverage(
        r.root, r.shas[-1], "web.py", "H._handle", "open(", "bounds", 2
    )
    assert cov.state == callers.ABSENT
    assert "caller-chain-exhausted" in cov.detail
    assert any(d.startswith("dispatch:") for d in cov.detail)


def test_dispatch_decorator_binding_is_absent(make_repo):
    root, sha = _repo(make_repo, {"app.py": DECORATED_HANDLER})
    cov = callers.family_coverage(
        root, sha, "app.py", "handler", "open(", "bounds", 2
    )
    assert cov.state == callers.ABSENT
    assert any(d.startswith("dispatch:") for d in cov.detail)


def test_non_dispatch_binding_stays_unprovable(make_repo):
    # registration through a shape the table does not cover is a
    # binding the walk cannot establish: fail quiet, never absent
    root, sha = _repo(
        make_repo,
        {
            "app.py": "def handler(request):\n"
            "    return open(request.path).read()\n",
            "reg.py": LIST_BOUND,
        },
    )
    cov = callers.family_coverage(
        root, sha, "app.py", "handler", "open(", "bounds", 2
    )
    assert cov.state == callers.UNPROVABLE
    assert any("live-mention" in d for d in cov.detail)


def test_dispatch_binding_in_another_file_is_absent(make_repo):
    root, sha = _repo(
        make_repo,
        {
            "app.py": "def handler(request):\n"
            "    return open(request.path).read()\n",
            "routes.py": ROUTES_FILE,
        },
    )
    cov = callers.family_coverage(
        root, sha, "app.py", "handler", "open(", "bounds", 2
    )
    assert cov.state == callers.ABSENT
    assert any(d.startswith("dispatch:routes.py") for d in cov.detail)


def test_guarded_caller_covers_despite_dispatch_edge(make_repo):
    # a dispatch edge is only an unguarded path: a real caller carrying
    # the family still covers
    sink = "def handler(request):\n    return open(request.path).read()\n"
    caller = (
        "from app import handler\n\n"
        "def entry(req):\n"
        "    if len(req.path) > MAX_LEN:\n"
        '        raise ValueError("big")\n'
        "    return handler(req)\n"
    )
    root, sha = _repo(
        make_repo,
        {"app.py": sink, "routes.py": ROUTES_FILE, "entry.py": caller},
    )
    cov = callers.family_coverage(
        root, sha, "app.py", "handler", "open(", "bounds", 2
    )
    assert cov.state == callers.COVERED
    assert any(d.startswith("caller:entry.py") for d in cov.detail)


# --- per-mention member attribution -----------------------------------------

# aiohttp-style: two classes in one file both define '_handle'. The
# 'self._handle' passed to ResourceRoute inside StaticResource.__init__
# binds to StaticResource._handle (our sink), while the one inside
# Route.__init__ binds to Route._handle, a different member, and is not
# evidence at all.
TWO_CLASS = (
    "class StaticResource:\n"
    "    def __init__(self):\n"
    "        self._routes = {\n"
    '            "GET": ResourceRoute(\n'
    '                "GET", self._handle, self\n'
    "            ),\n"
    "        }\n\n"
    "    def _handle(self, request):\n"
    "        return open(request.path).read()\n\n"
    "class Route:\n"
    "    def __init__(self):\n"
    "        super().__init__(self._handle)\n\n"
    "    def _handle(self, request):\n"
    "        return 1\n"
)

# a function reference handed to a constructor: the callee invokes it
# per request elsewhere, unguarded
RUNNER_HANDOFF = (
    "class Runner:\n"
    "    def make_server(self):\n"
    "        return Server(\n"
    "            self._app._handle,\n"
    "            request_factory=self._make_request,\n"
    "        )\n"
)

SINK_METHOD = (
    "class App:\n"
    "    def _handle(self, request):\n"
    "        return open(request.path).read()\n"
)


def test_same_named_members_attribute_per_class(make_repo):
    root, sha = _repo(make_repo, {"web.py": TWO_CLASS})
    cov = callers.family_coverage(
        root, sha, "web.py", "StaticResource._handle", "open(", "bounds", 2
    )
    # StaticResource's own 'self._handle' handoffs are unguarded edges;
    # Route's same-named member mention is not evidence
    assert cov.state == callers.ABSENT
    assert any(d.startswith("dispatch:") for d in cov.detail)


def test_self_call_attributed_to_sink_is_a_caller_edge(make_repo):
    # 'self._handle(req)' inside the sink's own class invokes the sink:
    # a real caller edge whose enclosing method is guard-evaluated
    src = (
        "class App:\n"
        "    def entry(self, req):\n"
        "        if len(req.path) > MAX_LEN:\n"
        '            raise ValueError("big")\n'
        "        return self._handle(req)\n\n"
        "    def _handle(self, request):\n"
        "        return open(request.path).read()\n"
    )
    root, sha = _repo(make_repo, {"app.py": src})
    cov = callers.family_coverage(
        root, sha, "app.py", "App._handle", "open(", "bounds", 2
    )
    assert cov.state == callers.COVERED
    assert any(d.startswith("caller:app.py:App.entry") for d in cov.detail)


def test_arg_position_handoff_is_unguarded_edge(make_repo):
    root, sha = _repo(
        make_repo, {"app.py": SINK_METHOD, "runner.py": RUNNER_HANDOFF}
    )
    cov = callers.family_coverage(
        root, sha, "app.py", "App._handle", "open(", "bounds", 2
    )
    assert cov.state == callers.ABSENT
    assert any(
        d.startswith("dispatch:runner.py") for d in cov.detail
    )


def test_unproven_receiver_call_is_unprovable(make_repo):
    # 'obj._handle(req)' invokes SOME member named _handle; without a
    # receiver construction in the file the walk cannot prove it is ours
    call = "def use(obj, req):\n    return obj._handle(req)\n"
    root, sha = _repo(
        make_repo, {"app.py": SINK_METHOD, "use.py": call}
    )
    cov = callers.family_coverage(
        root, sha, "app.py", "App._handle", "open(", "bounds", 2
    )
    assert cov.state == callers.UNPROVABLE
    assert any(d.startswith("member-call:") for d in cov.detail)


def test_proven_receiver_call_is_a_caller_edge(make_repo):
    # 'obj = App(' in the same file proves the receiver's type: the
    # member call is the tracked sink's caller and its guards count
    call = (
        "def use(req):\n"
        "    obj = App()\n"
        "    if len(req.path) > MAX_LEN:\n"
        '        raise ValueError("big")\n'
        "    return obj._handle(req)\n"
    )
    root, sha = _repo(
        make_repo, {"app.py": SINK_METHOD, "use.py": call}
    )
    cov = callers.family_coverage(
        root, sha, "app.py", "App._handle", "open(", "bounds", 2
    )
    assert cov.state == callers.COVERED
    assert any(d.startswith("caller:use.py") for d in cov.detail)


def test_self_mention_unattributable_is_unprovable(make_repo):
    # 'self._handle' in a class that does not define _handle may resolve
    # through an invisible base: fail quiet
    src = (
        "class C:\n"
        "    def use(self):\n"
        "        return wrap(self._handle)\n"
    )
    root, sha = _repo(
        make_repo, {"app.py": SINK_METHOD, "other.py": src}
    )
    cov = callers.family_coverage(
        root, sha, "app.py", "App._handle", "open(", "bounds", 2
    )
    assert cov.state == callers.UNPROVABLE
    assert any("live-mention" in d for d in cov.detail)


def test_doc_mention_is_not_evidence(make_repo):
    # a .rst file cannot hold a call site in the four corpus languages
    root, sha = _repo(
        make_repo,
        {
            "app.py": UNGUARDED,
            "notes.rst": "call recv(x) on every request\n",
        },
    )
    assert _cov(root, sha).state == callers.ABSENT


def test_pyx_mention_stays_ambiguous(make_repo):
    # .pyx can embed python: a word mention there may hide a caller
    root, sha = _repo(
        make_repo,
        {"app.py": UNGUARDED, "old.pyx": "def f():\n    return recv(x)\n"},
    )
    cov = _cov(root, sha)
    assert cov.state == callers.UNPROVABLE
    assert any(d.startswith("unsupported-ext:") for d in cov.detail)


def test_bare_name_arg_to_bare_call_is_handoff(make_repo):
    # 'map(recv, xs)' hands the reference to a bare callee that invokes
    # it: an unguarded edge. A member callee ('HANDLERS.append(recv)')
    # may only store it and stays ambiguous (pinned above).
    use = "def feed(items):\n    return list(map(recv, items))\n"
    root, sha = _repo(
        make_repo, {"app.py": UNGUARDED, "use.py": use}
    )
    cov = _cov(root, sha)
    assert cov.state == callers.ABSENT
    assert any(d.startswith("dispatch:use.py") for d in cov.detail)


def test_bare_name_in_return_position_is_handoff(make_repo):
    # 'return recv' hands the reference to the caller, which invokes it
    # elsewhere, unguarded: a dispatch edge, not an ambiguity
    use = "def pick():\n    return recv\n"
    root, sha = _repo(
        make_repo, {"app.py": UNGUARDED, "use.py": use}
    )
    cov = _cov(root, sha)
    assert cov.state == callers.ABSENT
    assert any(d.startswith("dispatch:use.py") for d in cov.detail)
