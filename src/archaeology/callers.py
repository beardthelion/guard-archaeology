"""Commit-scoped caller corpus: KTD7's lexical bounded caller chain.

REGRESSED must prove the guard family absent on the whole sink path,
the sink function plus its bounded caller chain, at a given commit
(R9). This module builds that proof against the tree materialized at a
single commit: ``git grep -l <name> <sha>`` narrows the caller-candidate
file set without materializing the whole tree, ``git show <sha>:<path>``
reads each candidate, and the enclosing-function extents come from the
same lexical scan extraction uses (shapes.find_functions).

Coverage states:

- ``covered``: a same-family guard is provably on the sink path (the
  function itself, a same-file helper it calls before the sink, a bound
  caller within ``--caller-depth``, or a module-level guard before a
  module-level call).
- ``absent``: every resolvable caller within the bound was checked and
  none carries the family. A function with zero resolvable in-repo
  callers is provable on its own scope (KTD7: the empty chain cannot
  hide a guard), so exported sinks can still reach REGRESSED. A
  dispatch-registration binding ('self.add_route("GET", self._handle)',
  '@app.route("/x")' above the def) also resolves to an unguarded
  caller edge: the framework dispatcher is the real caller and carries
  no guard.
- ``unprovable``: any ambiguity, a getattr/quoted-string reference, a
  non-dispatch live mention, a member call on an unproven receiver, a
  self-mention its enclosing class cannot attribute, an unparseable
  call site, an unreadable candidate. Cannot prove always degrades to
  UNKNOWN, never REGRESSED.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from . import extract, gitlog, shapes

COVERED = "covered"
ABSENT = "absent"
UNPROVABLE = "unprovable"

AMBIGUOUS = object()  # locate_function sentinel: name resolves to >1 def


@dataclass(frozen=True)
class Coverage:
    """Provable family-coverage answer for one commit."""

    state: str  # covered | absent | unprovable
    detail: tuple = ()  # machine markers: which scope/path decided it


# --- lexical helpers ------------------------------------------------------------


def _quoted_re(name):
    # a bare quoted token: the dynamic-reference idiom (getattr,
    # dispatch tables, globals()[...]). Multi-word strings do not match.
    return re.compile(r"[\"'`]" + re.escape(name) + r"[\"'`]")


def _mentions(masked_text, names):
    return any(shapes._word_re(n).search(masked_text) for n in names)


def _split_top(args_text):
    """Top-level comma segments of an argument/param list."""
    parts, depth, cur = [], 0, []
    for ch in args_text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth <= 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


def _call_args(masked_text, name, member=False):
    """Argument-list text of the first name(...) call, or None.

    The text must be string/comment-masked so parens inside literals do
    not unbalance the scan. ``member`` also matches attribute-qualified
    calls ('obj.name(...)'); the default bare form does not.
    """
    if member:
        cre = re.compile(r"(?<![\w$])" + re.escape(name) + r"\s*\(")
    else:
        cre = shapes._call_re(name)
    m = cre.search(masked_text)
    if m is None:
        return None
    i = masked_text.find("(", m.start())
    depth = 0
    for j in range(i, len(masked_text)):
        ch = masked_text[j]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return masked_text[i + 1 : j]
    return None


_KWARG_RE = re.compile(r"^\s*([A-Za-z_$][\w$]*)\s*=(?![=])")
_IDENT = re.compile(r"[A-Za-z_$][\w$]*")


def _arg_names(args_text):
    """Identifier set of each positional/keyword argument, in order.

    Every identifier in the segment binds to the sink argument, not just
    the first root: a guard on ``name`` covers ``open(base + '/' + name)``
    and one on ``f`` covers ``os.path.join(d, f)`` equally. A keyword
    argument's own name is a parameter name, not data, so it is skipped.
    """
    roots = []
    for seg in _split_top(args_text):
        seg = seg.strip()
        if not seg:
            roots.append(frozenset())
            continue
        kw = _KWARG_RE.match(seg)
        if kw:
            seg = seg[kw.end() :]
        roots.append(frozenset(_IDENT.findall(seg)))
    return roots


def _head_params(lines, masked, func, name, lang):
    """Ordered first-identifier-per-segment param names of a decl."""
    head = "\n".join(lines[func.start : min(func.end, func.start + 8) + 1])
    args = _call_args(shapes.mask_code(head, lang), name)
    if args is None:
        return []
    params = []
    for seg in _split_top(args):
        m = re.match(r"\s*\*{0,2}\s*([A-Za-z_$][\w$]*)", seg)
        if m:
            params.append(m.group(1))
    return params


def _mapped_params(args_text, params, bound_names):
    """Callee param names receiving a sink-bound argument.

    Positional args map to params by index; a keyword arg maps to its
    named param. When no arg binds, the weak form binds every param,
    a guard on any callee input counts as cover (fail-quiet side).
    """
    segs = _split_top(args_text)
    roots = _arg_names(args_text)
    mapped = set()
    for i, seg in enumerate(segs):
        root = roots[i] if i < len(roots) else frozenset()
        on_path = bound_names is None or bool(root & bound_names)
        if not on_path:
            continue
        kw = _KWARG_RE.match(seg)
        if kw and kw.group(1) in params:
            mapped.add(kw.group(1))
        elif i < len(params):
            mapped.add(params[i])
    if not mapped:
        return None  # nothing bound: caller decides weak/ambig
    return mapped


def locate_function(funcs, qualname):
    """FuncRange for a sink qualname, AMBIGUOUS, or None.

    Exact qualname first; a single same-basename function is the
    fallback. More than one match on either pass is a binding the
    lexical walk cannot establish, AMBIGUOUS, never a guess.
    """
    exact = [
        f for f in funcs if f.kind == "func" and f.qualname == qualname
    ]
    if len(exact) > 1:
        return AMBIGUOUS
    if exact:
        return exact[0]
    base = shapes.basename(qualname)
    matches = [f for f in funcs if f.kind == "func" and f.name == base]
    if len(matches) > 1:
        return AMBIGUOUS
    return matches[0] if matches else None


# --- guard statements on a path ----------------------------------------------------


def _guarded_stmt(lines, masked, lang, i, family, bound_names,
                  before_line):
    """True when the statement at line i is a same-family guard that
    completes on/before before_line and mentions a bound name (the weak
    form, bound_names=None, counts any same-family guard in scope)."""
    stmt, end = extract._complete_statement(lang, lines, masked, i)
    if end > before_line:
        return False  # spans the call: a guard must complete before it
    cls = shapes.classify_statement(lang, stmt)
    if cls is None or cls[1] != family:
        return False
    if bound_names is not None and not _mentions(
        shapes.mask_code(stmt, lang), bound_names
    ):
        return False
    return True


def _family_guard(lines, masked, lang, func, family, bound_names,
                  before_line):
    """Same-family guard statement in func ending on/before before_line.

    ``bound_names`` restricts which statements cover: the guard must
    mention a bound identifier (the name binding to the sink argument,
    KTD7). bound_names=None is the weak form, any same-family guard in
    scope counts.
    """
    end_of = min(func.end, len(lines) - 1, before_line)
    for i in range(func.start, end_of + 1):
        if not masked[i].strip():
            continue
        if _guarded_stmt(
            lines, masked, lang, i, family, bound_names, before_line
        ):
            return True
    return False


def _module_guard(lines, masked, lang, funcs, family, bound_names,
                  before_line):
    """Same-family guard at module scope before a module-level call."""
    inside = set()
    for f in funcs:
        inside.update(range(f.start, f.end + 1))
    for i in range(0, min(before_line, len(lines) - 1) + 1):
        if i in inside or not masked[i].strip():
            continue
        if _guarded_stmt(
            lines, masked, lang, i, family, bound_names, before_line
        ):
            return True
    return False


def _callee_defs(repo, sha, cpath, name):
    """(defs, ambiguous), in-repo definitions of a callee name at sha.

    defs: (fpath, ftext, flang, ffuncs, FuncRange) for every file that
    lexically defines a function of this name. More than one defining
    file, or a def in an unsupported-language file, is a binding the
    walk cannot establish, reported ambiguous.
    """
    defs = []
    ambiguous = []
    for fpath in sorted(gitlog.grep_files(repo, name, sha)):
        if fpath == cpath:
            continue
        if shapes.is_ignored_path(fpath):
            continue
        flang = shapes.language_for_path(fpath)
        if flang is None:
            continue  # outside the four-language corpus: not evidence
        ftext = gitlog.show_file_cached(repo, sha, fpath)
        if ftext is gitlog.NOT_FOUND:
            continue
        ffuncs = shapes.find_functions(flang, ftext)
        for f in ffuncs:
            if f.kind == "func" and f.name == name:
                defs.append((fpath, ftext, flang, ffuncs, f))
    if len({d[0] for d in defs}) > 1:
        ambiguous.append(f"callee-defs:{name}")
        defs = []
    return defs, ambiguous


def _callee_guard(repo, sha, cpath, text, lines, masked, lang, funcs,
                  func, family, bound_names, before_line):
    """(covered, ambiguous), helper invoked before before_line.

    Covers the relocation where the guard moved into a shared helper the
    sink function (or a bound caller) calls on the sink path. Callees
    resolve same-file first, else by corpus def lookup; a callee name
    with a non-call live mention in the calling file (alias/dispatch
    binding) or defs in several files is a binding the walk cannot
    establish. One hop: a helper of a helper is beyond the lexical
    bound.
    """
    ambiguous = []
    seen = set()
    for j in range(func.start, min(func.end, before_line) + 1):
        if not masked[j].strip():
            continue
        names = shapes.call_names(lang, masked[j])
        if not names:
            continue
        stmt, _e = extract._complete_statement(lang, lines, masked, j)
        mstmt = shapes.mask_code(stmt, lang)
        for cname in names:
            if cname in seen:
                continue
            seen.add(cname)
            args = _call_args(mstmt, cname)
            if args is None:
                continue
            roots = _arg_names(args)
            bound_here = frozenset().union(*roots) if roots else frozenset()
            if bound_names is not None and bound_here and not (
                bound_here & bound_names
            ):
                continue  # callee not on the sink-bound path
            cands = [
                c
                for c in funcs
                if c.kind == "func"
                and c.name == cname
                and not (c.start == func.start and c.end == func.end)
            ]
            targets = [(cpath, text, lang, funcs, c) for c in cands]
            if not cands:
                # no same-file def: a non-call live mention in this file
                # means the name binds through a local alias/dispatch,
                # cannot prove where the call lands. A dispatch-
                # registration binding does not rebind the name, so it
                # is not a stray mention.
                stray = [
                    i
                    for i, ml in enumerate(masked)
                    if shapes._word_re(cname).search(ml)
                    and not shapes._call_re(cname).search(ml)
                    and not _is_import_line(lang, ml)
                ]
                if stray:
                    stray = [
                        i
                        for i in stray
                        if i not in _dispatch_binding(lang, masked, cname)
                    ]
                if stray:
                    ambiguous.append(
                        f"callee-dispatch:{cpath}:{cname}"
                    )
                    continue
                targets, amb = _callee_defs(repo, sha, cpath, cname)
                ambiguous.extend(amb)
            for tpath, ttext, tlang, tfuncs, cand in targets:
                if ttext is text:
                    tl, tm = lines, masked
                else:
                    tl = ttext.splitlines()
                    tm = [shapes.mask_code(l, tlang) for l in tl]
                params = _head_params(tl, tm, cand, cname, tlang)
                mapped = None if not roots else (
                    _mapped_params(args, params, bound_names) or None
                )
                if _family_guard(
                    tl, tm, tlang, cand, family, mapped, cand.end
                ):
                    return True, ambiguous
    return False, ambiguous


# --- sink presence ------------------------------------------------------------------


def _sink_line(lines, lang, fn, sink_op):
    """First line in fn whose catalogued sink op matches, or None."""
    for j in range(fn.start, fn.end + 1):
        if shapes.sink_op(lang, lines[j]) == sink_op:
            return j
    return None


def sink_present(repo, sha, path, sink_function, sink_op):
    """True/False provable, None unprovable: the sink at one commit.

    Present = the lineage file exists, the sink function resolves, and
    the recorded sink op still matches inside it. A missing file or
    function is provable absence (REMOVED-WITH-SINK evidence); an
    ambiguous function name is unprovable.
    """
    if path is None:
        return False
    lang = shapes.language_for_path(path)
    if lang is None:
        return None
    text = gitlog.show_file_cached(repo, sha, path)
    if text is gitlog.NOT_FOUND:
        return False
    funcs = shapes.find_functions(lang, text)
    fn = locate_function(funcs, sink_function)
    if fn is AMBIGUOUS:
        return None
    if fn is None:
        # the recorded function is gone: if the sink op still exists in
        # the file it moved or was renamed, and the lexical walk cannot
        # re-attribute it: unprovable, not proof of removal
        lines = text.splitlines()
        if any(shapes.sink_op(lang, l) == sink_op for l in lines):
            return None
        return False
    lines = text.splitlines()
    return _sink_line(lines, lang, fn, sink_op) is not None


def _sink_args(lines, masked, lang, sink_line, sink_op):
    """Root identifiers of the sink call's arguments.

    The sink call itself binds which names feed the sink; its arg roots
    are the bound set the function-scope guard must mention. Sink ops
    that are not calls (attribute writes, bare paths) or whose call text
    will not parse yield the empty set, which the caller treats as the
    weak form.
    """
    stmt, _e = extract._complete_statement(lang, lines, masked, sink_line)
    mstmt = shapes.mask_code(stmt, lang)
    op_name = sink_op[:-1] if sink_op.endswith("(") else sink_op
    args = _call_args(mstmt, op_name) if op_name else None
    if args is None:
        return []
    return sorted(frozenset().union(*_arg_names(args)))


# --- the caller corpus --------------------------------------------------------------


# Extensions that can plausibly embed one of the four corpus languages:
# Cython sources and declarations (.pyx/.pxd), type stubs (.pyi),
# single-file JS components (.vue/.svelte), a JS-source alias
# (.coffee), and notebooks with code cells (.ipynb). A grep hit in one
# of these may hide a caller the lexical walk cannot parse, so the file
# stays an ambiguity. Every other unparseable extension (docs, data,
# config, binaries) cannot hold a call site and is not evidence.
_CODE_EMBEDDING_EXTS = frozenset(
    {".pyx", ".pxd", ".pyi", ".vue", ".svelte", ".coffee", ".ipynb"}
)

# Receivers that bind a member through the enclosing class rather than a
# value type: python self/cls, tsjs this, rust self.
_SELF_RECVS = frozenset({"self", "cls", "this"})

_BRACKET_PAIR = {")": "(", "]": "[", "}": "{"}

# 'return'/'yield' whose tail so far is only receiver text: the mention
# sits in return position.
_RETURN_HEAD = re.compile(r"\b(?:return|yield)\s+[\w$.\s]*$")

_IMPORT_RES = {
    "python": re.compile(r"^\s*(?:from\s+\S+\s+)?import\b"),
    "go": re.compile(r"^\s*import\b"),
    "rust": re.compile(r"^\s*(?:pub\s+)?use\b"),
    "tsjs": re.compile(
        r"^\s*import\b|\brequire\s*\(|^\s*export\s+.*\bfrom\b"
    ),
}


def _is_import_line(lang, masked_line):
    return bool(_IMPORT_RES[lang].search(masked_line))


def _dispatch_binding(lang, masked, name):
    """Line indices spanned by dispatch-registration bindings of name.

    masked is the file's per-line string/comment-masked text. A binding
    is a call statement '<recv.><dispatch>(... <name> ...)': the callee
    matches the language's shapes._DISPATCH_RES['args'] table AND the
    balanced argument list mentions the sink basename as a word. Bare
    'name' and member forms 'self.name'/'this.name'/'@name' all reduce
    to the same word mention on masked text, so member access needs no
    separate case and no receiver check.

    The binding proves reachability (the framework dispatches to the
    sink) but never carries a guard; _find_callers records it as an
    unguarded edge instead of a live-mention ambiguity. The check is
    lexical, same-file only in the sense that it binds whatever the
    grep-matched file's 'name' resolves to: a colliding basename fed to
    an unrelated registry in another file would still resolve. That
    collision risk is accepted because _find_callers already drops
    files defining a competing same-named def, and a dispatch edge can
    only downgrade 'unprovable' to 'absent', never to 'covered'.
    """
    text = "\n".join(masked)
    word = shapes._word_re(name)
    lines = set()
    for cre in shapes._DISPATCH_RES[lang]["args"]:
        for m in cre.finditer(text):
            open_i = text.find("(", m.end() - 1)
            if open_i < 0:
                continue
            depth = 0
            close_i = -1
            for j in range(open_i, len(text)):
                if text[j] == "(":
                    depth += 1
                elif text[j] == ")":
                    depth -= 1
                    if depth == 0:
                        close_i = j
                        break
            if close_i < 0 or not word.search(text, open_i + 1, close_i):
                continue
            first = text.count("\n", 0, m.start())
            last = text.count("\n", 0, close_i)
            lines.update(range(first, last + 1))
    return lines


def _decorator_binding(lang, masked, func):
    """Line index of a dispatch decorator above func's def, or None.

    Walks the contiguous '@' lines directly above the def (blank and
    comment lines mask to empty and are skipped). A decorator whose
    callee matches the language's dispatch table registers the function
    with a framework: an unguarded caller edge like _dispatch_binding.
    The '@' context already restricts intent, so the decorator table
    matches bare names too ('@route("/x")'). go/rust have no in-scope
    decorator shape (their table entry is None).
    """
    cre = shapes._DISPATCH_RES[lang]["decorator"]
    if cre is None:
        return None
    i = func.start - 1
    while i >= 0:
        stripped = masked[i].strip()
        if not stripped:
            i -= 1
            continue
        if not stripped.startswith("@"):
            break
        if cre.match(masked[i]):
            return i
        i -= 1
    return None


def _mention_sites(mline, name):
    """(offset, receiver, is_call) for each word-mention on a masked line.

    receiver is the identifier chain left of the '.', None for a bare
    mention, or "" when the receiver is not a plain identifier chain
    ('super().name', 'a[i].name').
    """
    sites = []
    for m in shapes._word_re(name).finditer(mline):
        k = m.end()
        while k < len(mline) and mline[k] in " \t":
            k += 1
        is_call = k < len(mline) and mline[k] == "("
        j = m.start() - 1
        while j >= 0 and mline[j] in " \t":
            j -= 1
        recv = None
        if j >= 0 and mline[j] == ".":
            end, start, ok = j, j, True
            while True:
                q = start - 1
                while q >= 0 and mline[q] in " \t":
                    q -= 1
                seg_end = q + 1
                while q >= 0 and (mline[q].isalnum() or mline[q] in "_$"):
                    q -= 1
                if q + 1 == seg_end:
                    ok = False  # 'a[i].name', 'super().name'
                    break
                start = q + 1
                p = start - 1
                while p >= 0 and mline[p] in " \t":
                    p -= 1
                if p >= 0 and mline[p] == ".":
                    start = p
                    continue
                break
            recv = mline[start:end] if ok else ""
            recv = re.sub(r"\s*\.\s*", ".", recv)
        sites.append((m.start(), recv, is_call))
    return sites


def _ref_context(mtext, goff, mline, col, lang):
    """Lexical context of a non-call mention in full masked file text.

    'call': inside the argument list of a bare-identifier call
    'membercall': inside the argument list of a member-access call
    'group': inside brackets that are not a call argument list
    'return': in return/yield position
    None: a bare expression position
    """
    stack = []
    for k in range(goff):
        ch = mtext[k]
        if ch in "([{":
            stack.append((ch, k))
        elif ch in ")]}":
            if stack and stack[-1][0] == _BRACKET_PAIR[ch]:
                stack.pop()
    if stack:
        if stack[-1][0] != "(":
            return "group"
        p = stack[-1][1] - 1
        while p >= 0 and mtext[p] in " \t\n":
            p -= 1
        q = p
        while q >= 0 and (mtext[q].isalnum() or mtext[q] in "_$"):
            q -= 1
        word = mtext[q + 1 : p + 1]
        if not word:
            return "group"
        if word in shapes._KEYWORDS[lang]:
            return "return" if word in ("return", "yield") else "group"
        r = q
        while r >= 0 and mtext[r] in " \t":
            r -= 1
        return "membercall" if r >= 0 and mtext[r] == "." else "call"
    if _RETURN_HEAD.search(mline[:col]):
        return "return"
    return None


def _class_member(ffuncs, cls, name, lang):
    """Qualname of the function 'name' defined directly in cls, or None."""
    sep = "::" if lang == "rust" else "."
    want = cls.qualname + sep + name
    for f in ffuncs:
        if f.kind == "func" and f.qualname == want:
            return want
    return None


_BASE_HEAD = {
    "python": re.compile(r"\bclass\s+[A-Za-z_]\w*\s*\(([^)]*)\)"),
    "tsjs": re.compile(
        r"\bclass\s+[A-Za-z_$][\w$]*\s+extends\s+([A-Za-z_$][\w$.]*)"
    ),
}


def _class_bases(lang, decl_line):
    """Textual base names of a class declaration, basenames only."""
    cre = _BASE_HEAD.get(lang)
    if cre is None:
        return []
    m = cre.search(decl_line)
    if not m:
        return []
    out = []
    for seg in _split_top(m.group(1)):
        seg = seg.strip()
        if not seg or "=" in seg:
            continue  # metaclass= and other keyword entries
        seg = re.split(r"[<(]", seg, maxsplit=1)[0].strip()
        bm = re.search(r"([A-Za-z_$][\w$]*)\s*$", seg)
        if bm:
            out.append(bm.group(1))
    return out


def _bare_binds(ffuncs, defs, i):
    """The def of the callee name a bare call at line i resolves to.

    Scope walk: recursion first (the call sits inside a same-named def),
    then the innermost enclosing function's own defs, then each outer
    function scope, then module-level defs. A def whose direct parent is
    a container is a member ('class C: def name', 'func (r T) name',
    'fn name' inside an impl block): bare calls cannot reach it.
    """

    def parent(f):
        enc = [
            x
            for x in ffuncs
            if x is not f and x.start <= f.start and f.end <= x.end
        ]
        return max(enc, key=lambda x: x.start) if enc else None

    inside = [d for d in defs if d.start <= i <= d.end]
    if inside:
        return max(inside, key=lambda d: d.start)  # innermost binds
    bindable = []
    for d in defs:
        p = parent(d)
        if p is None:
            if d.qualname == d.name:
                bindable.append((None, d))
        elif p.kind == "func":
            bindable.append((p, d))
    scope = extract._enclosing(ffuncs, i, kind="func")
    while scope is not None:
        for p, d in bindable:
            if p is scope:
                return d
        outer = [
            f
            for f in ffuncs
            if f.kind == "func" and f.start < scope.start
            and scope.end <= f.end
        ]
        scope = max(outer, key=lambda f: f.start) if outer else None
    for p, d in bindable:
        if p is None:
            return d
    return None


def _receiver_is_owner(fmasked, recv, owner):
    """True when the file proves recv holds an OwnerClass instance.

    'recv = pkg.Owner(' or 'recv: pkg.Owner' anywhere in the masked file
    is enough: the lexical walk cannot order assignments, so any
    construction of the sink's owner type on that receiver counts.
    """
    if not owner:
        return False
    dotted = r"(?:[A-Za-z_$][\w$]*\s*\.\s*)*" + re.escape(owner)
    decl = re.compile(
        r"(?<![\w$.])" + re.escape(recv) + r"\s*=\s*" + dotted + r"\s*\("
    )
    anno = re.compile(
        r"(?<![\w$.])" + re.escape(recv) + r"\s*:\s*" + dotted + r"\b"
    )
    return any(decl.search(l) or anno.search(l) for l in fmasked)


def _find_callers(repo, sha, cpath, cfunc):
    """(callers, dispatches, ambiguous) bound to one callee at one commit.

    callers: (fpath, ftext, flines, fmasked, flang, ffuncs,
              enclosing FuncRange|None, call_line, arg_names frozenset)
    dispatches: (fpath, line) for dispatch-registration bindings and
      handoffs, a call-arg binding ('router.get("/x", handler)',
      'self.add_route("GET", self._handle)'), a dispatch decorator
      above cfunc's own def, or a function-reference handoff in
      arg/return position ('Server(self._app._handle, ...)'). Each is a
      resolvable unguarded caller edge: whoever received the reference
      invokes it without a guard the walk could credit, so it neither
      covers nor chains further.
    ambiguous: markers for every mention the walk cannot bind:
      getattr/quoted-string references, unparsable call sites,
      member calls on unproven receivers, self-mentions their enclosing
      class cannot attribute, non-dispatch live mentions, and grep
      hits in code-embedding extensions the corpus cannot parse
      (.pyx/.pyi/.vue/..., see _CODE_EMBEDDING_EXTS).

    Mention attribution: 'self.name'/'cls.name'/'this.name' binds to
    the member of its enclosing class FuncRange (or to the owner class
    member when the class lists the owner as a base). A mention that
    binds to a different class's member is not evidence; a 'self.name'
    its class cannot attribute could still reach the owner through an
    invisible base and stays ambiguous. A bare name in non-arg,
    non-return position stays ambiguous too: alias ('f = recv') and
    collection-store ('HANDLERS.append(recv)') shapes read identical
    at this lexical level and may rebind the name.
    """
    name = cfunc.name
    owner_base = None
    if cfunc.qualname != name:
        owner_base = shapes.basename(
            cfunc.qualname[: -len(name) - 1]
        )
    cand_paths = sorted(gitlog.grep_files(repo, name, sha))
    callers = []
    dispatches = []
    ambiguous = []
    call_re = shapes._call_re(name)
    word_re = shapes._word_re(name)
    quoted_re = _quoted_re(name)
    for fpath in cand_paths:
        if shapes.is_ignored_path(fpath):
            continue
        flang = shapes.language_for_path(fpath)
        if flang is None:
            dot = fpath.rfind(".")
            if dot < 0 or fpath[dot:].lower() not in _CODE_EMBEDDING_EXTS:
                continue  # docs/data/config cannot hold a call site
            ftext = gitlog.show_file_cached(repo, sha, fpath)
            if ftext is gitlog.NOT_FOUND:
                continue
            # the grep pattern is a bare substring: a hit that is not a
            # whole-word mention cannot be a caller of this callee
            if word_re.search(ftext):
                ambiguous.append(f"unsupported-ext:{fpath}")
            continue
        ftext = gitlog.show_file_cached(repo, sha, fpath)
        if ftext is gitlog.NOT_FOUND:
            continue
        flines = ftext.splitlines()
        fmasked = [shapes.mask_code(l, flang) for l in flines]
        ffuncs = shapes.find_functions(flang, ftext)
        defs_here = [f for f in ffuncs if f.name == name]
        decl_lines = {f.start for f in defs_here}
        binding_lines = _dispatch_binding(flang, fmasked, name)
        if fpath == cpath:
            dec = _decorator_binding(flang, fmasked, cfunc)
            if dec is not None:
                dispatches.append((fpath, dec))
        call_lines = set()
        mention_lines = set()
        for i, mline in enumerate(fmasked):
            if call_re.search(mline):
                call_lines.add(i)
            if word_re.search(mline):
                mention_lines.add(i)
        mtext = "\n".join(fmasked)
        line_off = [0]
        for l in fmasked:
            line_off.append(line_off[-1] + len(l) + 1)

        def _attribute(recv, i):
            """'ours'|'other'|'self-unres'|'unres' binding for a receiver."""
            if recv in _SELF_RECVS:
                cls = extract._enclosing(ffuncs, i, kind="container")
                if cls is None:
                    return "unres"  # bare identifier, not a class member
                bound = _class_member(ffuncs, cls, name, flang)
                if bound is not None:
                    if fpath == cpath and bound == cfunc.qualname:
                        return "ours"
                    return "other"
                if owner_base and owner_base in _class_bases(
                    flang, fmasked[cls.start]
                ):
                    return "ours"
                return "self-unres"
            if recv and owner_base and recv.rsplit(".", 1)[-1] == owner_base:
                return "ours"  # 'OwnerClass.name': the class itself
            return "unres"

        def _bare_caller(i, roots):
            bound = _bare_binds(ffuncs, defs_here, i)
            if fpath == cpath:
                if bound != cfunc:
                    return  # binds to another def, or to a global
            elif bound is not None:
                return  # binds to a file-local def, not the tracked one
            enc = extract._enclosing(ffuncs, i, kind="func")
            callers.append(
                (fpath, ftext, flines, fmasked, flang, ffuncs, enc, i,
                 roots)
            )

        def _member_caller(i, mstmt, parenless=False):
            args = _call_args(mstmt, name, member=True)
            if args is None and parenless:
                args = ""  # '@recv.name' invokes it on the decorated def
            if args is None:
                ambiguous.append(f"call-unbound:{fpath}:{i + 1}")
                return
            roots = frozenset().union(*_arg_names(args))
            enc = extract._enclosing(ffuncs, i, kind="func")
            callers.append(
                (fpath, ftext, flines, fmasked, flang, ffuncs, enc, i,
                 roots)
            )

        for i in sorted(mention_lines - decl_lines):
            mline = fmasked[i]
            if _is_import_line(flang, mline):
                continue
            if fpath == cpath and cfunc.start <= i <= cfunc.end:
                continue  # inside the callee itself
            if i in binding_lines:
                dispatches.append((fpath, i))
                continue  # a resolved unguarded edge, not an ambiguity
            on_dec = mline.lstrip().startswith("@")
            stmt, _e = extract._complete_statement(
                flang, flines, fmasked, i
            )
            mstmt = shapes.mask_code(stmt, flang)
            for off, recv, is_call in _mention_sites(mline, name):
                parenless = on_dec and not is_call
                if on_dec:
                    # a decorator line invokes the decorated def through
                    # the name: '@name' / '@recv.name' are call sites
                    is_call = True
                if recv is None and is_call:
                    if parenless:
                        _bare_caller(i, frozenset())
                    continue  # bare calls: the caller pass below owns them
                if is_call:
                    attr = _attribute(recv, i)
                    if attr == "other":
                        continue
                    if attr == "ours" or (
                        recv
                        and _receiver_is_owner(fmasked, recv, owner_base)
                    ):
                        _member_caller(i, mstmt, parenless)
                        continue
                    ambiguous.append(f"member-call:{fpath}:{i + 1}")
                    continue
                if recv is None:
                    ctx = _ref_context(
                        mtext, line_off[i] + off, mline, off, flang
                    )
                    if ctx in ("return", "call"):
                        dispatches.append((fpath, i))
                    else:
                        ambiguous.append(f"live-mention:{fpath}:{i + 1}")
                    continue
                attr = _attribute(recv, i)
                if attr == "other":
                    continue
                if attr == "self-unres":
                    # self.name the enclosing class cannot attribute may
                    # still reach the owner through an invisible base
                    ambiguous.append(f"live-mention:{fpath}:{i + 1}")
                    continue
                # ours or unresolvable non-self: a reference handoff is
                # an unguarded edge whichever member it turns out to be
                ctx = _ref_context(
                    mtext, line_off[i] + off, mline, off, flang
                )
                if ctx in ("return", "call", "membercall"):
                    dispatches.append((fpath, i))
                # any other position is not an invocation: not evidence
        if quoted_re.search(ftext):
            ambiguous.append(f"dynamic-ref:{fpath}")
        for i in sorted(call_lines - decl_lines):
            if fpath == cpath and cfunc.start <= i <= cfunc.end:
                continue  # recursion adds no new entry path
            stmt, _e = extract._complete_statement(
                flang, flines, fmasked, i
            )
            args = _call_args(shapes.mask_code(stmt, flang), name)
            if args is None:
                ambiguous.append(f"call-unbound:{fpath}:{i + 1}")
                continue
            roots = frozenset().union(*_arg_names(args))
            _bare_caller(i, roots)
    return callers, dispatches, ambiguous


# --- the bounded walk ---------------------------------------------------------------


def family_coverage(repo, sha, path, sink_function, sink_op, family, depth):
    """Coverage of the guard family on the sink path at one commit.

    Function scope first (the function's own text, then the helpers it
    calls before the sink), then callers bounded to ``depth``. Answers
    covered / absent / unprovable, never guessed.
    """
    lang = shapes.language_for_path(path)
    if lang is None:
        return Coverage(UNPROVABLE, ("unsupported-lang",))
    text = gitlog.show_file_cached(repo, sha, path)
    if text is gitlog.NOT_FOUND:
        return Coverage(UNPROVABLE, ("sink-file-absent",))
    funcs = shapes.find_functions(lang, text)
    fn = locate_function(funcs, sink_function)
    if fn is AMBIGUOUS:
        return Coverage(UNPROVABLE, ("sink-function-ambiguous",))
    if fn is None:
        return Coverage(UNPROVABLE, ("sink-function-absent",))
    lines = text.splitlines()
    masked = [shapes.mask_code(l, lang) for l in lines]
    sink_line = _sink_line(lines, lang, fn, sink_op)
    if sink_line is None:
        return Coverage(ABSENT, ("no-sink-op",))
    bound = _sink_args(lines, masked, lang, sink_line, sink_op)
    bound = frozenset(bound) if bound else None
    ambiguous = []
    if _family_guard(lines, masked, lang, fn, family, bound, sink_line):
        return Coverage(COVERED, ("function-scope",))
    covered, amb = _callee_guard(
        repo, sha, path, text, lines, masked, lang, funcs, fn, family,
        bound, sink_line,
    )
    ambiguous.extend(amb)
    if covered:
        return Coverage(COVERED, ("callee-scope",))
    if depth <= 0:
        # a zero bound still has to count the callers it cannot walk:
        # any found caller is a scope the bound never examined, which
        # is unprovable, never absent. Dispatch bindings are already
        # resolved edges (unguarded, terminal), so they count toward
        # neither the callers nor the ambiguities.
        found, disp, amb = _find_callers(repo, sha, path, fn)
        ambiguous.extend(amb)
        if found:
            ambiguous.append("depth-bound:callers")
        if ambiguous:
            return Coverage(UNPROVABLE, tuple(sorted(set(ambiguous))))
        marks = sorted({f"dispatch:{p}:{i + 1}" for p, i in disp})
        return Coverage(
            ABSENT, ("function-scope", "depth-bound", *marks)
        )
    frontier = [(path, fn)]
    visited = {(path, fn.qualname)}
    dispatch_marks = []
    for _lvl in range(depth):
        nxt = []
        for cpath, cfunc in frontier:
            found, disp, amb = _find_callers(repo, sha, cpath, cfunc)
            ambiguous.extend(amb)
            dispatch_marks.extend(
                f"dispatch:{p}:{i + 1}" for p, i in disp
            )
            for (fpath, ftext, flines, fmasked, flang, ffuncs, enc,
                 call_line, roots) in found:
                bound2 = roots if roots else None
                if enc is None:
                    if _module_guard(
                        flines, fmasked, flang, ffuncs, family, bound2,
                        call_line,
                    ):
                        return Coverage(
                            COVERED, (f"module-scope:{fpath}",)
                        )
                    continue  # unguarded module entry: resolvable, no chain
                if _family_guard(
                    flines, fmasked, flang, enc, family, bound2, call_line
                ):
                    return Coverage(
                        COVERED, (f"caller:{fpath}:{enc.qualname}",)
                    )
                covered, amb = _callee_guard(
                    repo, sha, fpath, ftext, flines, fmasked, flang,
                    ffuncs, enc, family, bound2, call_line,
                )
                ambiguous.extend(amb)
                if covered:
                    return Coverage(
                        COVERED,
                        (f"caller-callee:{fpath}:{enc.qualname}",),
                    )
                key = (fpath, enc.qualname)
                if key not in visited:
                    visited.add(key)
                    nxt.append((fpath, enc))
        frontier = nxt
        if not frontier:
            break
    if ambiguous:
        return Coverage(UNPROVABLE, tuple(sorted(set(ambiguous))))
    return Coverage(
        ABSENT,
        ("caller-chain-exhausted",)
        + tuple(sorted(set(dispatch_marks))),
    )


# --- locating a recorded sink op --------------------------------------------------


def locate_sink_line(text, path, sink_function, sink_op):
    """0-based line index of the recorded sink op in text, or None.

    Scoped search first: the op must match inside the recorded sink
    function's FuncRange on masked lines, so a lookalike substring in a
    comment, a string, or another function cannot anchor it. Falls back
    to a whole-file masked-op match, then a raw substring match.
    """
    if text is None:
        return None
    lines = text.splitlines()
    lang = shapes.language_for_path(path)
    if lang is not None:
        funcs = shapes.find_functions(lang, text)
        fn = locate_function(funcs, sink_function)
        if fn is not None and fn is not AMBIGUOUS:
            j = _sink_line(lines, lang, fn, sink_op)
            if j is not None:
                return j
        for i, l in enumerate(lines):
            if shapes.sink_op(lang, l) == sink_op:
                return i
    for i, l in enumerate(lines):
        if sink_op in l:
            return i
    return None
