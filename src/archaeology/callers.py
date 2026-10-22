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
  hide a guard), so exported sinks can still reach REGRESSED.
- ``unprovable``: any ambiguity, a dispatch/getattr reference, a
  shadowed local def, an unparseable call site, an unreadable
  candidate. Cannot prove always degrades to UNKNOWN, never REGRESSED.
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


def _call_args(masked_text, name):
    """Argument-list text of the first name(...) call, or None.

    The text must be string/comment-masked so parens inside literals do
    not unbalance the scan.
    """
    m = shapes._call_re(name).search(masked_text)
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
        flang = shapes.language_for_path(fpath)
        if flang is None:
            continue  # outside the four-language corpus: not evidence
        ftext = gitlog.show_file(repo, sha, fpath)
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
                # cannot prove where the call lands
                stray = [
                    i
                    for i, ml in enumerate(masked)
                    if shapes._word_re(cname).search(ml)
                    and not shapes._call_re(cname).search(ml)
                    and not _is_import_line(lang, ml)
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
    text = gitlog.show_file(repo, sha, path)
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


def _find_callers(repo, sha, cpath, cfunc):
    """(callers, ambiguous) bound to one callee at one commit.

    callers: (fpath, ftext, flines, fmasked, flang, ffuncs,
              enclosing FuncRange|None, call_line, arg_names frozenset)
    ambiguous: markers for every mention the walk cannot bind,
    getattr/dispatch references, shadowed local defs, unparsable call
    sites. A grep-matching file in an unsupported extension (.vue,
    .svelte, .pyx) may hold a caller the corpus cannot examine, so it is
    an ambiguity that degrades coverage to unprovable, never a silent
    skip.
    """
    name = cfunc.name
    cand_paths = sorted(gitlog.grep_files(repo, name, sha))
    callers = []
    ambiguous = []
    call_re = shapes._call_re(name)
    word_re = shapes._word_re(name)
    quoted_re = _quoted_re(name)
    for fpath in cand_paths:
        flang = shapes.language_for_path(fpath)
        if flang is None:
            ambiguous.append(f"unsupported-ext:{fpath}")
            continue
        ftext = gitlog.show_file(repo, sha, fpath)
        if ftext is gitlog.NOT_FOUND:
            continue
        flines = ftext.splitlines()
        fmasked = [shapes.mask_code(l, flang) for l in flines]
        ffuncs = shapes.find_functions(flang, ftext)
        defs_here = [f for f in ffuncs if f.name == name]
        if fpath != cpath and defs_here:
            # the file defines its own same-named function: bare calls
            # inside it bind locally, not to the tracked callee
            continue
        if len(defs_here) > 1:
            ambiguous.append(f"shadowed-def:{fpath}")
            continue
        decl_lines = {f.start for f in defs_here}
        call_lines = set()
        mention_lines = set()
        for i, mline in enumerate(fmasked):
            if call_re.search(mline):
                call_lines.add(i)
            if word_re.search(mline):
                mention_lines.add(i)
        for i in sorted(mention_lines - call_lines - decl_lines):
            if _is_import_line(flang, fmasked[i]):
                continue
            if fpath == cpath and cfunc.start <= i <= cfunc.end:
                continue  # inside the callee itself
            ambiguous.append(f"live-mention:{fpath}:{i + 1}")
        if quoted_re.search(ftext):
            ambiguous.append(f"dynamic-ref:{fpath}")
        for i in sorted(call_lines):
            if fpath == cpath and cfunc.start <= i <= cfunc.end:
                continue  # recursion adds no new entry path
            enc = extract._enclosing(ffuncs, i, kind="func")
            stmt, _e = extract._complete_statement(
                flang, flines, fmasked, i
            )
            args = _call_args(shapes.mask_code(stmt, flang), name)
            if args is None:
                ambiguous.append(f"call-unbound:{fpath}:{i + 1}")
                continue
            roots = frozenset().union(*_arg_names(args))
            callers.append(
                (fpath, ftext, flines, fmasked, flang, ffuncs, enc, i,
                 roots)
            )
    return callers, ambiguous


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
    text = gitlog.show_file(repo, sha, path)
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
        # is unprovable, never absent
        found, amb = _find_callers(repo, sha, path, fn)
        ambiguous.extend(amb)
        if found:
            ambiguous.append("depth-bound:callers")
        if ambiguous:
            return Coverage(UNPROVABLE, tuple(sorted(set(ambiguous))))
        return Coverage(ABSENT, ("function-scope", "depth-bound"))
    frontier = [(path, fn)]
    visited = {(path, fn.qualname)}
    for _lvl in range(depth):
        nxt = []
        for cpath, cfunc in frontier:
            found, amb = _find_callers(repo, sha, cpath, cfunc)
            ambiguous.extend(amb)
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
    return Coverage(ABSENT, ("caller-chain-exhausted",))


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
