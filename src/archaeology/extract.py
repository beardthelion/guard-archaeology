"""Guard extraction: seed-commit diffs -> guard records (R3, R4, R5).

Per seed commit the patch is parsed into per-file added lines (reusing
gitlog.show_patch/parse_patch_text); the file is materialized at the seed
commit so statements can be completed and the enclosing function found
lexically. A statement becomes a guard record only when a catalogued sink
is reachable in the same function's text after the guard, in an immediate
callee defined in the same file, or in an immediate same-file caller after
its call site. Anything else is dropped and counted as an extraction skip:
precision over recall is a spec mandate (R5).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from . import gitlog, shapes


@dataclass(frozen=True)
class GuardRecord:
    """One extracted guard (R4).

    ``signature`` is the KTD9 normalized statement; ``signature_anchor`` is
    the normalized skeleton of its first raw line, which is what KTD3's
    ``signature_regex`` compiles for pickaxe candidacy. ``raw_text`` is the
    verbatim added guard text (KTD3's candidacy input).
    """

    family: str  # SPEC.md Definitions vocabulary
    shape: str  # conditional-rejection | validation-call | constant-limit
    signature: str
    signature_anchor: str
    raw_text: str
    path: str  # file the guard was added in
    guard_line: int  # 1-based line of the guard head at the seed commit
    sink_path: str
    sink_function: str  # lexical qualname (Class.method, Type::method)
    sink_line: int  # 1-based line of the sink op at the seed commit
    sink_op: str  # matched sink operation text
    seed_sha: str
    advisory_id: str | None


@dataclass(frozen=True)
class Extraction:
    """Result of extracting a whole seed set."""

    records: tuple  # GuardRecord, in seed/patch/line order
    skipped: int  # total statements/patches dropped
    skip_reasons: dict  # reason -> count: unclassified, no-sink, ...
    errors: tuple  # per-seed/per-file failures for R13 error rows


_SKIP_REASONS = ("unclassified", "no-sink", "unsupported", "unreadable")

_CONTINUATION_TAIL = re.compile(r"(,|\\|&&|\|\||\?|:|=|\||&|\^|\.)\s*$")
_CONTROL_HEAD = re.compile(
    r"^\s*(?:if|else\s+if|else|for|while|catch|switch|do)\b"
)
_CONST_BLOCK_HEAD = re.compile(r"^\s*(?:const|var)\s*\(\s*$")

# Lines where a declared name counts as consulted: the name must appear
# next to a comparison, a control keyword, a membership, or a call.
_CONSULT_CUES = re.compile(
    r"(==|!=|<=|>=|<|>|\bin\b|\bnot\b|\bif\b|\bfor\b|\bwhile\b|\()"
)


def _paren_delta(masked):
    return (
        masked.count("(") - masked.count(")")
        + masked.count("[") - masked.count("]")
        + masked.count("{") - masked.count("}")
    )


def _complete_python(lines, masked, i):
    """Statement starting at line i plus its body/continuation lines."""
    head = masked[i].rstrip()
    indent = len(masked[i]) - len(masked[i].lstrip())
    depth = _paren_delta(head)
    parts = [lines[i]]
    j = i
    if head.endswith(":") and depth <= 0:
        while j + 1 < len(lines):
            nxt = masked[j + 1]
            if not nxt.strip():
                parts.append(lines[j + 1])
                j += 1
                continue
            ind = len(nxt) - len(nxt.lstrip())
            if ind <= indent:
                break
            parts.append(lines[j + 1])
            j += 1
        return "\n".join(parts), j
    while (depth > 0 or head.endswith("\\")) and j + 1 < len(lines):
        j += 1
        parts.append(lines[j])
        head = masked[j].rstrip()
        depth += _paren_delta(head)
    return "\n".join(parts), j


def _complete_brace(lines, masked, i):
    """Statement starting at line i, joined across its bracket extent."""
    parts = [lines[i]]
    j = i
    curly = 0
    other = 0
    while True:
        m = masked[j]
        curly += m.count("{") - m.count("}")
        other += m.count("(") - m.count(")")
        other += m.count("[") - m.count("]")
        if curly <= 0 and other <= 0:
            strip = m.strip()
            head = masked[i].strip()
            if _CONTINUATION_TAIL.search(strip):
                pass
            elif j == i and _CONTROL_HEAD.match(head) and not strip.endswith(
                (";", "{", "}")
            ):
                pass  # 'if (x)' whose brace/body starts on the next line
            else:
                break
        if j - i >= 50 or j + 1 >= len(lines):
            break
        j += 1
        parts.append(lines[j])
    return "\n".join(parts), j


def _complete_statement(lang, lines, masked, i):
    if lang == "python":
        return _complete_python(lines, masked, i)
    return _complete_brace(lines, masked, i)


def _const_blocks(lang, masked):
    """(start, end) line ranges of Go const (...)/var (...) blocks."""
    if lang != "go":
        return []
    ranges = []
    open_i = None
    for i, m in enumerate(masked):
        if _CONST_BLOCK_HEAD.match(m):
            open_i = i
        elif open_i is not None and m.lstrip().startswith(")"):
            ranges.append((open_i, i))
            open_i = None
    if open_i is not None:
        ranges.append((open_i, len(masked)))
    return ranges


def _enclosing(funcs, i, kind=None):
    """Innermost FuncRange containing line i, or None.

    ``kind`` restricts the match (e.g. "func" skips container ranges);
    None keeps any kind eligible.
    """
    best = None
    for f in funcs:
        if kind is not None and f.kind != kind:
            continue
        if f.start <= i <= f.end and (
            best is None or f.start > best.start
        ):
            best = f
    return best


def _call_names_in(lines, lang, a, b):
    """Callee basenames invoked on lines a..b, in order, deduplicated."""
    seen = set()
    out = []
    for j in range(a, min(b, len(lines) - 1) + 1):
        for name in shapes.call_names(lang, lines[j]):
            if name not in seen:
                seen.add(name)
                out.append(name)
    return out


def _call_site(lines, lang, cand, name):
    """First line inside cand where `name` is invoked as a bare callee."""
    cre = shapes._call_re(name)
    for j in range(cand.start, cand.end + 1):
        masked = shapes.mask_code(lines[j], lang)
        if cre.search(masked):
            return j
    return None


def _find_sink(lines, lang, funcs, func, guard_end):
    """(qualname, line, op) for the guard's sink, or None.

    Order: the enclosing function's text after the guard statement, then
    functions it calls (same-file callees), then same-file callers after
    their call site of the guard's function.
    """
    for j in range(guard_end + 1, func.end + 1):
        op = shapes.sink_op(lang, lines[j])
        if op:
            return (func.qualname, j + 1, op)
    for cname in _call_names_in(lines, lang, guard_end + 1, func.end):
        for cand in funcs:
            if cand.kind != "func" or cand.start == func.start:
                continue
            if cand.name != cname:
                continue
            for j in range(cand.start, cand.end + 1):
                op = shapes.sink_op(lang, lines[j])
                if op:
                    return (cand.qualname, j + 1, op)
    for cand in funcs:
        if cand.kind != "func" or cand.start == func.start:
            continue
        site = _call_site(lines, lang, cand, func.name)
        if site is None:
            continue
        for j in range(site + 1, cand.end + 1):
            op = shapes.sink_op(lang, lines[j])
            if op:
                return (cand.qualname, j + 1, op)
    return None


def _find_constant_sink(lines, lang, funcs, name, decl_line, decl_func):
    """(qualname, line, op) where `name` is consulted before a sink.

    A function-local constant must be consulted in its own function after
    the declaration; a module-level one may be consulted in any function.
    The consult line must carry a guard cue (comparison, control keyword,
    membership, or call).
    """
    name_re = shapes._word_re(name)
    cands = [decl_func] if decl_func is not None else list(funcs)
    for f in sorted(cands, key=lambda f: f.start):
        first_sink = None
        for j in range(f.start, f.end + 1):
            op = shapes.sink_op(lang, lines[j])
            if op:
                first_sink = (j, op)
                break
        if first_sink is None:
            continue
        lo = max(f.start, decl_line + 1) if decl_func is not None else f.start
        for j in range(lo, first_sink[0]):
            masked = shapes.mask_code(lines[j], lang)
            if name_re.search(masked) and _CONSULT_CUES.search(masked):
                return (f.qualname, first_sink[0] + 1, first_sink[1])
    return None


def extract_file(lang, path, text, added_linenos, seed_sha="", advisory_id=None):
    """(records, skip_reasons) for one file's content at the seed commit.

    ``added_linenos`` are 1-based new-file line numbers from the FilePatch.
    Statements are completed from the file text so an added ``if`` head
    wrapping existing code still resolves its body.
    """
    lines = text.splitlines()
    masked = [shapes.mask_code(l, lang) for l in lines]
    funcs = shapes.find_functions(lang, text)
    const_ranges = _const_blocks(lang, masked)
    consumed = set()
    records = []
    skips = {"unclassified": 0, "no-sink": 0}
    for ln in sorted(added_linenos):
        i = ln - 1
        if i < 0 or i >= len(lines) or i in consumed:
            continue
        if not masked[i].strip():
            continue  # blank or comment-only added line
        stmt_text, end = _complete_statement(lang, lines, masked, i)
        if re.match(r"\s*if\b", masked[i]):
            # swallow the guard's block so its reject-body lines are not
            # reprocessed; other heads keep their inner lines live (a func
            # decl must not consume the statements inside its body)
            consumed.update(range(i, end + 1))
        const_ctx = any(s <= i < e for s, e in const_ranges)
        cls = shapes.classify_statement(lang, stmt_text, const_ctx=const_ctx)
        if cls is None:
            skips["unclassified"] += 1
            continue
        shape, family, meta = cls
        signature = shapes.normalize_statement(lang, stmt_text)
        if signature is None:
            skips["unclassified"] += 1
            continue
        if shape == "constant-limit":
            decl_func = _enclosing(funcs, i)
            sink = _find_constant_sink(
                lines, lang, funcs, meta["name"], i, decl_func
            )
        else:
            func = _enclosing(funcs, i)
            sink = None
            if func is not None:
                sink = _find_sink(lines, lang, funcs, func, end)
        if sink is None:
            skips["no-sink"] += 1
            continue
        consumed.update(range(i, end + 1))
        sink_func, sink_line, sink_op = sink
        records.append(
            GuardRecord(
                family=family,
                shape=shape,
                signature=signature,
                signature_anchor=(
                    shapes.normalize_statement(lang, lines[i]) or signature
                ),
                raw_text=stmt_text,
                path=path,
                guard_line=ln,
                sink_path=path,
                sink_function=sink_func,
                sink_line=sink_line,
                sink_op=sink_op,
                seed_sha=seed_sha,
                advisory_id=advisory_id,
            )
        )
    return records, skips


def extract_guards(repo, seed_set):
    """Guard records for every seed in the set (R3, R4).

    Per-seed/per-file failures are recorded in ``errors`` for the R13
    error rows and never abort the run.
    """
    records = []
    reasons = {k: 0 for k in _SKIP_REASONS}
    errors = []
    for seed in seed_set.seeds:
        try:
            patches = gitlog.show_patch(repo, seed.sha)
        except gitlog.GitError as e:
            errors.append(
                {"stage": "extract", "seed": seed.sha, "reason": str(e)}
            )
            continue
        for fp in patches:
            if fp.is_binary or fp.is_delete or not fp.added:
                continue
            lang = shapes.language_for_path(fp.new_path)
            if lang is None or fp.new_path is None:
                reasons["unsupported"] += 1
                continue
            content = gitlog.show_file(repo, seed.sha, fp.new_path)
            if content is gitlog.NOT_FOUND:
                reasons["unreadable"] += 1
                errors.append(
                    {
                        "stage": "extract",
                        "seed": seed.sha,
                        "path": fp.new_path,
                        "reason": "path absent at seed commit",
                    }
                )
                continue
            recs, skips = extract_file(
                lang,
                fp.new_path,
                content,
                [n for n, _t in fp.added],
                seed_sha=seed.sha,
                advisory_id=seed.advisory_id,
            )
            records.extend(recs)
            for k, v in skips.items():
                reasons[k] += v
    return Extraction(
        records=tuple(records),
        skipped=sum(reasons.values()),
        skip_reasons={k: v for k, v in reasons.items() if v},
        errors=tuple(errors),
    )
