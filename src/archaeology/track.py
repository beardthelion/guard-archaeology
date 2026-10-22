"""Forward tracking: pickaxe candidacy over the rename lineage, then
verdict by file materialization (R6, R7, KTD3).

Per guard record the tracker builds the file's path lineage forward from
the seed path to the boundary (HEAD or --until), runs
'git log --full-history -G<regex>' over the lineage pathspecs where the
regex is compiled from the signature anchor (KTD3: candidacy never
queries the token-abstracted signature), then verifies each hit by
materializing the file at the commit and its parents and re-normalizing
the guard statements present. A hit whose file still carries the
signature is a cleared candidacy (reflow, rename, in-function move) and
is recorded as a mutation event; scanning resumes at the next hit. The
candidate removal is the first commit with verified absence, never the
first pickaxe count-drop.

Outcome statuses consumed downstream:

- ``intact``: the signature is present in the boundary file.
- ``candidate``: a commit with verified absence; classify decides.
- ``deleted``: the lineage's last hop is a deletion; classify routes it
  as REMOVED-WITH-SINK evidence rather than UNKNOWN.
- ``severed``: the file's identity was reset inside the window
  (delete-recreate, rename-in, a delete superseded at the boundary);
  classify routes it as lost lineage (UNKNOWN).
- ``unverifiable``: the signature is absent at the boundary with no hit
  to explain it, the boundary file cannot be found, or a git call
  failed; classify routes it as UNKNOWN.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import callers, extract, gitlog, shapes


@dataclass(frozen=True)
class MutationEvent:
    """A pickaxe hit that verified the guard still present (cleared
    candidacy: reflow, identifier rename, in-function move)."""

    sha: str
    kind: str = "mutation"


@dataclass(frozen=True)
class LineageBreak:
    """Where the tracked file's identity ended inside the window.

    kind: ``delete`` (terminal deletion, REMOVED-WITH-SINK evidence),
    ``delete-recreate`` or ``rename-reset`` or ``delete-superseded``
    (identity reset, lost-lineage evidence).
    """

    kind: str
    sha: str
    path: str


@dataclass(frozen=True)
class TrackOutcome:
    """Per-guard tracking result (the track state record of U4)."""

    guard: extract.GuardRecord
    status: str  # intact | candidate | deleted | severed | unverifiable
    path_chain: tuple  # file names, seed path first, boundary name last
    renames: tuple  # ((sha, old, new), ...) in forward order
    boundary_sha: str
    boundary_path: str | None
    boundary_present: bool
    boundary_excerpt: str | None
    add_confirmed: bool  # signature verified in the file at the seed
    candidate_sha: str | None  # first commit with verified absence
    removal_parent_sha: str | None  # parent where presence last held
    mutation_events: tuple  # MutationEvent, oldest hit first
    lineage_break: LineageBreak | None
    markers: tuple  # extra machine markers for classify/emit


@dataclass(frozen=True)
class Tracking:
    outcomes: tuple
    errors: tuple  # per-guard failures for R13 error rows


# --- presence checking ---------------------------------------------------------


def _guard_scope(lang, text, rec):
    """Line range the signature must be found in, or None for whole file.

    Presence is scoped to the recorded guard function's FuncRange so a
    same-signature guard living in a different function cannot keep a
    removed guard INTACT. The recorded qualname matches first, then a
    unique basename; a function that cannot be located (renamed, moved)
    falls back to the whole file.
    """
    funcs = shapes.find_functions(lang, text)
    name = rec.guard_function
    if name:
        exact = [f for f in funcs if f.qualname == name]
        if exact:
            return exact[0].start, exact[0].end
        base = shapes.basename(name)
        matches = [f for f in funcs if f.kind == "func" and f.name == base]
        if len(matches) == 1:
            return matches[0].start, matches[0].end
        if len(matches) > 1:
            return None
    return None


def _decl_name_of(lang, stmt):
    """Bound name when the statement is a literal constant decl."""
    masked = shapes.mask_code(stmt, lang)
    toks = shapes._lex(stmt, lang)
    if not toks:
        return None
    decl = shapes._constant_decl(
        lang, masked, toks, const_ctx=(lang == "go")
    )
    return decl[0] if decl else None


def _signature_present(lang, text, rec):
    """True when the guard's signature holds in its recorded scope.

    Statement completion reuses the extractor's segmentation so a
    signature only counts as present under the same segmentation it was
    extracted with; whitespace and line joins still collapse (KTD1).
    A constant-limit record also binds its declared name: ``ID=NUM``
    matches every numeric assignment in scope, so only a decl of
    ``rec.decl_name`` counts.
    """
    lines = text.splitlines()
    masked = [shapes.mask_code(l, lang) for l in lines]
    scope = _guard_scope(lang, text, rec)
    lo, hi = scope if scope else (0, len(lines) - 1)
    for i in range(lo, hi + 1):
        if not masked[i].strip():
            continue
        stmt, _end = extract._complete_statement(lang, lines, masked, i)
        if shapes.normalize_statement(lang, stmt) != rec.signature:
            continue
        if rec.decl_name is not None and (
            _decl_name_of(lang, stmt) != rec.decl_name
        ):
            continue
        return True
    return False


# --- lineage ---------------------------------------------------------------------


def _forward_lineage(repo, rec, boundary):
    """(chain, renames, break) walked forward from the seed path.

    For each name, the newest decisive record (A or D) in its path-limited
    log decides its fate. A decisive event that is an ancestor of the
    span's bound commit means the bound touch lies inside the boundary
    file's identity span: the lineage is continuous and the walk ends.
    A post-bound decisive event is disambiguated with 'git show -M' on
    the whole commit (a path-limited log shows a rename away as D and a
    rename in as A): a rename out extends the chain, a plain delete ends
    it terminally, and an add or rename-in is an identity reset.
    """
    chain = [rec.path]
    renames = []
    brk = None
    current = rec.path
    bound = rec.seed_sha
    while True:
        entries = gitlog.path_events(repo, current, boundary)
        decisive = next(
            (e for e in entries if e[1] in ("A", "D", "R")), None
        )
        if decisive is None:
            break  # the name's whole window is touches: continuous
        if gitlog.is_ancestor(repo, decisive[0], bound):
            break  # bound lies inside the current identity span
        records = [
            r
            for r in gitlog.name_status(repo, decisive[0])
            if r[1] == current or r[2] == current
        ]
        rout = [r for r in records if r[0] == "R" and r[1] == current]
        rin = [r for r in records if r[0] == "R" and r[2] == current]
        dels = [r for r in records if r[0] == "D" and r[1] == current]
        if rout:
            new = rout[0][2]
            renames.append((decisive[0], current, new))
            chain.append(new)
            current = new
            bound = decisive[0]
            continue
        if rin:
            brk = LineageBreak("rename-reset", decisive[0], current)
        elif dels:
            gone = (
                gitlog.show_file_cached(repo, boundary, current)
                is gitlog.NOT_FOUND
            )
            # a delete whose name still resolves at the boundary was
            # superseded (e.g. a merged-out deletion), not terminal
            kind = "delete" if gone else "delete-superseded"
            brk = LineageBreak(kind, decisive[0], current)
        else:
            brk = LineageBreak("delete-recreate", decisive[0], current)
        break
    return chain, renames, brk


def _path_at(renames, rec_path, repo, sha):
    """Lineage name in force at sha (newest rename it descends from)."""
    active = rec_path
    for rsha, _old, new in renames:
        if gitlog.is_ancestor(repo, rsha, sha):
            active = new
    return active


def _excerpt(text, path, sink_function, needle):
    """A few lines around the sink op, or None.

    The op is located inside the recorded sink function's FuncRange on
    masked lines first, so a matching substring in a comment or string
    cannot anchor the excerpt; whole-file masked and raw substring
    matching are the ordered fallbacks.
    """
    if text is None:
        return None
    i = callers.locate_sink_line(text, path, sink_function, needle)
    if i is None:
        return None
    lines = text.splitlines()
    lo = max(0, i - 3)
    return "\n".join(lines[lo : i + 4])


def _outcome(rec, boundary, status, chain, renames, brk, markers,
             mutations, candidate, parent_sha, boundary_name,
             boundary_present, excerpt, add_confirmed):
    return TrackOutcome(
        guard=rec,
        status=status,
        path_chain=tuple(chain),
        renames=tuple(renames),
        boundary_sha=boundary,
        boundary_path=boundary_name,
        boundary_present=boundary_present,
        boundary_excerpt=excerpt,
        add_confirmed=add_confirmed,
        candidate_sha=candidate,
        removal_parent_sha=parent_sha,
        mutation_events=tuple(mutations),
        lineage_break=brk,
        markers=tuple(markers),
    )


def track_guard(repo, rec, boundary):
    """One guard record -> TrackOutcome (R6, R7)."""
    lang = shapes.language_for_path(rec.path)
    if lang is None:
        # extraction only emits supported paths; this is defensive
        return _outcome(
            rec, boundary, "unverifiable", (rec.path,), (), None,
            ["unsupported-lang"], (), None, None, None, False, None,
            False,
        )
    chain, renames, brk = _forward_lineage(repo, rec, boundary)
    markers = []
    mutations = []

    cache = {}

    def present_at(sha):
        """(name, present, text); name None when absent under all names."""
        pref = _path_at(renames, rec.path, repo, sha)
        order = [pref] + [n for n in chain if n != pref]
        for name in order:
            key = (sha, name)
            if key not in cache:
                # the shared blob cache dedups this read across guards
                cache[key] = gitlog.show_file_cached(repo, sha, name)
            text = cache[key]
            if text is gitlog.NOT_FOUND:
                continue
            return name, _signature_present(lang, text, rec), text
        return None, False, None

    # add-commit confirmation: the guard must verify at its own seed
    _aname, add_present, _at = present_at(rec.seed_sha)
    add_confirmed = bool(add_present)
    if not add_confirmed:
        markers.append("seed-unconfirmed")

    candidate = None
    parent_sha = None
    regex = shapes.signature_regex(rec.signature_anchor)
    hits = gitlog.pickaxe(
        repo, regex, paths=chain, until=boundary, since=rec.seed_sha,
        topo=True,
    )
    for h in reversed(hits):  # ancestors before descendants
        if brk is not None and gitlog.is_ancestor(repo, brk.sha, h):
            break  # hits on the reset file prove nothing about ours
        name, present, _t = present_at(h)
        if name is None:
            continue  # file absent at hit: lineage event, not R7's
        if present:
            mutations.append(MutationEvent(sha=h))
            continue
        parents = gitlog.commit(repo, h).parents
        confirmed = False
        for p in parents:
            pname, ppresent, _pt = present_at(p)
            if pname is not None and ppresent:
                parent_sha = p
                confirmed = True
                break
        if confirmed:
            candidate = h
            break
        # guard absent before the hit too: side-branch noise, skip

    bname, bpresent, btext = present_at(boundary)
    boundary_present = bname is not None
    excerpt = (
        _excerpt(btext, bname, rec.sink_function, rec.sink_op)
        if btext
        else None
    )

    if brk is not None and brk.kind != "delete":
        # a non-delete identity reset (delete-recreate, rename-reset,
        # delete-superseded) severs lineage even when a verified removal
        # candidate was found earlier in the window: the candidate was
        # proven against a file identity that no longer exists
        status = "severed"
    elif candidate is not None:
        status = "candidate"
    elif brk is not None:
        status = "deleted"
    elif not boundary_present:
        markers.append("boundary-missing")
        status = "unverifiable"
    elif bpresent:
        status = "intact"
    else:
        markers.append("absent-unverified")
        status = "unverifiable"

    return _outcome(
        rec, boundary, status, chain, renames, brk, markers, mutations,
        candidate, parent_sha, bname if boundary_present else None,
        boundary_present, excerpt, add_confirmed,
    )


def track_guards(repo, records, until=None):
    """Track every guard record to the boundary; returns a Tracking.

    ``boundary`` is the resolved ``until`` rev (HEAD when unset). A
    per-guard git failure is recorded in ``errors`` and degrades that
    guard to an unverifiable outcome; it never aborts the run (R13).
    """
    boundary = gitlog.resolve_commit(repo, until or "HEAD")
    if boundary is None:
        return Tracking(
            (),
            (
                {
                    "stage": "track",
                    "reason": (
                        f"boundary rev unresolvable: {until or 'HEAD'}"
                    ),
                },
            ),
        )
    outcomes = []
    errors = []
    for rec in records:
        try:
            outcomes.append(track_guard(repo, rec, boundary))
        except gitlog.GitError as e:
            errors.append(
                {
                    "stage": "track",
                    "seed": rec.seed_sha,
                    "path": rec.path,
                    "reason": str(e),
                }
            )
            outcomes.append(
                _outcome(
                    rec, boundary, "unverifiable", (rec.path,), (), None,
                    ["track-error"], (), None, None, None, False, None,
                    False,
                )
            )
    return Tracking(tuple(outcomes), tuple(errors))
