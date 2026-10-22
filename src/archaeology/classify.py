"""Five-verdict removal classifier (R8, R9, R10, R11, KD2).

Per candidate removal the decision order is the HTD diagram's, strict:

1. lost lineage -> UNKNOWN. Track's ``severed`` and ``unverifiable``
   statuses route here; ``deleted`` routes to REMOVED-WITH-SINK, the
   terminal-delete evidence a last-hop deletion carries.
2. deliberate language in the removal commit's subject/body, or in a
   merge's constituent commit messages (the only linked-PR language a
   local clone carries, R10) -> DELIBERATE.
3. sink absent at the removal commit -> REMOVED-WITH-SINK.
4. same-family guard provably covering the sink path at the removal
   commit AND still covering it at the boundary -> RELOCATED.
5. sink absent at the boundary -> REMOVED-WITH-SINK.
6. family provably absent at BOTH the removal commit and the boundary,
   sink present at the boundary -> REGRESSED (R9's proven-absence bar
   over function plus bounded caller chain).
7. anything unprovable -> UNKNOWN. A weak evidence chain closes a
   candidate rather than flagging it (KD2).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from . import callers, gitlog, track

@dataclass(frozen=True)
class Verdict:
    """One classified removal; ``verdict`` is one of regressed,
    relocated, removed_with_sink, deliberate, unknown."""

    outcome: track.TrackOutcome
    verdict: str
    removal_sha: str | None
    removal_subject: str | None
    evidence: tuple  # "k=v" markers: which commits proved what


@dataclass(frozen=True)
class Classification:
    verdicts: tuple  # Verdict per non-intact outcome
    errors: tuple  # per-guard failures for R13 error rows


# --- deliberate language --------------------------------------------------------------

_REVERT_RE = re.compile(r"\brevert(?:s|ed|ing)?\b", re.IGNORECASE)

# explicit removal wording aimed at a check-shaped noun, anywhere in the
# message text
_REMOVE_CHECK_RE = re.compile(
    r"\b(?:remov\w+|drop\w*|strip\w*|delet\w*|eliminat\w*|pull\w*)\b"
    r"[^\n]{0,60}?\b(?:check|guard|validat\w*|sanitiz\w*|verif\w*|"
    r"bound\w*|limit\w*|escap\w*|allowlist|denylist|whitelist|"
    r"auth\w*|sanity|constraint|invariant|assertion)\w*\b",
    re.IGNORECASE,
)

_NO_LONGER_RE = re.compile(
    r"\b(?:no longer (?:needed|required|necessary)|not needed|"
    r"unnecessary|unneeded|redundant|obsolete)\b",
    re.IGNORECASE,
)


def removal_texts(repo, sha):
    """The removal commit's own message plus its merge constituents'.

    R10: constituent commit messages are the only linked-PR language a
    local clone can carry.
    """
    texts = [gitlog.commit_message(repo, sha)]
    texts.extend(gitlog.merge_constituent_messages(repo, sha))
    return texts


def _deliberate_language(repo, sha, seed_sha, seed_subject=None):
    """Deliberate marker when the removal speaks for itself, else None.

    Revert wording only counts when the message references the seed
    (its SHA, short prefix, or the ``Revert "<seed subject>"`` form);
    a bare 'revert' word names an intent, not which commit, and cannot
    mark a removal deliberate.
    """
    texts = removal_texts(repo, sha)
    short = seed_sha[:7] if seed_sha else None
    for t in texts:
        refs_seed = (
            (seed_sha and seed_sha in t)
            or (short and short in t)
            or (seed_subject and f'"{seed_subject}"' in t)
        )
        if _REVERT_RE.search(t):
            if refs_seed:
                return "revert-language"
        elif refs_seed:
            return "seed-sha"
    for t in texts:
        if _REMOVE_CHECK_RE.search(t):
            return "removal-language"
        if _NO_LONGER_RE.search(t):
            return "not-needed"
    return None


# --- per-outcome classification -------------------------------------------------------


def _removal_path(repo, outcome):
    """Lineage name in force at the removal commit."""
    return track._path_at(
        outcome.renames, outcome.guard.path, repo, outcome.candidate_sha
    )


def _verdict(outcome, verdict, removal_sha=None, removal_subject=None,
             evidence=()):
    return Verdict(
        outcome=outcome,
        verdict=verdict,
        removal_sha=removal_sha,
        removal_subject=removal_subject,
        evidence=tuple(evidence),
    )


def classify_outcome(repo, outcome, caller_depth=2):
    """TrackOutcome -> Verdict under the strict decision order."""
    rec = outcome.guard
    st = outcome.status
    if st == "deleted":
        brk = outcome.lineage_break
        return _verdict(
            outcome,
            "removed_with_sink",
            evidence=[f"lineage-delete:{brk.sha if brk else '?'}"],
        )
    if st in ("severed", "unverifiable"):
        detail = (
            outcome.lineage_break.kind
            if outcome.lineage_break is not None
            else (outcome.markers[0] if outcome.markers else "track")
        )
        return _verdict(
            outcome, "unknown", evidence=[f"lost-lineage:{detail}"]
        )
    if st != "candidate":
        return _verdict(
            outcome, "unknown", evidence=[f"status:{st}"]
        )
    sha = outcome.candidate_sha
    if sha is None:
        return _verdict(outcome, "unknown", evidence=["no-candidate"])
    subject = None
    try:
        subject = gitlog.commit(repo, sha).subject
    except gitlog.GitError:
        pass
    ev = [f"removal={sha}"]
    if not outcome.add_confirmed:
        return _verdict(
            outcome, "unknown", removal_sha=sha, removal_subject=subject,
            evidence=ev + ["seed-unconfirmed"],
        )
    seed_subject = None
    try:
        seed_subject = gitlog.commit(repo, rec.seed_sha).subject
    except gitlog.GitError:
        pass
    why = _deliberate_language(repo, sha, rec.seed_sha, seed_subject)
    if why:
        return _verdict(
            outcome, "deliberate", removal_sha=sha,
            removal_subject=subject, evidence=ev + [f"deliberate:{why}"],
        )
    rpath = _removal_path(repo, outcome)

    # E: sink absent at the removal commit -> the feature died wholesale
    sp_r = callers.sink_present(
        repo, sha, rpath, rec.sink_function, rec.sink_op
    )
    if sp_r is False:
        return _verdict(
            outcome, "removed_with_sink", removal_sha=sha,
            removal_subject=subject, evidence=ev + ["sink-absent:removal"],
        )
    if sp_r is None:
        return _verdict(
            outcome, "unknown", removal_sha=sha,
            removal_subject=subject,
            evidence=ev + ["sink-unprovable:removal"],
        )

    # F: family coverage at the removal commit and the boundary
    cov_r = callers.family_coverage(
        repo, sha, rpath, rec.sink_function, rec.sink_op,
        rec.family, caller_depth,
    )
    ev.append(f"coverage:removal={cov_r.state}")
    cov_b = None
    if outcome.boundary_present and outcome.boundary_path:
        cov_b = callers.family_coverage(
            repo, outcome.boundary_sha, outcome.boundary_path,
            rec.sink_function, rec.sink_op, rec.family, caller_depth,
        )
        ev.append(f"coverage:boundary={cov_b.state}")
    if (
        cov_r.state == callers.COVERED
        and cov_b is not None
        and cov_b.state == callers.COVERED
    ):
        return _verdict(
            outcome, "relocated", removal_sha=sha,
            removal_subject=subject,
            evidence=ev + ["family-covered:removal+boundary"]
            + list(cov_r.detail)
            + [f"b:{d}" for d in cov_b.detail],
        )

    # G: sink survival at the boundary
    if outcome.boundary_present and outcome.boundary_path:
        sp_b = callers.sink_present(
            repo, outcome.boundary_sha, outcome.boundary_path,
            rec.sink_function, rec.sink_op,
        )
    else:
        sp_b = False
    if sp_b is False:
        return _verdict(
            outcome, "removed_with_sink", removal_sha=sha,
            removal_subject=subject,
            evidence=ev + ["sink-absent:boundary"],
        )
    if sp_b is None:
        return _verdict(
            outcome, "unknown", removal_sha=sha,
            removal_subject=subject,
            evidence=ev + ["sink-unprovable:boundary"],
        )
    if (
        cov_b is not None
        and cov_b.state == callers.ABSENT
        and cov_r.state in (callers.ABSENT, callers.COVERED)
    ):
        # the sink is provably unguarded at the boundary: a same-family
        # replacement that died before the boundary is still a loss
        # (KTD4), same as a family absent at both commits
        marker = (
            "family-absent:removal+boundary"
            if cov_r.state == callers.ABSENT
            else "family-absent:boundary"
        )
        return _verdict(
            outcome, "regressed", removal_sha=sha,
            removal_subject=subject,
            evidence=ev + [marker, "sink-present:boundary"],
        )
    return _verdict(
        outcome, "unknown", removal_sha=sha, removal_subject=subject,
        evidence=ev + ["absence-unproven"],
    )


def classify_all(repo, outcomes, caller_depth=2):
    """Verdicts for every non-intact outcome; errors degrade to UNKNOWN.

    INTACT is assigned by tracking (R6) and never reaches the classifier
    (R8). A per-guard git failure is recorded for the R13 error rows and
    that guard's verdict degrades to UNKNOWN; it never aborts the run.
    """
    verdicts = []
    errors = []
    for o in outcomes:
        if o.status == "intact":
            continue
        try:
            verdicts.append(
                classify_outcome(repo, o, caller_depth=caller_depth)
            )
        except gitlog.GitError as e:
            errors.append(
                {
                    "stage": "classify",
                    "seed": o.guard.seed_sha,
                    "path": o.guard.path,
                    "reason": str(e),
                }
            )
            verdicts.append(
                _verdict(o, "unknown", evidence=["classify-error"])
            )
    return Classification(tuple(verdicts), tuple(errors))
