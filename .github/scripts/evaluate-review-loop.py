#!/usr/bin/env python3
"""Deterministic CLEAN / FIX_AGAIN / NEEDS_HUMAN gate for a PR HEAD.

Consumes a normalized snapshot JSON (never calls GitHub). Inspired by
SteerSpec-style reason codes and OpenCodeReview HEAD checkpoints, without
their "approve after N unclean rounds" escape hatch.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Mapping, Sequence

DECISION_CLEAN = "CLEAN"
DECISION_FIX_AGAIN = "FIX_AGAIN"
DECISION_NEEDS_HUMAN = "NEEDS_HUMAN"

REASON_NO_REVIEW = "no review yet for current HEAD"
REASON_STALE_REVIEW = "latest review is for an older commit"
REASON_CHANGES_REQUESTED = "active CHANGES_REQUESTED decision"
REASON_UNRESOLVED_THREADS = "unresolved review threads remain"
REASON_HUMAN_UNRESOLVED = "unresolved human review threads remain"
REASON_BODY_FINDINGS = "review body still has active findings"
REASON_PREVIOUSLY_MISSED = "Previously missed findings remain"
REASON_SUPPRESSED = "Suppressed comments remain in review body"
REASON_INLINE_FINDINGS = "active inline findings remain"
REASON_NAMED_TECHNICAL = "named technical issue in review rationale"
REASON_HUMAN_ONLY = "review asks for human validation without concrete defect"
REASON_VALIDATION_MISSING = "validation or evidence still missing"
REASON_REPEATED_FINDING = "same finding exceeded autofix budget"
REASON_REQUIRED_CI_FAILING = "required check failing"
REASON_REQUIRED_CI_PENDING = "required check pending"
REASON_CLEAN = "latest review of current HEAD has no active technical findings"
REASON_MALFORMED = "review overview could not be classified"

PASSING_CHECK_STATES = frozenset({"SUCCESS", "NEUTRAL"})
PENDING_CHECK_STATES = frozenset(
    {"PENDING", "QUEUED", "IN_PROGRESS", "WAITING", "REQUESTED"}
)

MAX_AUTOFIX_ATTEMPTS = None  # History is retained; attempts alone do not stop correction.


def _short(sha: str | None) -> str:
    if not sha:
        return "(none)"
    return sha if len(sha) <= 12 else f"{sha[:7]}…"


def evaluate_review_loop(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Return decision + ordered reason codes for one PR HEAD snapshot."""
    head_sha = str(snapshot.get("head_sha") or "")
    if snapshot.get("human_stop_review_ids"):
        return _result(DECISION_NEEDS_HUMAN,
                       ["persistent human decision requires authenticated disposition"],
                       head_sha=head_sha,
                       review_sha=str((snapshot.get("review") or {}).get("commit_id") or ""))
    review = snapshot.get("review") or {}
    classification = str(snapshot.get("classification") or "")
    requires_fixer = bool(snapshot.get("requires_fixer"))
    requires_human = bool(snapshot.get("requires_human"))
    github_decision = str(snapshot.get("review_decision") or "").upper()
    unresolved_threads = int(snapshot.get("unresolved_threads") or 0)
    human_unresolved = int(snapshot.get("human_unresolved_threads") or 0)
    open_titles = [str(x) for x in (snapshot.get("open_finding_titles") or [])]
    previously_missed = [
        str(x) for x in (snapshot.get("previously_missed_titles") or [])
    ]
    suppressed = [str(x) for x in (snapshot.get("suppressed_comment_titles") or [])]
    ledger = snapshot.get("finding_ledger") or []
    raw_checks = snapshot.get("required_checks", None)
    # Fail closed before any CLEAN path: missing/non-list/empty is not CI evidence.
    if not isinstance(raw_checks, list) or len(raw_checks) == 0:
        return _result(
            DECISION_NEEDS_HUMAN,
            ["required checks snapshot is empty"],
            head_sha=str(snapshot.get("head_sha") or ""),
            review_sha=str((snapshot.get("review") or {}).get("commit_id") or ""),
            note="Refuse CLEAN without required CI evidence.",
        )
    checks = raw_checks

    reasons: list[str] = []
    review_sha = str(review.get("commit_id") or review.get("head_sha") or "")

    if not review or not review_sha:
        return _result(
            DECISION_NEEDS_HUMAN,
            [REASON_NO_REVIEW],
            head_sha=head_sha,
            review_sha=review_sha,
        )

    # Fail closed: missing live HEAD or review commit must never reach CLEAN.
    if not head_sha:
        return _result(
            DECISION_NEEDS_HUMAN,
            [f"{REASON_STALE_REVIEW} (missing live head_sha)"],
            head_sha=head_sha,
            review_sha=review_sha,
            note="Freshness requires both live HEAD and review commit; refuse CLEAN when either is missing.",
        )

    if review_sha != head_sha:
        return _result(
            DECISION_NEEDS_HUMAN,
            [f"{REASON_STALE_REVIEW} (review={_short(review_sha)} head={_short(head_sha)})"],
            head_sha=head_sha,
            review_sha=review_sha,
            note="Stale reviews never validate a newer HEAD; wait for a fresh review.",
        )

    # Required CI
    for check in checks:
        name = str(check.get("name") or "unknown")
        state = str(check.get("state") or "").upper()
        if state in PENDING_CHECK_STATES:
            reasons.append(f"{REASON_REQUIRED_CI_PENDING}: {name}")
        elif state not in PASSING_CHECK_STATES:
            reasons.append(f"{REASON_REQUIRED_CI_FAILING}: {name} ({state})")
    if any(REASON_REQUIRED_CI_FAILING in r for r in reasons):
        return _result(
            DECISION_NEEDS_HUMAN,
            reasons,
            head_sha=head_sha,
            review_sha=review_sha,
        )
    if any(REASON_REQUIRED_CI_PENDING in r for r in reasons):
        return _result(
            DECISION_NEEDS_HUMAN,
            reasons,
            head_sha=head_sha,
            review_sha=review_sha,
            note="Do not treat missing CI as CLEAN.",
        )

    if human_unresolved > 0:
        reasons.append(f"{REASON_HUMAN_UNRESOLVED}: {human_unresolved}")
        return _result(
            DECISION_NEEDS_HUMAN,
            reasons,
            head_sha=head_sha,
            review_sha=review_sha,
            note="Human review threads require a human response, not FIX_AGAIN.",
        )

    if github_decision == "CHANGES_REQUESTED":
        reasons.append(REASON_CHANGES_REQUESTED)
        return _result(
            DECISION_FIX_AGAIN if requires_fixer else DECISION_NEEDS_HUMAN,
            reasons,
            head_sha=head_sha,
            review_sha=review_sha,
            note="Correct technical findings; the reviewer must independently clear CHANGES_REQUESTED.",
        )

    if unresolved_threads > 0:
        reasons.append(f"{REASON_UNRESOLVED_THREADS}: {unresolved_threads}")

    if open_titles:
        reasons.append(f"{REASON_INLINE_FINDINGS}: {len(open_titles)}")
    if previously_missed:
        reasons.append(f"{REASON_PREVIOUSLY_MISSED}: {len(previously_missed)}")
    if suppressed:
        reasons.append(f"{REASON_SUPPRESSED}: {len(suppressed)}")

    repeated = _repeated_findings(ledger)
    if repeated:
        reasons.append(f"{REASON_REPEATED_FINDING}: {', '.join(repeated)}")

    # Classification-driven branch (from classify-copilot-review.py).
    # Fail closed: inconsistent snapshots that say APPROVED while also
    # requiring fixer/human work must never report CLEAN.
    review_state = str(review.get("state") or "").upper()
    if (
        classification == "APPROVED"
        and review_state == "APPROVED"
        and not reasons
        and not requires_fixer
        and not requires_human
    ):
        return _result(
            DECISION_CLEAN,
            [REASON_CLEAN],
            head_sha=head_sha,
            review_sha=review_sha,
        )

    if classification in {"COPILOT_QUOTA_BLOCKED", "COPILOT_DIFF_TOO_LARGE", "REVIEW_ERROR", "MALFORMED", "NON_COPILOT"}:
        reasons.append(REASON_MALFORMED if classification == "MALFORMED" else classification)
        return _result(
            DECISION_NEEDS_HUMAN,
            reasons or [classification],
            head_sha=head_sha,
            review_sha=review_sha,
        )

    if repeated:
        return _result(
            DECISION_NEEDS_HUMAN,
            reasons,
            head_sha=head_sha,
            review_sha=review_sha,
        )

    if requires_human:
        if classification == "VALIDATION_MISSING":
            reasons.append(REASON_VALIDATION_MISSING)
        else:
            reasons.append(REASON_HUMAN_ONLY)
        return _result(
            DECISION_NEEDS_HUMAN,
            reasons,
            head_sha=head_sha,
            review_sha=review_sha,
        )

    if requires_fixer or previously_missed or suppressed or open_titles or unresolved_threads > 0:
        if classification == "CLOSER_LOOK_DIAGNOSTIC" and not (
            previously_missed or suppressed or open_titles
        ):
            reasons.append(REASON_NAMED_TECHNICAL)
        if not reasons:
            reasons.append(REASON_BODY_FINDINGS)
        return _result(
            DECISION_FIX_AGAIN,
            reasons,
            head_sha=head_sha,
            review_sha=review_sha,
        )

    if github_decision == "CHANGES_REQUESTED":
        return _result(
            DECISION_NEEDS_HUMAN,
            reasons,
            head_sha=head_sha,
            review_sha=review_sha,
        )

    # Findings: None + unresolved_threads=0 is NOT enough without a current-HEAD
    # review classification that is Approved or explicitly clean.
    if classification in {"ACTIONABLE_FINDINGS", "CLOSER_LOOK_DIAGNOSTIC"}:
        reasons.append(REASON_NAMED_TECHNICAL)
        return _result(
            DECISION_FIX_AGAIN,
            reasons,
            head_sha=head_sha,
            review_sha=review_sha,
        )

    if classification == "HUMAN_REQUIRED":
        reasons.append(REASON_HUMAN_ONLY)
        return _result(
            DECISION_NEEDS_HUMAN,
            reasons,
            head_sha=head_sha,
            review_sha=review_sha,
        )

    if classification == "APPROVED":
        if review_state != "APPROVED":
            # Classification and GitHub review state disagree: fail closed.
            reasons.append(REASON_HUMAN_ONLY)
            return _result(
                DECISION_NEEDS_HUMAN,
                reasons,
                head_sha=head_sha,
                review_sha=review_sha,
                note="classification APPROVED but GitHub review state is not APPROVED.",
            )
        return _result(
            DECISION_CLEAN,
            [REASON_CLEAN],
            head_sha=head_sha,
            review_sha=review_sha,
        )

    # Conservative default: never infer CLEAN from empty threads alone.
    return _result(
        DECISION_NEEDS_HUMAN,
        reasons or [REASON_NO_REVIEW],
        head_sha=head_sha,
        review_sha=review_sha,
        note="unresolved_threads=0 is insufficient without a clean current-HEAD review.",
    )


def _repeated_findings(ledger: Sequence[Mapping[str, Any]]) -> list[str]:
    out: list[str] = []
    for item in ledger:
        # Only `attempts` counts autofix cycles; do not treat `times_seen` as attempts.
        attempts = int(item.get("attempts") or 0)
        status = str(item.get("status") or "").lower()
        fingerprint = str(item.get("fingerprint") or item.get("id") or "")
        if status == "needs_human":
            if fingerprint and fingerprint not in out:
                out.append(fingerprint)
    return out


def _result(
    decision: str,
    reasons: Sequence[str],
    *,
    head_sha: str,
    review_sha: str,
    note: str | None = None,
) -> dict[str, Any]:
    primary = reasons[0] if reasons else REASON_NO_REVIEW
    payload: dict[str, Any] = {
        "decision": decision,
        "reason": primary,
        "reasons": list(reasons),
        "head_sha": head_sha,
        "review_sha": review_sha,
        "max_autofix_attempts": MAX_AUTOFIX_ATTEMPTS,
    }
    if note:
        payload["note"] = note
    return payload


def main() -> int:
    # Stdin only: no CLI path arguments (avoids path-injection / LLM-supplied path surfaces).
    snapshot = json.load(sys.stdin)
    if not isinstance(snapshot, dict):
        raise SystemExit("snapshot JSON must be an object")
    sys.stdout.write(json.dumps(evaluate_review_loop(snapshot), indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
