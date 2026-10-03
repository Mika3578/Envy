#!/usr/bin/env python3
"""Deterministic CLEAN / FIX_AGAIN / NEEDS_HUMAN gate for a PR HEAD.

Consumes a normalized snapshot JSON (never calls GitHub). Inspired by
SteerSpec-style reason codes and OpenCodeReview HEAD checkpoints, without
their "approve after N unclean rounds" escape hatch.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

_REVIEW = Path(__file__).resolve().parents[2] / "scripts" / "review"
if str(_REVIEW) not in sys.path:
    sys.path.insert(0, str(_REVIEW))
import required_checks as required_check_policy  # noqa: E402

DECISION_CLEAN = "CLEAN"
DECISION_FIX_AGAIN = "FIX_AGAIN"
DECISION_NEEDS_HUMAN = "NEEDS_HUMAN"
DECISION_WAITING_COPILOT = "WAITING_COPILOT_REVIEW"

SNAPSHOT_PRE_COPILOT_REQUEST = "pre_copilot_request"
SNAPSHOT_POST_COPILOT_REVIEW = "post_copilot_review"
COMPLETE_REVIEW_STATES = frozenset({"COMMENTED", "APPROVED", "CHANGES_REQUESTED", "DISMISSED"})

REASON_NO_REVIEW = "no review yet for current HEAD"
REASON_WAITING_COPILOT = "waiting for Copilot review on current HEAD"
REASON_PRE_REVIEW_SNAPSHOT = "pre-Copilot snapshot cannot decide CLEAN"
REASON_STALE_REVIEW = "latest review is for an older commit"
REASON_CHANGES_REQUESTED = "active CHANGES_REQUESTED decision"
REASON_UNRESOLVED_THREADS = "unresolved review threads remain"
REASON_UNTREATED_THREADS = "resolved threads lack a current-HEAD disposition reply"
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

PASSING_CHECK_STATES = required_check_policy.PASSING_CHECK_STATES
PENDING_CHECK_STATES = required_check_policy.PENDING_CHECK_STATES

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
    if snapshot.get("snapshot_phase") == SNAPSHOT_PRE_COPILOT_REQUEST:
        return _result(
            DECISION_WAITING_COPILOT,
            [REASON_PRE_REVIEW_SNAPSHOT],
            head_sha=head_sha,
            review_sha=str((snapshot.get("review") or {}).get("commit_id") or ""),
            note="A Copilot request is a synchronization barrier; reuse of the pre-request snapshot is forbidden.",
        )
    if snapshot.get("planned_push") or snapshot.get("local_changes"):
        return _result(
            DECISION_FIX_AGAIN,
            ["HEAD is not stable (planned push or local changes)"],
            head_sha=head_sha,
            review_sha=str((snapshot.get("review") or {}).get("commit_id") or ""),
        )
    review = snapshot.get("review") or {}
    classification = str(snapshot.get("classification") or "")
    requires_fixer = bool(snapshot.get("requires_fixer"))
    requires_human = bool(snapshot.get("requires_human"))
    github_decision = str(snapshot.get("review_decision") or "").upper()
    if not isinstance(snapshot.get("unresolved_threads"), int) or snapshot["unresolved_threads"] < 0:
        return _result(
            DECISION_NEEDS_HUMAN,
            ["unresolved thread count is missing"],
            head_sha=str(snapshot.get("head_sha") or ""),
            review_sha=str((snapshot.get("review") or {}).get("commit_id") or ""),
            note="Refuse CLEAN without a complete thread snapshot.",
        )
    if not isinstance(snapshot.get("human_unresolved_threads"), int) or snapshot["human_unresolved_threads"] < 0:
        return _result(
            DECISION_NEEDS_HUMAN,
            ["human unresolved thread count is missing"],
            head_sha=str(snapshot.get("head_sha") or ""),
            review_sha=str((snapshot.get("review") or {}).get("commit_id") or ""),
            note="Refuse CLEAN without a complete thread snapshot.",
        )
    unresolved_threads = snapshot["unresolved_threads"]
    human_unresolved = snapshot["human_unresolved_threads"]
    if not isinstance(snapshot.get("untreated_threads"), int) or snapshot["untreated_threads"] < 0:
        return _result(
            DECISION_NEEDS_HUMAN,
            ["untreated thread count is missing"],
            head_sha=str(snapshot.get("head_sha") or ""),
            review_sha=str((snapshot.get("review") or {}).get("commit_id") or ""),
            note="Refuse CLEAN without a complete thread snapshot.",
        )
    untreated_threads = snapshot["untreated_threads"]
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
        if snapshot.get("copilot_request_pending"):
            return _result(
                DECISION_WAITING_COPILOT,
                [REASON_WAITING_COPILOT],
                head_sha=head_sha,
                review_sha=review_sha,
            )
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
        if snapshot.get("copilot_request_pending"):
            return _result(
                DECISION_WAITING_COPILOT,
                [f"{REASON_WAITING_COPILOT}; {REASON_STALE_REVIEW} (review={_short(review_sha)} head={_short(head_sha)})"],
                head_sha=head_sha,
                review_sha=review_sha,
                note="A late review for an old SHA is ignored; a new Copilot review is required for the current HEAD.",
            )
        return _result(
            DECISION_NEEDS_HUMAN,
            [f"{REASON_STALE_REVIEW} (review={_short(review_sha)} head={_short(head_sha)})"],
            head_sha=head_sha,
            review_sha=review_sha,
            note="Stale reviews never validate a newer HEAD; wait for a fresh review.",
        )
    review_state = str(review.get("state") or "").upper()
    if snapshot.get("copilot_request_pending") and review_state not in COMPLETE_REVIEW_STATES:
        return _result(
            DECISION_WAITING_COPILOT,
            [REASON_WAITING_COPILOT],
            head_sha=head_sha,
            review_sha=review_sha,
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
    if untreated_threads > 0:
        reasons.append(f"{REASON_UNTREATED_THREADS}: {untreated_threads}")

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

    if requires_fixer or previously_missed or suppressed or open_titles or unresolved_threads > 0 or untreated_threads > 0:
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


def coalesce_post_review_reads(
    first: Mapping[str, Any], second: Mapping[str, Any]
) -> dict[str, Any]:
    """Keep the stricter of two bounded post-review API reads.

    Review threads and overview findings can appear slightly after the
    review submission event. One read is never treated as definitive.
    """
    merged = dict(second)
    merged["unresolved_threads"] = max(
        int(first.get("unresolved_threads") or 0),
        int(second.get("unresolved_threads") or 0),
    )
    merged["untreated_threads"] = max(
        int(first.get("untreated_threads") or 0),
        int(second.get("untreated_threads") or 0),
    )
    for key in (
        "open_finding_titles",
        "previously_missed_titles",
        "suppressed_comment_titles",
        "untreated_pr_level_findings",
    ):
        left = [str(x) for x in (first.get(key) or [])]
        right = [str(x) for x in (second.get(key) or [])]
        merged[key] = list(dict.fromkeys(left + right))
    merged["snapshot_phase"] = SNAPSHOT_POST_COPILOT_REVIEW
    return merged


def decide_after_copilot_request(
    pre_review_snapshot: Mapping[str, Any] | None,
    post_review_snapshot: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Synchronization barrier: never terminate on the pre-request snapshot."""
    if pre_review_snapshot is not None and post_review_snapshot is pre_review_snapshot:
        return _result(
            DECISION_WAITING_COPILOT,
            [REASON_PRE_REVIEW_SNAPSHOT],
            head_sha=str((pre_review_snapshot or {}).get("head_sha") or ""),
            review_sha="",
            note="The stabilizer must wait for a Copilot review and a fresh post-review snapshot.",
        )
    if post_review_snapshot is None:
        head = str((pre_review_snapshot or {}).get("head_sha") or "")
        return _result(
            DECISION_WAITING_COPILOT,
            [REASON_WAITING_COPILOT],
            head_sha=head,
            review_sha="",
        )
    if post_review_snapshot.get("snapshot_phase") == SNAPSHOT_PRE_COPILOT_REQUEST:
        return evaluate_review_loop(post_review_snapshot)
    return evaluate_review_loop(post_review_snapshot)


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
        "merge_ready": decision == DECISION_CLEAN,
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
