#!/usr/bin/env python3
"""Evaluate pull-request review readiness for a specific HEAD SHA.

Pure, offline-capable policy. Consumes a normalized snapshot JSON and never
calls GitHub. Distinguishes review-complete from merge-approval validity.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Mapping, Sequence

COPILOT_REVIEWER_LOGIN = "copilot-pull-request-reviewer[bot]"
COPILOT_REVIEWER_LOGINS = frozenset(
    {
        "copilot-pull-request-reviewer[bot]",
        "copilot-pull-request-reviewer",
        "Copilot",
    }
)
MAX_COPILOT_GENERATIONS = 3

# Terminal / next-action classes for the orchestrator.
READY_TO_MERGE = "READY_TO_MERGE"
REVIEW_COMPLETE = "REVIEW_COMPLETE"
STALE_REVIEW = "STALE_REVIEW"
ACTIONABLE_FINDINGS = "ACTIONABLE_FINDINGS"
NO_ACTIONABLE_FINDINGS_REQUIRES_CONFIRMATION = (
    "NO_ACTIONABLE_FINDINGS_REQUIRES_CONFIRMATION"
)
APPROVED = "APPROVED"
REQUEST_COPILOT = "REQUEST_COPILOT"
WAIT_COPILOT = "WAIT_COPILOT"
COPILOT_RETRYABLE_ERROR = "COPILOT_RETRYABLE_ERROR"
COPILOT_QUOTA_BLOCKED = "COPILOT_QUOTA_BLOCKED"
COPILOT_UNAVAILABLE = "COPILOT_UNAVAILABLE"
COPILOT_DIFF_TOO_LARGE = "COPILOT_DIFF_TOO_LARGE"
HUMAN_REQUIRED = "HUMAN_REQUIRED"
NOT_MERGE_READY = "NOT_MERGE_READY"
GENERATION_BUDGET_EXCEEDED = "GENERATION_BUDGET_EXCEEDED"

PASSING_CHECK_STATES = frozenset({"SUCCESS", "SKIPPED", "NEUTRAL"})
PENDING_CHECK_STATES = frozenset({"PENDING", "QUEUED", "IN_PROGRESS", "WAITING"})


def _norm_state(value: Any) -> str:
    return str(value or "").strip().upper()


def _short_sha(sha: str | None) -> str:
    if not sha:
        return "(none)"
    return sha if len(sha) <= 12 else f"{sha[:12]}..."


def _is_copilot_login(login: str) -> bool:
    return login in COPILOT_REVIEWER_LOGINS


def select_copilot_review_for_head(
    reviews: Sequence[Mapping[str, Any]], head_sha: str
) -> dict[str, Any] | None:
    """Latest completed Copilot review whose commit_id matches head_sha."""
    matches: list[Mapping[str, Any]] = []
    for review in reviews:
        login = str((review.get("user") or {}).get("login") or review.get("author") or "")
        if not _is_copilot_login(login):
            continue
        if str(review.get("commit_id") or "") != head_sha:
            continue
        state = _norm_state(review.get("state"))
        if state in {"PENDING"}:
            continue
        matches.append(review)
    if not matches:
        return None
    matches.sort(key=lambda item: str(item.get("submitted_at") or ""), reverse=True)
    return dict(matches[0])


def latest_copilot_review(
    reviews: Sequence[Mapping[str, Any]],
) -> dict[str, Any] | None:
    matches = [
        review
        for review in reviews
        if _is_copilot_login(
            str((review.get("user") or {}).get("login") or review.get("author") or "")
        )
        and _norm_state(review.get("state")) != "PENDING"
    ]
    if not matches:
        return None
    matches.sort(key=lambda item: str(item.get("submitted_at") or ""), reverse=True)
    return dict(matches[0])


def classify_copilot_error(body: str) -> str | None:
    text = (body or "").lower()
    if not text.strip():
        return None
    if "quota" in text or "rate limit" in text or "usage limit" in text:
        return COPILOT_QUOTA_BLOCKED
    if "too large" in text or "diff is too large" in text or "exceeds the maximum" in text:
        return COPILOT_DIFF_TOO_LARGE
    if "encountered an error" in text or "unable to review" in text:
        return COPILOT_RETRYABLE_ERROR
    if "could not access" in text or "timed out" in text or "timeout" in text:
        return COPILOT_UNAVAILABLE
    return None


def count_threads(threads: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    total = len(threads)
    unresolved = 0
    unresolved_copilot = 0
    unresolved_other = 0
    for thread in threads:
        if thread.get("isResolved") is True:
            continue
        unresolved += 1
        comments = thread.get("comments") or []
        authors = {
            str(
                (comment.get("author") or {}).get("login")
                or (comment.get("user") or {}).get("login")
                or ""
            )
            for comment in comments
        }
        if COPILOT_REVIEWER_LOGIN in authors or "Copilot" in authors or any(
            _is_copilot_login(author) for author in authors
        ):
            unresolved_copilot += 1
        else:
            unresolved_other += 1
    return {
        "total_threads": total,
        "unresolved_threads": unresolved,
        "unresolved_copilot_threads": unresolved_copilot,
        "unresolved_other_reviewer_threads": unresolved_other,
    }


def evaluate_required_checks(
    checks: Sequence[Mapping[str, Any]], *, required_contexts: Sequence[str] | None = None
) -> dict[str, Any]:
    by_name: dict[str, Mapping[str, Any]] = {}
    for check in checks:
        name = str(check.get("name") or check.get("context") or "")
        if not name:
            continue
        by_name[name] = check

    selected: list[Mapping[str, Any]]
    if required_contexts:
        selected = [by_name[name] for name in required_contexts if name in by_name]
        missing = [name for name in required_contexts if name not in by_name]
    else:
        selected = list(by_name.values())
        missing = []

    failing: list[str] = []
    pending: list[str] = []
    passing = 0
    for check in selected:
        name = str(check.get("name") or check.get("context") or "")
        state = _norm_state(check.get("state") or check.get("conclusion"))
        if state in PASSING_CHECK_STATES:
            passing += 1
        elif state in PENDING_CHECK_STATES:
            pending.append(name)
        else:
            failing.append(f"{name}:{state or 'UNKNOWN'}")

    total = len(selected) + len(missing)
    return {
        "required_total": total,
        "required_passing": passing,
        "required_green": total > 0 and not failing and not pending and not missing,
        "failing": failing,
        "pending": pending,
        "missing": list(missing),
    }


def find_valid_approval(
    reviews: Sequence[Mapping[str, Any]], head_sha: str
) -> dict[str, Any] | None:
    """A real GitHub APPROVED review on the current HEAD (not dismissed)."""
    candidates: list[Mapping[str, Any]] = []
    for review in reviews:
        if _norm_state(review.get("state")) != "APPROVED":
            continue
        if str(review.get("commit_id") or "") != head_sha:
            continue
        # Text containing "Approved." is irrelevant; state is authoritative.
        candidates.append(review)
    if not candidates:
        return None
    candidates.sort(key=lambda item: str(item.get("submitted_at") or ""), reverse=True)
    return dict(candidates[0])


def decide_request_action(
    *,
    head_sha: str,
    copilot_for_head: Mapping[str, Any] | None,
    pending_request: bool,
    request_marker_for_head: bool,
    generation_count: int,
    stable: bool,
) -> str:
    if generation_count >= MAX_COPILOT_GENERATIONS:
        return GENERATION_BUDGET_EXCEEDED
    if not stable:
        return WAIT_COPILOT
    if copilot_for_head is not None:
        return "NONE"
    if pending_request or request_marker_for_head:
        return WAIT_COPILOT
    return REQUEST_COPILOT


def evaluate_snapshot(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    head_sha = str(snapshot.get("head_sha") or "")
    if not head_sha:
        raise ValueError("snapshot.head_sha is required")

    reviews = list(snapshot.get("reviews") or [])
    threads = list(snapshot.get("threads") or [])
    checks = list(snapshot.get("checks") or [])
    required_contexts = snapshot.get("required_contexts")
    if required_contexts is not None and not isinstance(required_contexts, list):
        raise ValueError("required_contexts must be a list when provided")

    copilot_outcome = snapshot.get("copilot_outcome") or {}
    pending_request = bool(snapshot.get("copilot_review_requested"))
    request_marker_for_head = bool(snapshot.get("request_marker_for_head"))
    generation_count = int(snapshot.get("copilot_generation_count") or 0)
    stable = bool(snapshot.get("head_stable", True))
    changed_files = int(snapshot.get("changed_files") or 0)
    diff_too_large = bool(snapshot.get("diff_too_large", False))
    coverage_incomplete = bool(snapshot.get("review_coverage_incomplete", False))

    thread_stats = count_threads(threads)
    check_stats = evaluate_required_checks(
        checks, required_contexts=required_contexts
    )
    copilot_for_head = select_copilot_review_for_head(reviews, head_sha)
    any_copilot = latest_copilot_review(reviews)
    approval = find_valid_approval(reviews, head_sha)

    assessment = str(copilot_outcome.get("assessment") or "")
    classification = str(copilot_outcome.get("classification") or "")
    github_state = (
        _norm_state(copilot_for_head.get("state")) if copilot_for_head else ""
    )
    finding_open = int(
        copilot_outcome.get("finding_count")
        if copilot_outcome.get("finding_count") is not None
        else 0
    )
    finding_resolved = int(copilot_outcome.get("resolved_count") or 0)
    if copilot_outcome.get("resolved_since_last_titles"):
        finding_resolved = max(
            finding_resolved, len(copilot_outcome["resolved_since_last_titles"])
        )

    error_class = None
    if copilot_for_head is not None:
        error_class = classify_copilot_error(str(copilot_for_head.get("body") or ""))
    if diff_too_large:
        error_class = COPILOT_DIFF_TOO_LARGE

    review_complete = copilot_for_head is not None and error_class is None
    assessment_green = assessment in {"APPROVED", "APPROVAL_RECOMMENDED"} or (
        github_state == "APPROVED"
        and classification == "APPROVED"
    )
    # Assessment green must not be confused with a GitHub APPROVED state.
    copilot_assessment_green = assessment == "APPROVED" or (
        classification == "APPROVED" and github_state == "APPROVED"
    )
    if assessment == "APPROVED" and github_state and github_state != "APPROVED":
        # visual assessment only
        copilot_assessment_green = True

    merge_approval_valid = approval is not None
    review_stale = False
    stale_review_sha = None
    if any_copilot and (
        not copilot_for_head
        or str(any_copilot.get("commit_id") or "") != head_sha
    ):
        if str(any_copilot.get("commit_id") or "") != head_sha:
            review_stale = True
            stale_review_sha = str(any_copilot.get("commit_id") or "")
        if _norm_state(any_copilot.get("state")) == "DISMISSED":
            review_stale = True
            stale_review_sha = str(any_copilot.get("commit_id") or "")

    next_action = NOT_MERGE_READY
    blockers: list[str] = []

    if generation_count >= MAX_COPILOT_GENERATIONS and not (
        review_complete and finding_open == 0 and merge_approval_valid
    ):
        next_action = GENERATION_BUDGET_EXCEEDED
        blockers.append(
            f"Final Copilot generation budget exceeded ({generation_count}/{MAX_COPILOT_GENERATIONS})."
        )
        if review_stale:
            blockers.append(
                f"Latest Copilot review is also stale "
                f"(reviewed {_short_sha(stale_review_sha)}, HEAD {_short_sha(head_sha)})."
            )
    elif error_class:
        next_action = error_class
        blockers.append(f"Copilot review error class: {error_class}")
    elif coverage_incomplete:
        next_action = HUMAN_REQUIRED
        blockers.append("Review coverage incomplete; do not treat as success.")
    elif review_stale and not review_complete:
        next_action = STALE_REVIEW
        blockers.append(
            f"Latest Copilot review is stale (reviewed {_short_sha(stale_review_sha)}, "
            f"HEAD {_short_sha(head_sha)})."
        )
    elif not review_complete:
        request = decide_request_action(
            head_sha=head_sha,
            copilot_for_head=copilot_for_head,
            pending_request=pending_request,
            request_marker_for_head=request_marker_for_head,
            generation_count=generation_count,
            stable=stable,
        )
        next_action = request if request != "NONE" else REQUEST_COPILOT
        if next_action == WAIT_COPILOT:
            blockers.append("Copilot review already requested or still running for this HEAD.")
        elif next_action == REQUEST_COPILOT:
            blockers.append("No Copilot review completed for the current HEAD.")
        elif next_action == GENERATION_BUDGET_EXCEEDED:
            blockers.append("Generation budget exceeded before a fresh HEAD review.")
    elif finding_open > 0 or classification == "ACTIONABLE_FINDINGS":
        next_action = ACTIONABLE_FINDINGS
        blockers.append(f"Open Copilot findings: {finding_open}")
    elif classification == "CLOSER_LOOK_DIAGNOSTIC" or (
        assessment == "NEEDS_CLOSER_LOOK" and finding_open == 0
    ):
        next_action = NO_ACTIONABLE_FINDINGS_REQUIRES_CONFIRMATION
        blockers.append(
            "Copilot Needs a closer look with no actionable findings; "
            "do not modify code arbitrarily."
        )
    elif classification == "VALIDATION_MISSING":
        next_action = NO_ACTIONABLE_FINDINGS_REQUIRES_CONFIRMATION
        blockers.append("Validation evidence is still missing for this HEAD.")
    elif thread_stats["unresolved_threads"] > 0:
        next_action = NOT_MERGE_READY
        blockers.append(
            f"Unresolved review threads: {thread_stats['unresolved_threads']} "
            f"(copilot={thread_stats['unresolved_copilot_threads']}, "
            f"other={thread_stats['unresolved_other_reviewer_threads']})"
        )
    elif not check_stats["required_green"]:
        next_action = NOT_MERGE_READY
        if check_stats["failing"]:
            blockers.append("Required checks failing: " + ", ".join(check_stats["failing"]))
        if check_stats["pending"]:
            blockers.append("Required checks pending: " + ", ".join(check_stats["pending"]))
        if check_stats["missing"]:
            blockers.append("Required checks missing: " + ", ".join(check_stats["missing"]))
    elif not merge_approval_valid:
        next_action = REVIEW_COMPLETE
        blockers.append(
            "HEAD has been reviewed, but no GitHub APPROVED review is valid for this HEAD."
        )
        if github_state == "COMMENTED" and (
            assessment_green or assessment == "APPROVED" or classification == "HUMAN_REQUIRED"
        ):
            blockers.append(
                "Copilot assessment looks green, but review.state is COMMENTED (not APPROVED)."
            )
        if classification == "HUMAN_REQUIRED":
            blockers.append("Human confirmation is still required before merge approval.")
    else:
        next_action = READY_TO_MERGE

    ready = next_action == READY_TO_MERGE

    report_lines = [
        "PR Review Gate",
        "",
        f"HEAD: {_short_sha(head_sha)}",
        f"Changed files: {changed_files}",
        "",
        "Copilot:",
        f"  review found for HEAD: {'yes' if copilot_for_head else 'no'}",
        f"  reviewed SHA: {_short_sha((copilot_for_head or any_copilot or {}).get('commit_id'))}",
        f"  current SHA: {_short_sha(head_sha)}",
        f"  status: {'STALE' if review_stale and not review_complete else (github_state or 'NONE')}",
        f"  assessment: {assessment or '(none)'}",
        f"  classification: {classification or '(none)'}",
        f"  github state: {github_state or '(none)'}",
        f"  generation: {generation_count}/{MAX_COPILOT_GENERATIONS}",
        "",
        "Copilot findings:",
        f"  open: {finding_open}",
        f"  resolved: {finding_resolved}",
        "",
        "Review threads:",
        f"  unresolved: {thread_stats['unresolved_threads']}",
        f"  unresolved Copilot: {thread_stats['unresolved_copilot_threads']}",
        f"  unresolved other: {thread_stats['unresolved_other_reviewer_threads']}",
        "",
        "Required checks:",
        f"  {check_stats['required_passing']}/{check_stats['required_total']} passing",
        f"  green: {str(check_stats['required_green']).lower()}",
        "",
        "Approval:",
        f"  valid for current HEAD: {str(merge_approval_valid).lower()}",
        "",
        "Gates:",
        f"  review_complete: {str(review_complete).lower()}",
        f"  merge_approval_valid: {str(merge_approval_valid).lower()}",
        f"  ready_to_merge: {str(ready).lower()}",
        "",
        f"Next action: {next_action}",
    ]
    if blockers:
        report_lines.append("")
        report_lines.append("Blockers:")
        for blocker in blockers:
            report_lines.append(f"  - {blocker}")

    return {
        "head_sha": head_sha,
        "copilot": {
            "requested": pending_request or request_marker_for_head,
            "running": pending_request and not review_complete,
            "completed": review_complete,
            "reviewed_sha": (
                str(copilot_for_head.get("commit_id"))
                if copilot_for_head
                else (str(any_copilot.get("commit_id")) if any_copilot else None)
            ),
            "state": github_state or None,
            "assessment": assessment or None,
            "classification": classification or None,
            "assessment_green": copilot_assessment_green,
            "stale": review_stale and not review_complete,
            "generation_count": generation_count,
            "max_generations": MAX_COPILOT_GENERATIONS,
            "error_class": error_class,
        },
        "findings": {
            "open": finding_open,
            "resolved": finding_resolved,
        },
        "threads": thread_stats,
        "checks": check_stats,
        "approval": {
            "valid_for_head": merge_approval_valid,
            "review_id": str(approval.get("id")) if approval else None,
            "reviewer": (
                str((approval.get("user") or {}).get("login") or "")
                if approval
                else None
            ),
        },
        "review_complete": review_complete,
        "merge_approval_valid": merge_approval_valid,
        "ready_to_merge": ready,
        "next_action": next_action,
        "blockers": blockers,
        "report": "\n".join(report_lines) + "\n",
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--snapshot-json",
        default="-",
        choices=["-"],
        help="Read snapshot JSON from stdin (only '-' is supported)",
    )
    args = parser.parse_args(argv)
    raw = json.load(sys.stdin)
    if not isinstance(raw, dict):
        raise SystemExit("snapshot JSON must be an object")
    result = evaluate_snapshot(raw)
    sys.stdout.write(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
