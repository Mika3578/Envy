#!/usr/bin/env python3
"""Exact-HEAD Final review gate evaluator.

Consumes a normalized snapshot JSON (never calls GitHub). Posts nothing.
A later workflow may write commit status context GATE_CONTEXT on publish_sha
only when allow_publish is true.

Fail closed: API errors, ambiguous identity, stale HEAD, incomplete CI,
untreated findings, and unknown reviewers never become success.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

_REVIEW = Path(__file__).resolve().parents[2] / "scripts" / "review"
if str(_REVIEW) not in sys.path:
    sys.path.insert(0, str(_REVIEW))
import disposition as disposition_policy  # noqa: E402
import required_checks as required_check_policy  # noqa: E402

GATE_CONTEXT = "Final review gate"
# GitHub Actions app id pinned by protect-develop.final-review-gate.desired.json.
GATE_PUBLISHER_INTEGRATION_ID = 15368

STATE_SUCCESS = "success"
STATE_FAILURE = "failure"
STATE_PENDING = "pending"
STATE_ERROR = "error"

# Code Review reviewer aliases only. The Copilot SWE coding agent must never
# satisfy "Copilot already reviewed this SHA" / gate SUCCESS — that identity is
# classified NON_COPILOT and would otherwise deadlock the final request.
COPILOT_LOGINS = frozenset(
    {
        "Copilot",
        "copilot-pull-request-reviewer",
        "copilot-pull-request-reviewer[bot]",
    }
)
# Known non-reviewer Copilot identities: ignore for latest-review matching so
# they neither count as "already reviewed" nor trip unknown-identity ERROR.
NON_REVIEWER_COPILOT_LOGINS = frozenset(
    {
        "copilot-swe-agent",
        "copilot-swe-agent[bot]",
        "github-copilot",
        "github-copilot[bot]",
    }
)

# Privileged governance: Copilot APPROVED is never sufficient.
PRIVILEGED_PATHS = (
    "AGENTS.md",
    ".github/copilot-instructions.md",
    ".github/settings.yml",
)
PRIVILEGED_PREFIXES = (
    ".github/skills/",
    ".github/workflows/",
    ".github/rulesets/",
    ".github/scripts/",
    ".github/review-ledgers/",
    "scripts/review/",
)

PASSING_CHECK_STATES = required_check_policy.PASSING_CHECK_STATES
GATE_PASSING_CHECK_STATES = required_check_policy.GATE_PASSING_CHECK_STATES
PENDING_CHECK_STATES = required_check_policy.PENDING_CHECK_STATES
# Gate SUCCESS requires a fully mergeable head. Copilot *request* eligibility
# still allows BLOCKED/HAS_HOOKS because Copilot APPROVED is often what clears
# the review-gate BLOCKED state (CLEAN-only before request would deadlock).
GATE_SUCCESS_MERGE_STATES = frozenset({"CLEAN"})
REQUEST_MERGE_STATES = frozenset({"CLEAN", "BLOCKED", "HAS_HOOKS"})

SUCCESS_COPILOT_CLASSIFICATIONS = frozenset({"APPROVED"})
BLOCKING_COPILOT_CLASSIFICATIONS = frozenset(
    {
        "MALFORMED",
        "CLOSER_LOOK_DIAGNOSTIC",
        "VALIDATION_MISSING",
        "ACTIONABLE_FINDINGS",
        "HUMAN_REQUIRED",
        "COPILOT_QUOTA_BLOCKED",
        "COPILOT_DIFF_TOO_LARGE",
        "REVIEW_ERROR",
        "NON_COPILOT",
    }
)

def is_privileged_path(path: str) -> bool:
    normalized = (path or "").replace("\\", "/").lstrip("/")
    if normalized in PRIVILEGED_PATHS:
        return True
    return any(normalized.startswith(prefix) for prefix in PRIVILEGED_PREFIXES)


def privileged_paths_changed(files: Sequence[Any]) -> bool:
    for item in files or []:
        candidates: list[str] = []
        if isinstance(item, str):
            candidates.append(item)
        elif isinstance(item, Mapping):
            for key in ("path", "filename", "previous_filename"):
                value = item.get(key)
                if value:
                    candidates.append(str(value))
        for path in candidates:
            if is_privileged_path(path):
                return True
    return False


def _login(review: Mapping[str, Any]) -> str:
    user = review.get("user")
    if isinstance(user, Mapping):
        return str(user.get("login") or "")
    return str(review.get("login") or "")


def _is_copilot(login: str) -> bool:
    return login in COPILOT_LOGINS


def _looks_like_copilot(login: str) -> bool:
    return "copilot" in login.lower()


def is_advisory_self_gate_check(check: Mapping[str, Any]) -> bool:
    """True only for this publisher's Final review gate receipt (integration 15368).

    Another required integration that reuses the same context name must still be
    evaluated; name-only filtering would hide its missing/failing receipt.
    """
    name = str(check.get("name") or check.get("context") or "")
    if name != GATE_CONTEXT:
        return False
    return check.get("integration_id") == GATE_PUBLISHER_INTEGRATION_ID


def is_authorized_disposition_author(login: str, *, typename: str = "", user_type: str = "") -> bool:
    """Human User replies only. Bots and Copilot never treat a thread."""
    if user_type and str(user_type) != "User":
        return False
    if typename and str(typename) != "User":
        return False
    if not typename and not user_type:
        return False
    if not login or _is_copilot(login) or _looks_like_copilot(login) or login.endswith("[bot]"):
        return False
    return True


def comment_commit_oid(item: Mapping[str, Any]) -> str:
    commit = item.get("commit")
    if isinstance(commit, Mapping):
        return str(commit.get("oid") or "")
    return str(item.get("commit_id") or "")


def resolved_thread_is_untreated(comments: Sequence[Any], head_sha: str, *, outdated: bool = False) -> bool:
    """True when a resolved thread has no authorized disposition for this HEAD.

    GitHub review replies keep the original review-commit OID, so an outdated
    thread cannot carry a live-HEAD commit on the reply. Live (non-outdated)
    threads still require the reply commit to equal the current HEAD. A bare
    acknowledgement is never a disposition; the reply body must carry a
    technical justification or evidence marker.
    """
    nodes = [item for item in comments if isinstance(item, Mapping)]
    if not nodes:
        return True
    head = str(head_sha or "")
    last_disposition_idx = None
    for idx, item in enumerate(nodes[1:], start=1):
        author = item.get("author") if isinstance(item.get("author"), Mapping) else {}
        login = str(author.get("login") or "")
        typename = str(author.get("__typename") or "")
        user_type = str(author.get("type") or "")
        if not is_authorized_disposition_author(login, typename=typename, user_type=user_type):
            continue
        body = str(item.get("body") or "")
        if not disposition_policy.is_valid_disposition_body(body, head_sha=head):
            continue
        reply_commit = comment_commit_oid(item)
        matches_head = bool(head and reply_commit == head)
        # Outdated threads keep the original review OID on replies. Accept only
        # when the body cites the current HEAD (already required above).
        outdated_ok = bool(
            outdated and head and disposition_policy.body_cites_sha(body, head)
        )
        if matches_head or outdated_ok:
            last_disposition_idx = idx
    if last_disposition_idx is None:
        return True
    # A later comment after the disposition reopens the thread for treatment.
    return last_disposition_idx < len(nodes) - 1


def reviews_for_head(reviews: Sequence[Mapping[str, Any]], head_sha: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for review in reviews or []:
        if not isinstance(review, Mapping):
            continue
        if str(review.get("commit_id") or "") != head_sha:
            continue
        out.append(dict(review))
    return out


def latest_copilot_review(
    reviews: Sequence[Mapping[str, Any]], head_sha: str
) -> dict[str, Any] | None:
    matched: list[dict[str, Any]] = []
    for review in reviews_for_head(reviews, head_sha):
        login = _login(review)
        if login in NON_REVIEWER_COPILOT_LOGINS:
            continue
        if _is_copilot(login):
            matched.append(review)
        elif _looks_like_copilot(login):
            review = dict(review)
            review["_unknown_copilot_identity"] = True
            matched.append(review)
    if not matched:
        return None
    matched.sort(key=lambda review: (int(review.get("id") or 0), str(review.get("submitted_at") or "")))
    return matched[-1]


def _review_recency_key(review: Mapping[str, Any]) -> tuple[int, str]:
    return (int(review.get("id") or 0), str(review.get("submitted_at") or ""))


def human_approved_on_head(
    reviews: Sequence[Mapping[str, Any]],
    head_sha: str,
    author_login: str = "",
) -> bool:
    author = str(author_login or "").casefold()
    latest: dict[str, Mapping[str, Any]] = {}
    for review in reviews_for_head(reviews, head_sha):
        login = _login(review)
        user = review.get("user") if isinstance(review.get("user"), Mapping) else {}
        if str(user.get("type") or "") != "User":
            continue
        if not login or _is_copilot(login) or _looks_like_copilot(login) or login.endswith("[bot]"):
            continue
        if author and login.casefold() == author:
            continue
        key = login.casefold()
        prev = latest.get(key)
        if prev is None or _review_recency_key(review) >= _review_recency_key(prev):
            latest[key] = review
    return any(
        str(review.get("state") or "").upper() == "APPROVED" for review in latest.values()
    )


def evaluate_final_review_gate(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Return commit-status fields bound to the current PR HEAD."""
    metrics = {
        "copilot_reviews_for_pr": 0,
        "copilot_reviews_for_head": 0,
        "correction_batches": 0,
        "bot_findings_before_copilot": 0,
        "copilot_findings_after_stabilization": 0,
    }

    if snapshot.get("api_error"):
        return _result(
            STATE_ERROR,
            ["GitHub API error"],
            snapshot,
            metrics,
            allow_publish=False,
        )

    head = str(snapshot.get("head_sha") or "")
    current = str(snapshot.get("current_head_sha") or "")
    if not head:
        return _result(
            STATE_ERROR,
            ["missing PR HEAD SHA"],
            snapshot,
            metrics,
            allow_publish=False,
        )
    if not current:
        return _result(
            STATE_ERROR,
            ["current HEAD SHA is missing"],
            snapshot,
            metrics,
            allow_publish=False,
        )
    if current and current != head:
        return _result(
            STATE_PENDING,
            [f"HEAD changed during evaluation ({head[:7]} -> {current[:7]}); refuse stale success"],
            snapshot,
            metrics,
            allow_publish=False,
            publish_sha=current,
        )

    reviews = snapshot.get("reviews")
    if not isinstance(reviews, list):
        return _result(
            STATE_ERROR,
            ["reviews snapshot is missing"],
            snapshot,
            metrics,
            allow_publish=False,
        )

    files = snapshot.get("changed_files")
    if not isinstance(files, list):
        return _result(
            STATE_ERROR,
            ["changed files snapshot is missing"],
            snapshot,
            metrics,
            allow_publish=False,
        )

    copilot_all = [
        r
        for r in reviews
        if isinstance(r, Mapping) and _is_copilot(_login(r))
    ]
    metrics["copilot_reviews_for_pr"] = len(copilot_all)
    metrics["copilot_reviews_for_head"] = len(
        [r for r in copilot_all if str(r.get("commit_id") or "") == head]
    )
    ledger = snapshot.get("finding_ledger") or []
    if isinstance(ledger, list):
        metrics["correction_batches"] = sum(int(item.get("attempts") or 0) for item in ledger if isinstance(item, Mapping))
    metrics["bot_findings_before_copilot"] = int(snapshot.get("bot_findings_before_copilot") or 0)
    metrics["copilot_findings_after_stabilization"] = int(
        snapshot.get("copilot_findings_after_stabilization") or 0
    )

    reasons: list[str] = []
    privileged = privileged_paths_changed(files)

    if snapshot.get("is_draft"):
        reasons.append("pull request is Draft")
        return _result(STATE_PENDING, reasons, snapshot, metrics, privileged=privileged)

    author = str(snapshot.get("pr_author_login") or "")
    if _is_copilot(author) or _looks_like_copilot(author):
        reasons.append("Copilot-authored pull requests cannot self-approve")
        return _result(STATE_FAILURE, reasons, snapshot, metrics, privileged=privileged)

    # Validate GraphQL provenance before the pre-Copilot short-circuit so
    # should_request_copilot cannot authorize from a REST-derived decision.
    if snapshot.get("review_decision_source") != "graphql":
        return _result(
            STATE_ERROR,
            ["reviewDecision must be fetched through GraphQL"],
            snapshot,
            metrics,
            allow_publish=False,
            privileged=privileged,
        )
    if snapshot.get("review_decision_unavailable"):
        return _result(
            STATE_ERROR,
            ["reviewDecision is unavailable"],
            snapshot,
            metrics,
            allow_publish=False,
            privileged=privileged,
        )

    if snapshot.get("snapshot_phase") == "pre_copilot_request":
        reasons.append("pre-Copilot snapshot cannot publish success")
        return _result(STATE_PENDING, reasons, snapshot, metrics, privileged=privileged, allow_publish=False)
    review_decision = str(snapshot.get("review_decision") or "").upper()
    if review_decision == "CHANGES_REQUESTED":
        reasons.append("active CHANGES_REQUESTED")
        return _result(STATE_FAILURE, reasons, snapshot, metrics, privileged=privileged)
    if review_decision != "APPROVED":
        reasons.append(f"reviewDecision is {review_decision or 'empty'}, not APPROVED")
        return _result(STATE_FAILURE, reasons, snapshot, metrics, privileged=privileged)
    if snapshot.get("requires_human") or snapshot.get("loop_guard") or snapshot.get("human_stop_review_ids"):
        reasons.append("persistent human stop is still active")
        return _result(STATE_FAILURE, reasons, snapshot, metrics, privileged=privileged)

    unresolved = snapshot.get("unresolved_threads")
    if not isinstance(unresolved, int) or unresolved < 0:
        return _result(
            STATE_ERROR,
            ["unresolved thread count is missing"],
            snapshot,
            metrics,
            allow_publish=False,
            privileged=privileged,
        )
    if unresolved > 0:
        reasons.append(f"unresolved review threads: {unresolved}")
        return _result(STATE_FAILURE, reasons, snapshot, metrics, privileged=privileged)
    untreated_threads = snapshot.get("untreated_threads")
    if not isinstance(untreated_threads, int) or untreated_threads < 0:
        return _result(
            STATE_ERROR,
            ["untreated thread count is missing"],
            snapshot,
            metrics,
            allow_publish=False,
            privileged=privileged,
        )
    if untreated_threads > 0:
        reasons.append(f"resolved threads without a current-HEAD disposition reply: {untreated_threads}")
        return _result(STATE_FAILURE, reasons, snapshot, metrics, privileged=privileged)

    untreated = []
    for key, label in (
        ("untreated_pr_level_findings", "PR-level finding"),
        ("previously_missed_titles", "Previously missed finding"),
        ("suppressed_comment_titles", "Suppressed comment"),
        ("open_finding_titles", "open finding"),
    ):
        values = snapshot.get(key)
        if values is None:
            continue
        if not isinstance(values, list):
            return _result(
                STATE_ERROR,
                [f"{key} snapshot is malformed"],
                snapshot,
                metrics,
                allow_publish=False,
                privileged=privileged,
            )
        untreated.extend(f"{label}: {item}" for item in values if item)
    if untreated:
        reasons.extend(untreated)
        return _result(STATE_FAILURE, reasons, snapshot, metrics, privileged=privileged)

    raw_checks = snapshot.get("required_checks")
    if not isinstance(raw_checks, list) or not raw_checks:
        return _result(
            STATE_ERROR,
            ["required checks snapshot is empty"],
            snapshot,
            metrics,
            allow_publish=False,
            privileged=privileged,
        )
    pending_ci = False
    failing_ci = False
    external_required = 0
    for check in raw_checks:
        if not isinstance(check, Mapping):
            return _result(
                STATE_ERROR,
                ["required check entry is malformed"],
                snapshot,
                metrics,
                allow_publish=False,
                privileged=privileged,
            )
        name = str(check.get("name") or "")
        if is_advisory_self_gate_check(check):
            continue
        external_required += 1
        state = str(check.get("state") or "").upper()
        if state in PENDING_CHECK_STATES or not state:
            pending_ci = True
            reasons.append(f"required check pending: {name or 'unknown'}")
        elif state not in GATE_PASSING_CHECK_STATES:
            failing_ci = True
            reasons.append(f"required check failing: {name} ({state})")
    if external_required == 0:
        return _result(
            STATE_ERROR,
            ["required checks snapshot has no external contexts"],
            snapshot,
            metrics,
            allow_publish=False,
            privileged=privileged,
        )
    if failing_ci:
        return _result(STATE_FAILURE, reasons, snapshot, metrics, privileged=privileged)
    if pending_ci:
        return _result(STATE_PENDING, reasons, snapshot, metrics, privileged=privileged)

    merge_state = str(snapshot.get("merge_state_status") or "").upper()
    if merge_state not in GATE_SUCCESS_MERGE_STATES:
        reasons.append(f"merge state not ready for gate success: {merge_state or '<missing>'}")
        return _result(STATE_FAILURE, reasons, snapshot, metrics, privileged=privileged)

    copilot = latest_copilot_review(reviews, head)
    if copilot and copilot.get("_unknown_copilot_identity"):
        return _result(
            STATE_ERROR,
            [f"unknown Copilot reviewer identity: {_login(copilot)}"],
            snapshot,
            metrics,
            allow_publish=False,
            privileged=privileged,
        )

    if snapshot.get("copilot_request_pending") and not copilot:
        reasons.append("Copilot review request is pending for this HEAD")
        return _result(STATE_PENDING, reasons, snapshot, metrics, privileged=privileged)

    if not copilot:
        reasons.append("no Copilot review on current HEAD")
        return _result(STATE_PENDING, reasons, snapshot, metrics, privileged=privileged)

    copilot_state = str(copilot.get("state") or "").upper()
    if copilot_state in {"PENDING", ""}:
        reasons.append("Copilot review is pending")
        return _result(STATE_PENDING, reasons, snapshot, metrics, privileged=privileged)
    if copilot_state == "CHANGES_REQUESTED":
        reasons.append("Copilot CHANGES_REQUESTED on current HEAD")
        return _result(STATE_FAILURE, reasons, snapshot, metrics, privileged=privileged)
    if copilot_state == "COMMENTED":
        reasons.append("Copilot COMMENTED is not APPROVED")
        return _result(STATE_FAILURE, reasons, snapshot, metrics, privileged=privileged)
    if copilot_state == "DISMISSED":
        reasons.append("Copilot review on current HEAD is dismissed")
        return _result(STATE_FAILURE, reasons, snapshot, metrics, privileged=privileged)
    if copilot_state != "APPROVED":
        reasons.append(f"Copilot review state {copilot_state} is not APPROVED")
        return _result(STATE_FAILURE, reasons, snapshot, metrics, privileged=privileged)

    if snapshot.get("classifier_missing"):
        return _result(
            STATE_ERROR,
            ["classify-copilot-review.py is missing on the trusted default branch"],
            snapshot,
            metrics,
            allow_publish=False,
            privileged=privileged,
        )
    classification = str(snapshot.get("copilot_classification") or "")
    if not classification:
        return _result(
            STATE_ERROR,
            ["Copilot classification is missing"],
            snapshot,
            metrics,
            allow_publish=False,
            privileged=privileged,
        )
    if classification in BLOCKING_COPILOT_CLASSIFICATIONS or classification not in SUCCESS_COPILOT_CLASSIFICATIONS:
        reasons.append(f"Copilot classification {classification} is not APPROVED")
        return _result(STATE_FAILURE, reasons, snapshot, metrics, privileged=privileged)

    if str(copilot.get("commit_id") or "") != head:
        reasons.append("Copilot review.commit_id does not match current HEAD")
        return _result(STATE_FAILURE, reasons, snapshot, metrics, privileged=privileged)

    if privileged and not human_approved_on_head(
        reviews, head, str(snapshot.get("pr_author_login") or "")
    ):
        reasons.append("privileged governance paths require independent human APPROVED")
        return _result(STATE_FAILURE, reasons, snapshot, metrics, privileged=True)

    return _result(
        STATE_SUCCESS,
        ["current HEAD has exact-SHA Copilot APPROVED and treated findings"],
        snapshot,
        metrics,
        privileged=privileged,
    )


def revalidate_gate_before_success(
    evaluated: Mapping[str, Any], live_snapshot: Mapping[str, Any]
) -> dict[str, Any]:
    """Fail closed: never publish SUCCESS from a stale pre-success snapshot."""
    live = evaluate_final_review_gate(live_snapshot)
    evaluated_head = str(evaluated.get("head_sha") or "")
    live_head = str(live_snapshot.get("current_head_sha") or live_snapshot.get("head_sha") or "")
    if str(evaluated.get("state") or "") != STATE_SUCCESS:
        return dict(evaluated)
    if not live_head or live_head != evaluated_head:
        live["state"] = STATE_PENDING
        live["allow_publish"] = False
        live["reasons"] = [f"HEAD changed during evaluation ({evaluated_head[:7]} -> {live_head[:7] or 'missing'}); refuse stale success"]
        live["reason"] = live["reasons"][0]
        return live
    if live.get("state") != STATE_SUCCESS:
        live["allow_publish"] = False
        return live
    copilot = latest_copilot_review(live_snapshot.get("reviews") or [], live_head)
    unresolved = live_snapshot.get("unresolved_threads")
    decision = str(live_snapshot.get("review_decision") or "").upper()
    if (
        not copilot
        or str(copilot.get("commit_id") or "") != live_head
        or not isinstance(unresolved, int)
        or unresolved > 0
        or decision == "CHANGES_REQUESTED"
    ):
        live["state"] = STATE_FAILURE if decision == "CHANGES_REQUESTED" or (isinstance(unresolved, int) and unresolved > 0) else STATE_PENDING
        live["allow_publish"] = False
        live["reasons"] = ["post-success revalidation failed; refuse stale success"]
        live["reason"] = live["reasons"][0]
        return live
    raw_checks = live_snapshot.get("required_checks")
    if not isinstance(raw_checks, list) or not raw_checks:
        live["state"] = STATE_ERROR
        live["allow_publish"] = False
        return live
    external_required = 0
    for check in raw_checks:
        if not isinstance(check, Mapping):
            continue
        if is_advisory_self_gate_check(check):
            continue
        external_required += 1
        state = str(check.get("state") or "").upper()
        if state in PENDING_CHECK_STATES or state not in GATE_PASSING_CHECK_STATES:
            live["state"] = STATE_PENDING if state in PENDING_CHECK_STATES else STATE_FAILURE
            live["allow_publish"] = False
            live["reasons"] = [f"required CI not green at publish: {check.get('name')}"]
            live["reason"] = live["reasons"][0]
            return live
    if external_required == 0:
        live["state"] = STATE_ERROR
        live["allow_publish"] = False
        live["reasons"] = ["required checks snapshot has no external contexts"]
        live["reason"] = live["reasons"][0]
        return live
    return live


def should_request_copilot(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """At most one accepted Copilot review request per SHA. Transport failures
    before a submitted review may retry because no review exists yet.
    """
    head = str(snapshot.get("head_sha") or "")
    current = str(snapshot.get("current_head_sha") or "")
    if not head or not current or current != head:
        return {"request": False, "reason": "HEAD snapshot is stale or incomplete"}
    if snapshot.get("review_decision_source") != "graphql":
        return {"request": False, "reason": "reviewDecision must be fetched through GraphQL"}
    if snapshot.get("review_decision_unavailable"):
        return {"request": False, "reason": "reviewDecision is unavailable"}
    gate = evaluate_final_review_gate(snapshot)
    reasons: list[str] = []
    if snapshot.get("is_draft"):
        return {"request": False, "reason": "Draft"}
    if snapshot.get("planned_push") or snapshot.get("local_changes"):
        return {"request": False, "reason": "HEAD not stable (planned push or local changes)"}
    if snapshot.get("copilot_request_pending"):
        return {"request": False, "reason": "Copilot request already pending for this HEAD"}
    reviews = snapshot.get("reviews") if isinstance(snapshot.get("reviews"), list) else []
    copilot = latest_copilot_review(reviews, head)
    if copilot and not copilot.get("_unknown_copilot_identity"):
        return {"request": False, "reason": "Copilot already reviewed this HEAD"}
    if snapshot.get("requires_human") or snapshot.get("loop_guard") or snapshot.get("human_stop_review_ids"):
        return {"request": False, "reason": "persistent human stop"}
    if gate["state"] in {STATE_ERROR}:
        return {"request": False, "reason": gate["reasons"][0] if gate["reasons"] else "fail closed"}
    if str(snapshot.get("review_decision") or "").upper() == "CHANGES_REQUESTED":
        return {"request": False, "reason": "CHANGES_REQUESTED"}
    unresolved = snapshot.get("unresolved_threads")
    if not isinstance(unresolved, int) or unresolved < 0:
        return {"request": False, "reason": "unresolved threads unknown"}
    if unresolved > 0:
        return {"request": False, "reason": "unresolved threads"}
    if not isinstance(snapshot.get("untreated_threads"), int) or snapshot["untreated_threads"] < 0:
        return {"request": False, "reason": "untreated threads unknown"}
    if snapshot["untreated_threads"] > 0:
        return {"request": False, "reason": "untreated threads"}
    untreated_keys = (
        "untreated_pr_level_findings",
        "previously_missed_titles",
        "open_finding_titles",
        "suppressed_comment_titles",
    )
    if any(snapshot.get(key) for key in untreated_keys):
        return {"request": False, "reason": "untreated findings remain"}
    merge_state = str(snapshot.get("merge_state_status") or "").upper()
    if merge_state not in REQUEST_MERGE_STATES:
        return {
            "request": False,
            "reason": f"merge state not ready for Copilot: {merge_state or '<missing>'}",
        }
    raw_checks = snapshot.get("required_checks")
    if not isinstance(raw_checks, list) or not raw_checks:
        return {"request": False, "reason": "required CI unknown"}
    external_required = 0
    for check in raw_checks:
        if not isinstance(check, Mapping):
            return {"request": False, "reason": "required CI unknown"}
        if is_advisory_self_gate_check(check):
            continue
        external_required += 1
        state = str(check.get("state") or "").upper()
        if state in PENDING_CHECK_STATES or state not in GATE_PASSING_CHECK_STATES:
            return {"request": False, "reason": f"required CI not green: {check.get('name')}"}
    if external_required == 0:
        return {"request": False, "reason": "required checks snapshot has no external contexts"}
    reasons.append("stable HEAD eligible for one Copilot request")
    return {"request": True, "reason": reasons[0]}


def _result(
    state: str,
    reasons: Sequence[str],
    snapshot: Mapping[str, Any],
    metrics: Mapping[str, Any],
    *,
    allow_publish: bool = True,
    publish_sha: str | None = None,
    privileged: bool = False,
) -> dict[str, Any]:
    head = str(snapshot.get("head_sha") or "")
    current = str(snapshot.get("current_head_sha") or head)
    sha = publish_sha or (current if allow_publish else head)
    if state == STATE_SUCCESS and (not allow_publish or sha != current or sha != head):
        state = STATE_PENDING
        reasons = list(reasons) + ["refusing success on mismatched HEAD"]
        allow_publish = False
    return {
        "context": GATE_CONTEXT,
        "state": state,
        "reasons": list(reasons),
        "reason": reasons[0] if reasons else "unknown",
        "head_sha": head,
        "publish_sha": sha,
        "allow_publish": bool(allow_publish and sha == str(snapshot.get("current_head_sha") or head)),
        "privileged_paths": privileged,
        "metrics": dict(metrics),
    }


def main() -> int:
    snapshot = json.load(sys.stdin)
    if not isinstance(snapshot, dict):
        raise SystemExit("snapshot JSON must be an object")
    mode = "evaluate"
    if len(sys.argv) > 1 and sys.argv[1] in {"--should-request", "--evaluate"}:
        mode = "request" if sys.argv[1] == "--should-request" else "evaluate"
    if mode == "request":
        payload = should_request_copilot(snapshot)
    else:
        payload = evaluate_final_review_gate(snapshot)
    sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
