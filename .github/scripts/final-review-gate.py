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
from typing import Any, Mapping, Sequence

GATE_CONTEXT = "Final review gate"

STATE_SUCCESS = "success"
STATE_FAILURE = "failure"
STATE_PENDING = "pending"
STATE_ERROR = "error"

COPILOT_LOGINS = frozenset(
    {
        "Copilot",
        "copilot-pull-request-reviewer",
        "copilot-pull-request-reviewer[bot]",
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
)

PASSING_CHECK_STATES = frozenset({"SUCCESS", "NEUTRAL", "SKIPPED"})
PENDING_CHECK_STATES = frozenset(
    {"PENDING", "QUEUED", "IN_PROGRESS", "WAITING", "REQUESTED", "EXPECTED"}
)

RETRYABLE_COPILOT = frozenset(
    {"COPILOT_QUOTA_BLOCKED", "COPILOT_DIFF_TOO_LARGE", "REVIEW_ERROR"}
)


def is_privileged_path(path: str) -> bool:
    normalized = (path or "").replace("\\", "/").lstrip("/")
    if normalized in PRIVILEGED_PATHS:
        return True
    return any(normalized.startswith(prefix) for prefix in PRIVILEGED_PREFIXES)


def privileged_paths_changed(files: Sequence[Any]) -> bool:
    for item in files or []:
        if isinstance(item, str):
            if is_privileged_path(item):
                return True
            continue
        if isinstance(item, Mapping) and is_privileged_path(str(item.get("path") or "")):
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
    lowered = login.lower()
    return "copilot" in lowered and "swe-agent" not in lowered


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
        if _is_copilot(login):
            matched.append(review)
        elif _looks_like_copilot(login):
            review = dict(review)
            review["_unknown_copilot_identity"] = True
            matched.append(review)
    if not matched:
        return None
    return matched[-1]


def human_approved_on_head(
    reviews: Sequence[Mapping[str, Any]], head_sha: str
) -> bool:
    for review in reviews_for_head(reviews, head_sha):
        login = _login(review)
        if not login or _is_copilot(login) or login.endswith("[bot]"):
            continue
        if str(review.get("state") or "").upper() == "APPROVED":
            return True
    return False


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
    current = str(snapshot.get("current_head_sha") or head)
    if not head:
        return _result(
            STATE_ERROR,
            ["missing PR HEAD SHA"],
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

    review_decision = str(snapshot.get("review_decision") or "").upper()
    if review_decision == "CHANGES_REQUESTED":
        reasons.append("active CHANGES_REQUESTED")
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
        if name == GATE_CONTEXT:
            continue
        state = str(check.get("state") or "").upper()
        if state in PENDING_CHECK_STATES or not state:
            pending_ci = True
            reasons.append(f"required check pending: {name or 'unknown'}")
        elif state not in PASSING_CHECK_STATES:
            failing_ci = True
            reasons.append(f"required check failing: {name} ({state})")
    if failing_ci:
        return _result(STATE_FAILURE, reasons, snapshot, metrics, privileged=privileged)
    if pending_ci:
        return _result(STATE_PENDING, reasons, snapshot, metrics, privileged=privileged)

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

    if str(copilot.get("commit_id") or "") != head:
        reasons.append("Copilot review.commit_id does not match current HEAD")
        return _result(STATE_FAILURE, reasons, snapshot, metrics, privileged=privileged)

    if privileged and not human_approved_on_head(reviews, head):
        reasons.append("privileged governance paths require independent human APPROVED")
        return _result(STATE_FAILURE, reasons, snapshot, metrics, privileged=True)

    return _result(
        STATE_SUCCESS,
        ["current HEAD has exact-SHA Copilot APPROVED and treated findings"],
        snapshot,
        metrics,
        privileged=privileged,
    )


def should_request_copilot(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """At most one final Copilot request per SHA unless a retryable error."""
    gate = evaluate_final_review_gate(snapshot)
    head = str(snapshot.get("head_sha") or "")
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
        classification = str(snapshot.get("copilot_classification") or "")
        if classification in RETRYABLE_COPILOT:
            return {"request": True, "reason": f"retryable Copilot outcome {classification}"}
        return {"request": False, "reason": "Copilot already reviewed this HEAD"}
    if gate["state"] in {STATE_ERROR}:
        return {"request": False, "reason": gate["reasons"][0] if gate["reasons"] else "fail closed"}
    if str(snapshot.get("review_decision") or "").upper() == "CHANGES_REQUESTED":
        return {"request": False, "reason": "CHANGES_REQUESTED"}
    if int(snapshot.get("unresolved_threads") or 0) > 0:
        return {"request": False, "reason": "unresolved threads"}
    untreated_keys = (
        "untreated_pr_level_findings",
        "previously_missed_titles",
        "open_finding_titles",
    )
    if any(snapshot.get(key) for key in untreated_keys):
        return {"request": False, "reason": "untreated findings remain"}
    raw_checks = snapshot.get("required_checks")
    if not isinstance(raw_checks, list) or not raw_checks:
        return {"request": False, "reason": "required CI unknown"}
    for check in raw_checks:
        if not isinstance(check, Mapping):
            return {"request": False, "reason": "required CI unknown"}
        if str(check.get("name") or "") == GATE_CONTEXT:
            continue
        state = str(check.get("state") or "").upper()
        if state in PENDING_CHECK_STATES or state not in PASSING_CHECK_STATES:
            return {"request": False, "reason": f"required CI not green: {check.get('name')}"}
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
