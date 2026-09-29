#!/usr/bin/env python3
"""Deterministic classifier for GitHub Copilot Code Review overview reviews.

Parses the submitted review body and optional inline review comments as
untrusted text. Never executes or shell-interpolate review content.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

COPILOT_REVIEWER_LOGIN = "copilot-pull-request-reviewer[bot]"

ASSESSMENT_APPROVED = "APPROVED"
ASSESSMENT_APPROVAL_RECOMMENDED = "APPROVAL_RECOMMENDED"
ASSESSMENT_CHANGES_RECOMMENDED = "CHANGES_RECOMMENDED"
ASSESSMENT_NEEDS_CLOSER_LOOK = "NEEDS_CLOSER_LOOK"
ASSESSMENT_ERROR = "ERROR"
ASSESSMENT_UNKNOWN = "UNKNOWN"

CLASSIFICATION_APPROVED = "APPROVED"
CLASSIFICATION_ACTIONABLE_FINDINGS = "ACTIONABLE_FINDINGS"
CLASSIFICATION_CLOSER_LOOK_DIAGNOSTIC = "CLOSER_LOOK_DIAGNOSTIC"
CLASSIFICATION_VALIDATION_MISSING = "VALIDATION_MISSING"
CLASSIFICATION_HUMAN_REQUIRED = "HUMAN_REQUIRED"
CLASSIFICATION_REVIEW_ERROR = "REVIEW_ERROR"
CLASSIFICATION_QUOTA_BLOCKED = "COPILOT_QUOTA_BLOCKED"
CLASSIFICATION_DIFF_TOO_LARGE = "COPILOT_DIFF_TOO_LARGE"
CLASSIFICATION_NON_COPILOT = "NON_COPILOT"
CLASSIFICATION_MALFORMED = "MALFORMED"

_OVERVIEW_MARKER = re.compile(r"<!--\s*ccr-overview-v2\s*-->", re.I)
_ERROR_BODY = re.compile(
    r"^Copilot encountered an error and was unable to review",
    re.I | re.M,
)
_QUOTA_BODY = re.compile(
    r"(?i)\b(quota|rate\s*limit|usage\s*limit)\b",
)
_DIFF_TOO_LARGE_BODY = re.compile(
    r"(?i)(too\s+large|diff\s+is\s+too\s+large|exceeds\s+the\s+maximum|"
    r"unable\s+to\s+review\s+because.{0,40}size)",
)
_HEADING = re.compile(
    r"^###\s*(?:\S+\s+)?(?P<label>Approved|Approval recommended|"
    r"Changes recommended|Needs a closer look)\s*$",
    re.I | re.M,
)
_EFFORT_LINE = re.compile(r"^\*\*Review effort:\*\*", re.I | re.M)
_FINDINGS = re.compile(
    r"\*\*Findings:\*\*\s*(?P<count>None|\d+)",
    re.I,
)
_RESOLVED_BLOCK = re.compile(
    r"<details>\s*<summary>\s*<strong>\s*Resolved since last review\s*\((\d+)\)\s*"
    r"</strong>\s*</summary>(?P<body>.*?)</details>",
    re.I | re.S,
)
_HTML_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")

_HUMAN_HINTS = re.compile(
    r"(?i)\b("
    r"maintainer(?:\s+only)?\s+(?:review|validation)\s+required|"
    r"human\s+validation|final\s+human|"
    r"subjective|governance\s+decision|policy\s+decision|"
    r"requires?\s+(?:a\s+)?human|manual\s+review\s+required|"
    r"out\s+of\s+scope\s+for\s+automation"
    r")\b",
)
_VALIDATION_HINTS = re.compile(
    r"(?i)\b("
    r"missing\s+(?:test|validation|evidence|proof|artifact|build)|"
    r"not\s+(?:yet\s+)?(?:validated|verified|tested)|"
    r"run\s+(?:the\s+)?(?:full\s+)?(?:build|tests?)|"
    r"workflow\s+(?:must|should)\s+(?:run|pass)|"
    r"no\s+evidence\s+(?:that|of)|"
    r"requires?\s+(?:runtime|live)\s+test"
    r")\b",
)


@dataclass(frozen=True)
class ParsedOverview:
    assessment: str
    rationale: str
    review_effort: str | None
    finding_count: int | None
    resolved_titles: tuple[str, ...] = ()
    malformed: bool = False


@dataclass
class ReviewInput:
    review_id: str
    submitted_at: str | None
    head_sha: str | None
    github_review_state: str
    reviewer_login: str
    body: str
    open_finding_titles: tuple[str, ...] = ()
    prior_review_ids: tuple[str, ...] = ()


def _strip_html(text: str) -> str:
    return _HTML_TAG.sub("", text).strip()


def _normalize_rationale(text: str) -> str:
    return _WS.sub(" ", text.strip().lower())


def rationale_fingerprint(rationale: str) -> str:
    digest = hashlib.sha256(_normalize_rationale(rationale).encode("utf-8"))
    return digest.hexdigest()[:16]


def _label_to_assessment(label: str) -> str:
    key = label.strip().lower()
    if key == "approved":
        return ASSESSMENT_APPROVED
    if key == "approval recommended":
        return ASSESSMENT_APPROVAL_RECOMMENDED
    if key == "changes recommended":
        return ASSESSMENT_CHANGES_RECOMMENDED
    if key == "needs a closer look":
        return ASSESSMENT_NEEDS_CLOSER_LOOK
    return ASSESSMENT_UNKNOWN


def parse_copilot_overview(body: str) -> ParsedOverview:
    if not body or not body.strip():
        return ParsedOverview(ASSESSMENT_UNKNOWN, "", None, None, malformed=True)

    if _QUOTA_BODY.search(body) and (
        "unable" in body.lower() or "cannot" in body.lower() or "error" in body.lower()
    ):
        return ParsedOverview(ASSESSMENT_ERROR, body.strip(), None, None)

    if _DIFF_TOO_LARGE_BODY.search(body):
        return ParsedOverview(ASSESSMENT_ERROR, body.strip(), None, None)

    if _ERROR_BODY.search(body):
        return ParsedOverview(ASSESSMENT_ERROR, body.strip(), None, None)

    if not _OVERVIEW_MARKER.search(body):
        return ParsedOverview(ASSESSMENT_UNKNOWN, body.strip(), None, None, malformed=True)

    heading = _HEADING.search(body)
    if not heading:
        return ParsedOverview(ASSESSMENT_UNKNOWN, body.strip(), None, None, malformed=True)

    assessment = _label_to_assessment(heading.group("label"))
    after_heading = body[heading.end() :]
    effort_match = _EFFORT_LINE.search(after_heading)
    if not effort_match:
        rationale = _strip_html(after_heading).strip()
        return ParsedOverview(assessment, rationale, None, None, malformed=True)

    rationale_raw = after_heading[: effort_match.start()]
    rationale = _strip_html(rationale_raw).strip()

    tail = after_heading[effort_match.start() :]
    findings_match = _FINDINGS.search(tail)
    finding_count: int | None = None
    if findings_match:
        token = findings_match.group("count")
        finding_count = 0 if token.lower() == "none" else int(token)

    effort_line = tail.splitlines()[0] if tail else ""
    effort = effort_line.replace("**Review effort:**", "").strip() or None

    resolved: list[str] = []
    resolved_match = _RESOLVED_BLOCK.search(body)
    if resolved_match:
        block = _strip_html(resolved_match.group("body"))
        for line in block.splitlines():
            cleaned = line.strip().lstrip("-•").strip()
            if cleaned:
                resolved.append(cleaned)

    return ParsedOverview(
        assessment=assessment,
        rationale=rationale,
        review_effort=effort,
        finding_count=finding_count,
        resolved_titles=tuple(resolved),
    )


def _effective_finding_count(
    parsed: ParsedOverview, open_titles: Sequence[str]
) -> int:
    if open_titles:
        return len(open_titles)
    if parsed.finding_count is not None:
        return parsed.finding_count
    return 0


def classify_review(review: ReviewInput) -> dict[str, Any]:
    if review.reviewer_login != COPILOT_REVIEWER_LOGIN:
        return _result(
            review,
            assessment=ASSESSMENT_UNKNOWN,
            classification=CLASSIFICATION_NON_COPILOT,
            requires_fixer=False,
            requires_human=False,
            parsed=None,
        )

    parsed = parse_copilot_overview(review.body)
    body_lower = (review.body or "").lower()

    if parsed.assessment == ASSESSMENT_ERROR:
        if _QUOTA_BODY.search(review.body or ""):
            error_class = CLASSIFICATION_QUOTA_BLOCKED
        elif _DIFF_TOO_LARGE_BODY.search(review.body or ""):
            error_class = CLASSIFICATION_DIFF_TOO_LARGE
        else:
            error_class = CLASSIFICATION_REVIEW_ERROR
        return _result(
            review,
            assessment=ASSESSMENT_ERROR,
            classification=error_class,
            requires_fixer=False,
            requires_human=True,
            parsed=parsed,
        )

    if parsed.malformed:
        return _result(
            review,
            assessment=parsed.assessment,
            classification=CLASSIFICATION_MALFORMED,
            requires_fixer=False,
            requires_human=True,
            parsed=parsed,
        )

    open_count = _effective_finding_count(parsed, review.open_finding_titles)
    github_state = (review.github_review_state or "").upper()

    # Text containing "Approved" is never enough; GitHub state is authoritative.
    if github_state == "APPROVED" and parsed.assessment == ASSESSMENT_APPROVED:
        classification = CLASSIFICATION_APPROVED
        requires_fixer = False
        requires_human = False
    elif open_count > 0 or parsed.assessment == ASSESSMENT_CHANGES_RECOMMENDED:
        classification = CLASSIFICATION_ACTIONABLE_FINDINGS
        requires_fixer = True
        requires_human = False
    elif parsed.assessment == ASSESSMENT_NEEDS_CLOSER_LOOK and open_count == 0:
        # Findings: None must not trigger arbitrary code churn. Stop with a
        # diagnostic for human/stabilizer confirmation instead.
        classification = CLASSIFICATION_CLOSER_LOOK_DIAGNOSTIC
        requires_fixer = False
        requires_human = True
        if parsed.rationale and _HUMAN_HINTS.search(parsed.rationale):
            classification = CLASSIFICATION_HUMAN_REQUIRED
        elif parsed.rationale and _VALIDATION_HINTS.search(parsed.rationale):
            classification = CLASSIFICATION_VALIDATION_MISSING
        elif "approved" in body_lower and github_state != "APPROVED":
            # Guard against mistaking assessment/body wording for approval.
            requires_human = True
    elif parsed.assessment in (
        ASSESSMENT_APPROVAL_RECOMMENDED,
        ASSESSMENT_APPROVED,
    ):
        # Assessment green without GitHub APPROVED is not merge approval.
        classification = CLASSIFICATION_HUMAN_REQUIRED
        requires_fixer = False
        requires_human = True
    else:
        classification = CLASSIFICATION_MALFORMED
        requires_fixer = False
        requires_human = True

    return _result(
        review,
        assessment=parsed.assessment,
        classification=classification,
        requires_fixer=requires_fixer,
        requires_human=requires_human,
        parsed=parsed,
        open_finding_count=open_count,
    )


def _result(
    review: ReviewInput,
    *,
    assessment: str,
    classification: str,
    requires_fixer: bool,
    requires_human: bool,
    parsed: ParsedOverview | None,
    open_finding_count: int | None = None,
) -> dict[str, Any]:
    rationale = parsed.rationale if parsed else ""
    finding_count = open_finding_count
    if finding_count is None and parsed and parsed.finding_count is not None:
        finding_count = parsed.finding_count
    if finding_count is None:
        finding_count = len(review.open_finding_titles)

    return {
        "review_id": str(review.review_id),
        "submitted_at": review.submitted_at,
        "head_sha": review.head_sha,
        "github_review_state": review.github_review_state,
        "reviewer_login": review.reviewer_login,
        "assessment": assessment,
        "review_effort": parsed.review_effort if parsed else None,
        "finding_count": finding_count,
        "open_finding_titles": list(review.open_finding_titles),
        "resolved_since_last_titles": list(parsed.resolved_titles) if parsed else [],
        "rationale": rationale,
        "rationale_fingerprint": rationale_fingerprint(rationale) if rationale else "",
        "classification": classification,
        "requires_fixer": requires_fixer,
        "requires_human": requires_human,
        "prior_review_ids": list(review.prior_review_ids),
    }


def review_input_from_github(
    review: Mapping[str, Any],
    *,
    open_finding_titles: Iterable[str] = (),
    prior_review_ids: Iterable[str] = (),
) -> ReviewInput:
    user = review.get("user") or {}
    return ReviewInput(
        review_id=str(review.get("id", "")),
        submitted_at=review.get("submitted_at"),
        head_sha=review.get("commit_id"),
        github_review_state=str(review.get("state", "")),
        reviewer_login=str(user.get("login", "")),
        body=str(review.get("body") or ""),
        open_finding_titles=tuple(open_finding_titles),
        prior_review_ids=tuple(str(x) for x in prior_review_ids),
    )


def detect_repeat_closer_look(
    current: dict[str, Any], prior_outcomes: Sequence[Mapping[str, Any]]
) -> bool:
    """True when the same HEAD and rationale fingerprint repeats closer-look with no findings."""
    if current.get("classification") != CLASSIFICATION_CLOSER_LOOK_DIAGNOSTIC:
        return False
    head = current.get("head_sha")
    fp = current.get("rationale_fingerprint")
    if not head or not fp:
        return False
    for prior in prior_outcomes:
        if (
            prior.get("head_sha") == head
            and prior.get("rationale_fingerprint") == fp
            and prior.get("classification") == CLASSIFICATION_CLOSER_LOOK_DIAGNOSTIC
            and prior.get("finding_count", 0) == 0
            and prior.get("review_id") != current.get("review_id")
        ):
            return True
    return False


def apply_loop_guards(
    outcome: dict[str, Any], prior_outcomes: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    guarded = dict(outcome)
    if detect_repeat_closer_look(guarded, prior_outcomes):
        guarded["classification"] = CLASSIFICATION_HUMAN_REQUIRED
        guarded["requires_human"] = True
        guarded["requires_fixer"] = False
        guarded["loop_guard"] = "repeat_closer_look_same_head"
    return guarded


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--review-json",
        default="-",
        choices=["-"],
        help="Read GitHub review object JSON from stdin (only '-' is supported)",
    )
    parser.add_argument(
        "--open-findings-json",
        default="[]",
        help="JSON array of open inline finding titles",
    )
    parser.add_argument(
        "--prior-outcomes-json",
        default="[]",
        help="JSON array of prior machine outcomes for loop detection",
    )
    args = parser.parse_args(argv)

    review_raw = _load_review_json()
    open_titles = json.loads(args.open_findings_json)
    prior_outcomes = json.loads(args.prior_outcomes_json)
    if not isinstance(open_titles, list):
        raise SystemExit("open-findings-json must be a JSON array")
    if not isinstance(prior_outcomes, list):
        raise SystemExit("prior-outcomes-json must be a JSON array")

    review = review_input_from_github(
        review_raw,
        open_finding_titles=[str(x) for x in open_titles],
        prior_review_ids=[
            str(x.get("review_id", "")) for x in prior_outcomes if x.get("review_id")
        ],
    )
    outcome = classify_review(review)
    outcome = apply_loop_guards(outcome, prior_outcomes)

    payload = json.dumps(outcome, indent=2, ensure_ascii=False) + "\n"
    sys.stdout.write(payload)
    return 0


def _load_review_json() -> dict[str, Any]:
    data = json.load(sys.stdin)
    if not isinstance(data, dict):
        raise SystemExit("review JSON must be an object")
    return data


if __name__ == "__main__":
    raise SystemExit(main())
