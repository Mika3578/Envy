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
    r"(?i)(diff\s+(?:is\s+)?too\s+large|diff\s+exceeds\s+the\s+maximum|"
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
# Nested Copilot sections: "Previously missed (N)" and optional "Open findings (N)".
# Bodies are untrusted HTML; extract titles only (never execute). Nested
# <details> cannot be matched with a single non-greedy regex — use a depth walk.
_NAMED_DETAILS_SUMMARY = re.compile(
    r"<summary>\s*<strong>\s*(?P<label>Previously missed|Open findings|"
    r"Suppressed comments)\s*"
    r"\((?P<count>\d+)\)\s*</strong>\s*</summary>",
    re.I | re.S,
)
# Alternate layouts: ### Suppressed comments (N) or bare "Suppressed comments (N)"
_SUPPRESSED_HEADING = re.compile(
    r"(?im)^(?:###\s*)?Suppressed comments\s*\((\d+)\)\s*$"
)
_NESTED_DETAILS_SUMMARY = re.compile(
    r"<details>\s*<summary>(?P<summary>.*?)</summary>",
    re.I | re.S,
)
_HTML_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")
_PATH_LINE_REF = re.compile(
    r"(?i)(?<![\w./\\-])(?:[\w./\\-]+\.(?:py|ya?ml|md|cpp|h|hpp|c|cc|iss|json|xml|"
    r"sh|ps1|cmake|txt|bat|cmd)|\.editorconfig)\s*:\s*\d+\b"
)

_HUMAN_HINTS = re.compile(
    r"(?i)\b("
    r"maintainer(?:\s+only)?\s+(?:review|validation)\s+required|"
    r"human\s+validation|final\s+human|"
    r"subjective|governance\s+decision|policy\s+decision|"
    r"requires?\s+(?:a\s+)?human|manual\s+review\s+required|"
    r"require(?:s)?\s+human\s+review|"
    r"broad\s+(?:\w[\w/-]*)?(?:\s+)?(?:build|ci|workflow|governance)\s+changes|"
    r"broad\s+changes\s+require|"
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
_TECHNICAL_HINTS = re.compile(
    r"(?i)\b("
    r"must\s+be\s+(?:resolved|restricted|fixed|moved|capped|bounded)|"
    r"unresolved\s+(?:\w+\s+){0,6}issue|"
    r"self-?authorization|privileged\s+(?:review\s+)?workflow|"
    r"bypass(?:es|ing)?|"
    r"security\s+risk|authorization\s+risk|"
    r"incorrect|broken|regression|vulnerability|race\s+condition|"
    r"buffer\s+overflow|use-?after-?free|null\s+deref"
    r")\b",
)


@dataclass(frozen=True)
class ParsedOverview:
    assessment: str
    rationale: str
    review_effort: str | None
    finding_count: int | None
    resolved_titles: tuple[str, ...] = ()
    previously_missed_titles: tuple[str, ...] = ()
    body_open_finding_titles: tuple[str, ...] = ()
    suppressed_comment_titles: tuple[str, ...] = ()
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


def _titles_from_nested_details(block_body: str) -> tuple[str, ...]:
    """Extract nested finding titles from a Copilot <details> section body."""
    titles: list[str] = []
    for match in _NESTED_DETAILS_SUMMARY.finditer(block_body or ""):
        cleaned = _strip_html(match.group("summary"))
        cleaned = _WS.sub(" ", cleaned).strip()
        # Drop severity badge alt-text prefixes Copilot embeds in <img alt="...">.
        for prefix in (
            "Medium severity ",
            "High severity ",
            "Low severity ",
            "Critical severity ",
        ):
            if cleaned.startswith(prefix):
                cleaned = cleaned[len(prefix) :].strip()
                break
        lowered = cleaned.lower()
        if not cleaned:
            continue
        if lowered.startswith("previously missed") or lowered.startswith("open findings"):
            continue
        if lowered.startswith("suppressed comments"):
            continue
        if lowered.startswith("resolved since last review"):
            continue
        titles.append(cleaned)
    return tuple(titles)


def _titles_from_suppressed_heading_section(body: str) -> tuple[str, ...]:
    """Parse ### Suppressed comments (N) markdown lists (non-details layout)."""
    match = _SUPPRESSED_HEADING.search(body or "")
    if not match:
        return ()
    rest = body[match.end() :]
    # Stop at next markdown heading or details block.
    stop = re.search(r"(?m)^(###\s|\s*<details>)", rest)
    block = rest[: stop.start()] if stop else rest
    titles: list[str] = []
    for line in block.splitlines():
        cleaned = _strip_html(line).strip().lstrip("-•*").strip()
        if cleaned:
            titles.append(_WS.sub(" ", cleaned))
    return tuple(titles)


def _section_body_after_summary(body: str, summary_end: int) -> str:
    """Return the outer <details> body after a named summary (depth-aware)."""
    # Caller matched a <summary> that lives inside an already-open <details>.
    depth = 1
    i = summary_end
    lower = body.lower()
    while i < len(body) and depth > 0:
        open_idx = lower.find("<details", i)
        close_idx = lower.find("</details>", i)
        if close_idx < 0:
            return body[summary_end:]
        if open_idx >= 0 and open_idx < close_idx:
            depth += 1
            i = open_idx + len("<details")
            continue
        depth -= 1
        if depth == 0:
            return body[summary_end:close_idx]
        i = close_idx + len("</details>")
    return body[summary_end:]




def _named_section_nonzero_count(body: str, label: str) -> int | None:
    """Return N from '<label> (N)' headings when N > 0, else None."""
    wanted = label.lower()
    for match in _NAMED_DETAILS_SUMMARY.finditer(body or ""):
        if match.group("label").lower() != wanted:
            continue
        n = int(match.group("count"))
        return n if n > 0 else None
    return None

def _extract_named_details_titles(body: str, label: str) -> tuple[str, ...]:
    """Extract nested finding titles for Previously missed / Open findings."""
    wanted = label.lower()
    for match in _NAMED_DETAILS_SUMMARY.finditer(body or ""):
        if match.group("label").lower() != wanted:
            continue
        section = _section_body_after_summary(body, match.end())
        return _titles_from_nested_details(section)
    return ()


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

    if _ERROR_BODY.search(body):
        return ParsedOverview(ASSESSMENT_ERROR, body.strip(), None, None)

    if not _OVERVIEW_MARKER.search(body):
        if _QUOTA_BODY.search(body) and (
            "unable" in body.lower()
            or "cannot" in body.lower()
            or "error" in body.lower()
        ):
            return ParsedOverview(ASSESSMENT_ERROR, body.strip(), None, None)
        if _DIFF_TOO_LARGE_BODY.search(body):
            return ParsedOverview(ASSESSMENT_ERROR, body.strip(), None, None)
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
    if not findings_match:
        # Approved/Changes headings without **Findings:** are malformed; do not
        # treat finding_count=None as a clean overview.
        return ParsedOverview(assessment, rationale, None, None, malformed=True)

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

    previously_missed = _extract_named_details_titles(body, "Previously missed")
    body_open = _extract_named_details_titles(body, "Open findings")
    suppressed = _extract_named_details_titles(body, "Suppressed comments")
    if not suppressed:
        suppressed = _titles_from_suppressed_heading_section(body)

    # A nonzero Previously missed / Suppressed count without extractable titles
    # must not collapse to a clean Approved overview.
    for label, titles in (
        ("Previously missed", previously_missed),
        ("Suppressed comments", suppressed),
        ("Open findings", body_open),
    ):
        count = _named_section_nonzero_count(body, label)
        if count is not None and not titles:
            return ParsedOverview(
                assessment, rationale, effort, finding_count, malformed=True
            )
    # Alternate markdown heading form: ### Suppressed comments (N)
    alt = _SUPPRESSED_HEADING.search(body or "")
    if alt is not None and int(alt.group(1)) > 0 and not suppressed:
        return ParsedOverview(
            assessment, rationale, effort, finding_count, malformed=True
        )

    return ParsedOverview(
        assessment=assessment,
        rationale=rationale,
        review_effort=effort,
        finding_count=finding_count,
        resolved_titles=tuple(resolved),
        previously_missed_titles=previously_missed,
        body_open_finding_titles=body_open,
        suppressed_comment_titles=suppressed,
    )


def _merge_finding_titles(
    parsed: ParsedOverview, inline_titles: Sequence[str]
) -> tuple[str, ...]:
    """Inline + Open findings + Previously missed + Suppressed comments."""
    merged: list[str] = []
    seen: set[str] = set()
    for title in (
        *inline_titles,
        *parsed.body_open_finding_titles,
        *parsed.previously_missed_titles,
        *parsed.suppressed_comment_titles,
    ):
        key = _normalize_rationale(title)
        if not key or key in seen:
            continue
        seen.add(key)
        merged.append(title)
    return tuple(merged)


def _effective_finding_count(
    parsed: ParsedOverview, merged_titles: Sequence[str]
) -> int:
    if merged_titles:
        return len(merged_titles)
    if parsed.finding_count is not None:
        return parsed.finding_count
    return 0


def _rationale_has_technical_issue(rationale: str) -> bool:
    if not rationale:
        return False
    if _PATH_LINE_REF.search(rationale):
        return True
    if _TECHNICAL_HINTS.search(rationale):
        return True
    # Concrete file/path tokens without a line number still count.
    if re.search(
        r"(?i)\b[\w./\\-]+\.(?:py|ya?ml|md|cpp|h|hpp|c|cc|iss|json|xml|"
        r"editorconfig|sh|ps1|pot)\b",
        rationale,
    ):
        return True
    return False


def classify_review(review: ReviewInput) -> dict[str, Any]:
    if review.reviewer_login not in {
            COPILOT_REVIEWER_LOGIN, "Copilot", "copilot-pull-request-reviewer"}:
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

    merged_titles = _merge_finding_titles(parsed, review.open_finding_titles)
    open_count = _effective_finding_count(parsed, merged_titles)
    github_state = (review.github_review_state or "").upper()
    rationale = parsed.rationale or ""
    has_technical = _rationale_has_technical_issue(rationale)
    has_human = bool(rationale and _HUMAN_HINTS.search(rationale))
    has_validation = bool(rationale and _VALIDATION_HINTS.search(rationale))

    # Findings count wins over Approved headings: Findings: N with open_count>0
    # must not classify as APPROVED even when GitHub state is APPROVED.
    if open_count > 0 or parsed.assessment == ASSESSMENT_CHANGES_RECOMMENDED:
        # Previously missed / Open findings / inline comments / Changes recommended
        # are all fixer work. Findings: None does not hide Previously missed.
        classification = CLASSIFICATION_ACTIONABLE_FINDINGS
        requires_fixer = True
        requires_human = False
    elif github_state == "APPROVED" and parsed.assessment == ASSESSMENT_APPROVED:
        # Approved heading/state is not enough: human-validation, missing
        # evidence, or named technical issues in the free-text rationale must
        # disqualify the approval fast path.
        if has_technical:
            classification = CLASSIFICATION_CLOSER_LOOK_DIAGNOSTIC
            requires_fixer = True
            requires_human = False
        elif has_validation:
            classification = CLASSIFICATION_VALIDATION_MISSING
            requires_fixer = False
            requires_human = True
        elif has_human:
            classification = CLASSIFICATION_HUMAN_REQUIRED
            requires_fixer = False
            requires_human = True
        else:
            classification = CLASSIFICATION_APPROVED
            requires_fixer = False
            requires_human = False
    elif parsed.assessment == ASSESSMENT_NEEDS_CLOSER_LOOK and open_count == 0:
        # unresolved_threads=0 and Findings: None are NOT "PR clean".
        # Named technical issues in the free-text rationale are fixer work.
        # Pure "broad changes require human review" (no concrete defect) stops
        # the automation loop.
        if has_technical:
            classification = CLASSIFICATION_CLOSER_LOOK_DIAGNOSTIC
            requires_fixer = True
            requires_human = False
        elif has_human and not has_technical:
            classification = CLASSIFICATION_HUMAN_REQUIRED
            requires_fixer = False
            requires_human = True
        elif has_validation:
            classification = CLASSIFICATION_VALIDATION_MISSING
            requires_fixer = False
            requires_human = True
        elif "approved" in body_lower and github_state != "APPROVED":
            classification = CLASSIFICATION_CLOSER_LOOK_DIAGNOSTIC
            requires_fixer = False
            requires_human = True
        else:
            # Unclassified/uncertain closer-look rationale is human work, not
            # an automatic correction batch without a concrete defect signal.
            classification = CLASSIFICATION_HUMAN_REQUIRED
            requires_fixer = False
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

    if requires_fixer and (has_human or has_validation):
        # Technical work does not clear an independent human/evidence blocker.
        requires_human = True

    return _result(
        review,
        assessment=parsed.assessment,
        classification=classification,
        requires_fixer=requires_fixer,
        requires_human=requires_human,
        parsed=parsed,
        open_finding_count=open_count,
        merged_finding_titles=merged_titles,
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
    merged_finding_titles: Sequence[str] | None = None,
) -> dict[str, Any]:
    rationale = parsed.rationale if parsed else ""
    finding_count = open_finding_count
    if finding_count is None and parsed and parsed.finding_count is not None:
        finding_count = parsed.finding_count
    if finding_count is None:
        finding_count = len(review.open_finding_titles)

    titles = list(merged_finding_titles) if merged_finding_titles is not None else list(
        review.open_finding_titles
    )

    return {
        "review_id": str(review.review_id),
        "submitted_at": review.submitted_at,
        "head_sha": review.head_sha,
        "github_review_state": review.github_review_state,
        "reviewer_login": review.reviewer_login,
        "assessment": assessment,
        "review_effort": parsed.review_effort if parsed else None,
        "finding_count": finding_count,
        "open_finding_titles": titles,
        "previously_missed_titles": list(parsed.previously_missed_titles)
        if parsed
        else [],
        "suppressed_comment_titles": list(parsed.suppressed_comment_titles)
        if parsed
        else [],
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
        guarded["loop_guard"] = "repeat_closer_look_requires_changed_diagnosis"
        guarded["requires_human"] = True
        guarded["requires_fixer"] = False
        review_id = str(guarded.get("review_id") or "unknown")
        stops = [str(x) for x in (guarded.get("human_stop_review_ids") or [])]
        if review_id not in stops:
            stops.append(review_id)
        guarded["human_stop_review_ids"] = stops
    stops = []
    for prior in prior_outcomes:
        if prior.get("classification") not in {CLASSIFICATION_HUMAN_REQUIRED, CLASSIFICATION_VALIDATION_MISSING}:
            continue
        disposition = prior.get("human_disposition") or {}
        if (disposition.get("actor") == "Mika3578" and disposition.get("status") == "resolved"
                and str(disposition.get("evidence") or "").strip()):
            continue
        stops.append(str(prior.get("review_id") or "unknown"))
    if stops:
        guarded["requires_human"] = True
        guarded["human_stop_review_ids"] = stops
        guarded["loop_guard"] = "persistent_human_decision"
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
