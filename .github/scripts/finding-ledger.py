#!/usr/bin/env python3
"""Small persistent finding ledger helpers for the correction loop.

Conversation-scoped JSON only. Does not approve, merge, or call GitHub.
Fingerprint = sha256(normalized source|path|title)[:16].
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Mapping, MutableMapping, Sequence

STATUS_OPEN = "open"
STATUS_FIXED_PENDING = "fixed_pending_rereview"
STATUS_RESOLVED = "resolved"
STATUS_NEEDS_HUMAN = "needs_human"

# Policy aliases used by the stabilizer ledger (stored as canonical statuses).
POLICY_STATUS = {
    "NEW": STATUS_OPEN,
    "VALID": STATUS_OPEN,
    "FIXED": STATUS_FIXED_PENDING,
    "JUSTIFIED": STATUS_RESOLVED,
    "RESOLVED": STATUS_RESOLVED,
    "RECURRED": STATUS_OPEN,
    "NEEDS_HUMAN": STATUS_NEEDS_HUMAN,
    STATUS_OPEN: STATUS_OPEN,
    STATUS_FIXED_PENDING: STATUS_FIXED_PENDING,
    STATUS_RESOLVED: STATUS_RESOLVED,
    STATUS_NEEDS_HUMAN: STATUS_NEEDS_HUMAN,
}


def canonical_status(status: str) -> str:
    key = str(status or "").strip()
    if key in POLICY_STATUS:
        return POLICY_STATUS[key]
    raised = key.upper()
    if raised in POLICY_STATUS:
        return POLICY_STATUS[raised]
    raise ValueError(f"unknown finding status: {status}")

MAX_AUTOFIX_ATTEMPTS = None


def check_review_history(
    reviews: Any, current_review_id: int, prior_outcomes: Any
) -> int:
    """Reject missing durable state even when prior reviews target older HEADs."""
    if not isinstance(reviews, list):
        raise ValueError("review history JSON must be an array")
    if isinstance(current_review_id, bool) or current_review_id <= 0:
        raise ValueError("review ID must be positive")
    if not isinstance(prior_outcomes, list):
        raise ValueError("Complete prior outcome records are required; refusing to reset correction history")
    covered = set()
    for outcome in prior_outcomes:
        if (not isinstance(outcome, Mapping) or not str(outcome.get("review_id") or "").isdigit()
                or not isinstance(outcome.get("finding_ledger"), list)
                or not isinstance(outcome.get("classification"), str)
                or not outcome.get("classification") or not isinstance(outcome.get("head_sha"), str)
                or not outcome.get("head_sha")):
            raise ValueError("Invalid durable outcome schema")
        review_id = int(outcome["review_id"])
        if review_id <= 0 or review_id in covered:
            raise ValueError("Duplicate or invalid durable review ID")
        covered.add(review_id)
        for entry in outcome["finding_ledger"]:
            if (not isinstance(entry, Mapping) or not entry.get("fingerprint")
                    or isinstance(entry.get("attempts"), bool) or not isinstance(entry.get("attempts"), int)
                    or entry["attempts"] < 0 or entry.get("status") not in {
                        STATUS_OPEN, STATUS_FIXED_PENDING, STATUS_RESOLVED, STATUS_NEEDS_HUMAN}):
                raise ValueError("Invalid durable finding schema")
    prior_ids = set()
    for review in reviews:
        if not isinstance(review, Mapping) or not isinstance(review.get("user"), Mapping):
            raise ValueError("review history contains an invalid review")
        if review["user"].get("login") not in {
                "Copilot", "copilot-pull-request-reviewer", "copilot-pull-request-reviewer[bot]"}:
            continue
        review_id = review.get("id")
        if isinstance(review_id, bool) or not isinstance(review_id, int) or review_id <= 0:
            raise ValueError("Copilot review history contains an invalid review ID")
        if review_id < current_review_id:
            prior_ids.add(review_id)
    if not prior_ids.issubset(covered):
        raise ValueError(
            "Prior Copilot review IDs are not completely covered by durable outcomes; "
            "refusing to reset correction history"
        )
    return len(prior_ids)


def _classify_module():
    path = Path(__file__).with_name("classify-copilot-review.py")
    if not path.is_file():
        raise ValueError("classify-copilot-review.py is required to reconstruct finding history")
    spec = importlib.util.spec_from_file_location("classify_copilot_review_mod", path)
    classify = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = classify
    spec.loader.exec_module(classify)
    return classify


def reconstruct_prior_outcomes_from_reviews(
    reviews: Any, current_review_id: int
) -> list[dict[str, Any]]:
    """Cover prior Copilot reviews from GitHub and rebuild finding history."""
    if not isinstance(reviews, list):
        raise ValueError("review history JSON must be an array")
    if isinstance(current_review_id, bool) or current_review_id <= 0:
        raise ValueError("review ID must be positive")
    classify = _classify_module()
    outcomes: list[dict[str, Any]] = []
    seen: set[int] = set()
    ledger: list[dict[str, Any]] = []
    for review in reviews:
        if not isinstance(review, Mapping) or not isinstance(review.get("user"), Mapping):
            raise ValueError("review history contains an invalid review")
        if review["user"].get("login") not in {
            "Copilot",
            "copilot-pull-request-reviewer",
            "copilot-pull-request-reviewer[bot]",
        }:
            continue
        review_id = review.get("id")
        if isinstance(review_id, bool) or not isinstance(review_id, int) or review_id <= 0:
            raise ValueError("Copilot review history contains an invalid review ID")
        if review_id >= current_review_id or review_id in seen:
            continue
        head_sha = str(review.get("commit_id") or "")
        if not head_sha:
            raise ValueError("Copilot review history is missing commit_id")
        if not str(review.get("body") or "").strip():
            raise ValueError("prior Copilot review is missing body; refusing empty finding history")
        seen.add(review_id)
        outcome = classify.classify_review(classify.review_input_from_github(review))
        classification = str(outcome.get("classification") or "")
        if not classification:
            raise ValueError("prior Copilot review could not be classified")
        titles = [
            str(title)
            for title in (
                list(outcome.get("open_finding_titles") or [])
                + list(outcome.get("previously_missed_titles") or [])
                + list(outcome.get("suppressed_comment_titles") or [])
            )
            if title
        ]
        if not titles and (outcome.get("requires_fixer") or outcome.get("requires_human")):
            titles = [classification]
        for title in titles:
            item = upsert_finding(
                ledger,
                source="copilot",
                path="",
                title=title,
                head_sha=head_sha,
            )
            if outcome.get("requires_human"):
                item["status"] = STATUS_NEEDS_HUMAN
        outcomes.append(
            {
                "review_id": review_id,
                "head_sha": head_sha,
                "classification": classification,
                "finding_ledger": json.loads(json.dumps(ledger)),
                "finding_count": outcome.get("finding_count"),
                "rationale_fingerprint": outcome.get("rationale_fingerprint") or "",
                "requires_human": bool(outcome.get("requires_human")),
                "requires_fixer": bool(outcome.get("requires_fixer")),
            }
        )
    return outcomes


DISPOSITION_MARKER = "<!-- envy-human-disposition:"


def attach_human_dispositions(outcomes: list[dict[str, Any]], comments: Any) -> list[dict[str, Any]]:
    """Overlay maintainer stop dispositions published as PR issue comments."""
    found: dict[str, dict[str, str]] = {}
    for comment in comments or []:
        if not isinstance(comment, Mapping):
            continue
        user = comment.get("user") if isinstance(comment.get("user"), Mapping) else {}
        login = str(user.get("login") or "")
        if login != "Mika3578":
            continue
        body = str(comment.get("body") or "")
        start = body.find(DISPOSITION_MARKER)
        if start < 0:
            continue
        rest = body[start + len(DISPOSITION_MARKER) :]
        end = rest.find("-->")
        if end < 0:
            continue
        try:
            payload = json.loads(rest[:end].strip())
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        review_id = str(payload.get("review_id") or "")
        evidence = str(payload.get("evidence") or "").strip()
        if review_id and payload.get("status") == "resolved" and evidence:
            found[review_id] = {
                "actor": login,
                "status": "resolved",
                "evidence": evidence,
            }
    attached = []
    for outcome in outcomes:
        item = dict(outcome)
        disposition = found.get(str(item.get("review_id") or ""))
        if disposition:
            item["human_disposition"] = disposition
        attached.append(item)
    return attached


def fingerprint(source: str, path: str, title: str, location: str = "") -> str:
    # Stable identity is source|path|title. Location is metadata only so a
    # fixer that moves the same defect to another line cannot reset attempts.
    _ = location
    key = (
        f"{(source or '').strip().lower()}|"
        f"{(path or '').strip().lower()}|"
        f"{(title or '').strip().lower()}"
    )
    key = " ".join(key.split())
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def upsert_finding(
    ledger: list[dict[str, Any]],
    *,
    source: str,
    path: str,
    title: str,
    head_sha: str,
    location: str = "",
) -> dict[str, Any]:
    fp = fingerprint(source, path, title, location)
    # Overview-only titles can acquire an inline path later. Reuse the existing
    # identity and attempts; ambiguous cross-path matches require human review.
    candidates = [item for item in ledger
                  if fingerprint(item.get("source", ""), "", item.get("title", ""))
                  == fingerprint(source, "", title)
                  and (not path or not item.get("path")
                       or str(item.get("path")).strip().lower() == path.strip().lower())]
    if len(candidates) > 1:
        active = [
            item
            for item in candidates
            if item.get("status") in {STATUS_OPEN, STATUS_FIXED_PENDING}
        ]
        if len(active) > 1:
            for item in candidates:
                item["status"] = STATUS_NEEDS_HUMAN
            return candidates[0]
        for item in candidates:
            item["status"] = STATUS_NEEDS_HUMAN
        if len(active) == 1:
            candidates = active
        else:
            candidates = [
                max(candidates, key=lambda item: int(item.get("attempts") or 0))
            ]
    for item in ledger:
        if item.get("fingerprint") == fp or item in candidates:
            if path and not item.get("path"):
                item["path"] = path
            if location and not item.get("location"):
                item["location"] = location
            item["last_seen_head"] = head_sha
            item["times_seen"] = int(item.get("times_seen") or 0) + 1
            if item.get("status") == STATUS_RESOLVED:
                item["status"] = STATUS_OPEN
            return item
    entry = {
        "id": f"{source}-{fp}",
        "fingerprint": fp,
        "source": source,
        "path": path,
        "title": title,
        "location": location,
        "first_seen_head": head_sha,
        "last_seen_head": head_sha,
        "times_seen": 1,
        "attempts": 0,
        "status": STATUS_OPEN,
        "correction_commit": "",
    }
    ledger.append(entry)
    return entry


def mark_fix_attempt(
    ledger: list[dict[str, Any]], fingerprint_value: str, commit: str
) -> dict[str, Any] | None:
    for item in ledger:
        if item.get("fingerprint") == fingerprint_value:
            item["attempts"] = int(item.get("attempts") or 0) + 1
            item["correction_commit"] = commit
            if item.get("status") != STATUS_NEEDS_HUMAN:
                item["status"] = STATUS_FIXED_PENDING
            return item
    return None


def merge_active_findings(inline_findings, outcome):
    """Retain overview-only findings alongside inline locations and budgets."""
    findings = [dict(item) for item in inline_findings if item.get("title")]
    titles = {str(item["title"]) for item in findings}
    for key in ("open_finding_titles", "previously_missed_titles", "suppressed_comment_titles"):
        for title in outcome.get(key) or []:
            if title and title not in titles:
                findings.append({"title": title, "path": "", "line": None})
                titles.add(title)
    return findings


def reconcile_after_review(
    ledger: list[dict[str, Any]],
    active_fingerprints: Sequence[str],
    head_sha: str,
) -> list[dict[str, Any]]:
    """Resolve absent technical findings without clearing a human stop."""
    active = set(active_fingerprints)
    for item in ledger:
        fp = str(item.get("fingerprint") or "")
        if fp in active:
            item["last_seen_head"] = head_sha
            if item.get("status") == STATUS_FIXED_PENDING:
                # Still present after a claimed fix → count toward human stop.
                item["times_seen"] = int(item.get("times_seen") or 0) + 1
                item["status"] = STATUS_OPEN
        elif item.get("status") in {
            STATUS_OPEN,
            STATUS_FIXED_PENDING,
        }:
            item["status"] = STATUS_RESOLVED
    return ledger


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_fp = sub.add_parser("fingerprint", help="Print fingerprint for source/path/title")
    p_fp.add_argument("--source", required=True)
    p_fp.add_argument("--path", default="")
    p_fp.add_argument("--title", required=True)
    p_fp.add_argument("--location", default="")

    p_up = sub.add_parser("upsert", help="Upsert finding into ledger JSON on stdin")
    p_up.add_argument("--source", required=True)
    p_up.add_argument("--path", default="")
    p_up.add_argument("--title", required=True)
    p_up.add_argument("--head-sha", required=True)
    p_up.add_argument("--location", default="")

    p_fix = sub.add_parser(
        "mark-fix",
        help="Record a correction-agent fix attempt (stdin ledger JSON → stdout)",
    )
    p_fix.add_argument("--fingerprint", required=True)
    p_fix.add_argument("--commit", required=True)

    p_history = sub.add_parser("check-history", help="Reject missing prior review state")
    p_history.add_argument("--review-id", required=True, type=int)
    p_history.add_argument("--prior-outcomes-json", required=True)
    p_rebuild = sub.add_parser(
        "reconstruct-history",
        help="Cover prior Copilot review IDs from GitHub reviews (stdin reviews JSON)",
    )
    p_rebuild.add_argument("--review-id", required=True, type=int)

    args = parser.parse_args(argv)
    if args.cmd == "reconstruct-history":
        try:
            outcomes = reconstruct_prior_outcomes_from_reviews(json.load(sys.stdin), args.review_id)
        except (ValueError, TypeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        sys.stdout.write(json.dumps(outcomes) + "\n")
        return 0
    if args.cmd == "check-history":
        try:
            count = check_review_history(
                json.load(sys.stdin), args.review_id, json.loads(args.prior_outcomes_json)
            )
        except (ValueError, TypeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"Prior Copilot review IDs: {count}; durable state guard passed")
        return 0
    if args.cmd == "fingerprint":
        sys.stdout.write(
            fingerprint(args.source, args.path, args.title, args.location) + "\n"
        )
        return 0
    if args.cmd == "upsert":
        ledger = json.load(sys.stdin)
        if not isinstance(ledger, list):
            raise SystemExit("ledger JSON must be an array")
        upsert_finding(
            ledger,
            source=args.source,
            path=args.path,
            title=args.title,
            head_sha=args.head_sha,
            location=args.location,
        )
        sys.stdout.write(json.dumps(ledger, indent=2) + "\n")
        return 0
    if args.cmd == "mark-fix":
        ledger = json.load(sys.stdin)
        if not isinstance(ledger, list):
            raise SystemExit("ledger JSON must be an array")
        updated = mark_fix_attempt(ledger, args.fingerprint, args.commit)
        if updated is None:
            raise SystemExit(f"fingerprint not found: {args.fingerprint}")
        sys.stdout.write(json.dumps(ledger, indent=2) + "\n")
        return 0
    raise SystemExit(f"unknown command {args.cmd}")


if __name__ == "__main__":
    raise SystemExit(main())
