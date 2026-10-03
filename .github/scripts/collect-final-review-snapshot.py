#!/usr/bin/env python3
"""Collect a Final review gate snapshot from GitHub (metadata only).

Never executes PR code. Requires gh + GH_TOKEN. Fail closed on API errors.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any

from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import importlib.util

_SPEC = importlib.util.spec_from_file_location(
    "final_review_gate_mod", SCRIPTS / "final-review-gate.py"
)
GATE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(GATE)


def gh_json(args: list[str]) -> Any:
    proc = subprocess.run(
        ["gh", *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "gh failed")
    return json.loads(proc.stdout)


def paginate_reviews(repository: str, pr: int) -> list[dict[str, Any]]:
    proc = subprocess.run(
        [
            "gh",
            "api",
            f"repos/{repository}/pulls/{pr}/reviews",
            "--paginate",
            "--jq",
            ".[]",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "reviews paginate failed")
    reviews: list[dict[str, Any]] = []
    decoder = json.JSONDecoder()
    text = proc.stdout.lstrip()
    idx = 0
    while idx < len(text):
        while idx < len(text) and text[idx].isspace():
            idx += 1
        if idx >= len(text):
            break
        obj, end = decoder.raw_decode(text, idx)
        if not isinstance(obj, dict):
            raise RuntimeError("review page item is not an object")
        reviews.append(obj)
        idx = end
    return reviews


def paginate_files(repository: str, pr: int) -> list[str]:
    proc = subprocess.run(
        ["gh", "api", f"repos/{repository}/pulls/{pr}/files", "--paginate", "--jq", ".[].filename"],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "files paginate failed")
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def unresolved_threads(owner: str, repo: str, pr: int) -> int:
    query = """
    query($o:String!,$n:String!,$p:Int!,$after:String){
      repository(owner:$o,name:$n){
        pullRequest(number:$p){
          reviewThreads(first:100, after:$after){
            nodes { isResolved }
            pageInfo { hasNextPage endCursor }
          }
        }
      }
    }
    """
    after = None
    unresolved = 0
    while True:
        args = [
            "api",
            "graphql",
            "-f",
            f"query={query}",
            "-f",
            f"o={owner}",
            "-f",
            f"n={repo}",
            "-F",
            f"p={pr}",
        ]
        if after:
            args.extend(["-f", f"after={after}"])
        data = gh_json(args)
        pr_data = (((data.get("data") or {}).get("repository") or {}).get("pullRequest"))
        if not pr_data:
            raise RuntimeError("pull request missing from GraphQL")
        threads = pr_data.get("reviewThreads") or {}
        for node in threads.get("nodes") or []:
            if not node.get("isResolved"):
                unresolved += 1
        page = threads.get("pageInfo") or {}
        if not page.get("hasNextPage"):
            return unresolved
        after = page.get("endCursor")
        if not after:
            raise RuntimeError("reviewThreads hasNextPage without endCursor")


def graphql_pr_gate_fields(payload: Any, expected_head: str) -> dict[str, Any]:
    """Bind GraphQL reviewDecision and author to the exact HEAD. Fail closed."""
    if not isinstance(payload, dict):
        raise RuntimeError("GraphQL reviewDecision payload is missing")
    if payload.get("errors"):
        raise RuntimeError("GraphQL reviewDecision query returned errors")
    pr_data = (((payload.get("data") or {}).get("repository") or {}).get("pullRequest"))
    if not isinstance(pr_data, dict):
        raise RuntimeError("GraphQL pull request payload is missing")
    gql_head = str(pr_data.get("headRefOid") or "")
    if not expected_head or gql_head != expected_head:
        raise RuntimeError("GraphQL headRefOid does not match the collected PR HEAD")
    author = pr_data.get("author")
    login = ""
    if isinstance(author, dict):
        login = str(author.get("login") or "")
    if not login:
        raise RuntimeError("GraphQL PR author login is unavailable")
    if "reviewDecision" not in pr_data:
        raise RuntimeError("GraphQL reviewDecision field is unavailable")
    decision = pr_data.get("reviewDecision")
    if decision is not None and not isinstance(decision, str):
        raise RuntimeError("GraphQL reviewDecision is malformed")
    return {
        "review_decision": str(decision or ""),
        "review_decision_source": "graphql",
        "pr_author_login": login,
        "review_decision_unavailable": False,
    }


def fetch_graphql_pr_gate_fields(owner: str, repo: str, pr: int, expected_head: str) -> dict[str, Any]:
    query = """
    query($o:String!,$n:String!,$p:Int!){
      repository(owner:$o,name:$n){
        pullRequest(number:$p){
          reviewDecision
          headRefOid
          author { login }
        }
      }
    }
    """
    payload = gh_json(
        [
            "api",
            "graphql",
            "-f",
            f"query={query}",
            "-f",
            f"o={owner}",
            "-f",
            f"n={repo}",
            "-F",
            f"p={pr}",
        ]
    )
    return graphql_pr_gate_fields(payload, expected_head)


def collect(repository: str, pr: int) -> dict[str, Any]:
    owner, _, repo = repository.partition("/")
    pr_json = gh_json(["api", f"repos/{repository}/pulls/{pr}"])
    head = str(pr_json.get("head", {}).get("sha") or "")
    gate_fields = fetch_graphql_pr_gate_fields(owner, repo, pr, head)
    checks_proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS.parent.parent / "scripts" / "review" / "required_checks.py"),
            "--repository",
            repository,
            "--head",
            head,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    checks: list[dict[str, Any]] = []
    if checks_proc.returncode == 0 and checks_proc.stdout.strip():
        payload = json.loads(checks_proc.stdout)
        checks = payload.get("checks") if isinstance(payload, dict) else []
        if not isinstance(checks, list):
            checks = []
    requested = gh_json(["api", f"repos/{repository}/pulls/{pr}/requested_reviewers"])
    pending_copilot = any(
        (user.get("login") in GATE.COPILOT_LOGINS)
        for user in (requested.get("users") or [])
        if isinstance(user, dict)
    )
    reviews = paginate_reviews(repository, pr)
    snapshot = {
        "pr_number": pr,
        "head_sha": head,
        "current_head_sha": head,
        "is_draft": bool(pr_json.get("draft")),
        "review_decision": gate_fields["review_decision"],
        "review_decision_source": "graphql",
        "review_decision_unavailable": False,
        "pr_author_login": gate_fields["pr_author_login"],
        "unresolved_threads": unresolved_threads(owner, repo, pr),
        "untreated_pr_level_findings": [],
        "previously_missed_titles": [],
        "suppressed_comment_titles": [],
        "open_finding_titles": [],
        "changed_files": paginate_files(repository, pr),
        "required_checks": checks,
        "reviews": reviews,
        "finding_ledger": [],
        "copilot_request_pending": pending_copilot,
        "api_error": False,
        "snapshot_phase": "pre_copilot_request",
    }
    latest = GATE.latest_copilot_review(reviews, head)
    if latest:
        snapshot["unresolved_threads"] = max(
            int(snapshot["unresolved_threads"]), unresolved_threads(owner, repo, pr)
        )
        snapshot["snapshot_phase"] = "post_copilot_review"
        snapshot["post_review_reread"] = True
    classify_path = SCRIPTS / "classify-copilot-review.py"
    if latest:
        if not classify_path.is_file():
            snapshot["classifier_missing"] = True
            snapshot["api_error"] = True
            snapshot["api_error_message"] = "classify-copilot-review.py is missing"
            return snapshot
        spec = importlib.util.spec_from_file_location(
            "classify_copilot_review_mod", classify_path
        )
        classify = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(classify)
        outcome = classify.classify_review(classify.review_input_from_github(latest))
        snapshot["previously_missed_titles"] = list(outcome.get("previously_missed_titles") or [])
        snapshot["suppressed_comment_titles"] = list(outcome.get("suppressed_comment_titles") or [])
        snapshot["open_finding_titles"] = list(outcome.get("open_finding_titles") or [])
        snapshot["copilot_classification"] = str(outcome.get("classification") or "")
        if not snapshot["copilot_classification"]:
            snapshot["api_error"] = True
            snapshot["api_error_message"] = "Copilot classification is empty"
            return snapshot
        snapshot["untreated_pr_level_findings"] = [
            title
            for title in snapshot["open_finding_titles"]
            if title and title not in snapshot["previously_missed_titles"]
        ]
    # Re-read HEAD after collection (race 1).
    fresh = gh_json(["api", f"repos/{repository}/pulls/{pr}"])
    snapshot["current_head_sha"] = str(fresh.get("head", {}).get("sha") or "")
    return snapshot


def main() -> int:
    repository = os.environ.get("REPOSITORY") or os.environ.get("GITHUB_REPOSITORY")
    pr = os.environ.get("PR_NUMBER")
    if not repository or not pr or not pr.isdigit():
        print("REPOSITORY and PR_NUMBER are required", file=sys.stderr)
        return 1
    try:
        snapshot = collect(repository, int(pr))
    except Exception as exc:  # noqa: BLE001 — fail closed into snapshot
        snapshot = {
            "pr_number": int(pr),
            "head_sha": "",
            "current_head_sha": "",
            "api_error": True,
            "api_error_message": str(exc),
            "reviews": [],
            "changed_files": [],
            "required_checks": [],
            "unresolved_threads": None,
            "review_decision_unavailable": True,
            "review_decision_source": "",
            "copilot_classification": "",
        }
    sys.stdout.write(json.dumps(snapshot, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
