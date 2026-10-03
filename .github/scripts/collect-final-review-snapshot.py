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
sys.modules[_SPEC.name] = GATE
_SPEC.loader.exec_module(GATE)

_LEDGER_SPEC = importlib.util.spec_from_file_location(
    "finding_ledger_mod", SCRIPTS / "finding-ledger.py"
)
LEDGER = importlib.util.module_from_spec(_LEDGER_SPEC)
sys.modules[_LEDGER_SPEC.name] = LEDGER
_LEDGER_SPEC.loader.exec_module(LEDGER)


def gh_json(args: list[str]) -> Any:
    proc = subprocess.run(
        ["gh", *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "gh failed")
    payload = json.loads(proc.stdout)
    if isinstance(payload, dict) and payload.get("errors") and "graphql" in args:
        raise RuntimeError("GraphQL query returned errors")
    return payload


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


GITHUB_PR_FILES_CAP = 3000


def file_inventory_paths(changed_files_count: Any, entries: list[Any]) -> list[str]:
    """Fail closed when GitHub's file list is truncated; include rename sources."""
    if not isinstance(changed_files_count, int) or changed_files_count < 0:
        raise RuntimeError("pull changed_files is missing")
    if changed_files_count > GITHUB_PR_FILES_CAP:
        raise RuntimeError("pull file inventory exceeds GitHub 3000-file cap")
    if not isinstance(entries, list) or len(entries) != changed_files_count:
        raise RuntimeError("incomplete pull file inventory")
    paths: list[str] = []
    for obj in entries:
        if not isinstance(obj, dict):
            raise RuntimeError("file page item is not an object")
        filename = str(obj.get("filename") or "").strip()
        if not filename:
            raise RuntimeError("file entry missing filename")
        paths.append(filename)
        previous = str(obj.get("previous_filename") or "").strip()
        if previous:
            paths.append(previous)
    return paths


def paginate_files(repository: str, pr: int) -> list[str]:
    expected = gh_json(["api", f"repos/{repository}/pulls/{pr}"]).get("changed_files")
    proc = subprocess.run(
        ["gh", "api", f"repos/{repository}/pulls/{pr}/files", "--paginate", "--jq", ".[]"],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "files paginate failed")
    entries: list[dict[str, Any]] = []
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
            raise RuntimeError("file page item is not an object")
        entries.append(obj)
        idx = end
    return file_inventory_paths(expected, entries)


def count_thread_dispositions(nodes: list, head_sha: str = "") -> tuple[int, int]:
    """Return (unresolved, resolved-without-authorized-HEAD-disposition). Fail closed."""
    unresolved = 0
    untreated = 0
    for node in nodes:
        if not isinstance(node, dict):
            raise RuntimeError("review thread node is malformed")
        comments = node.get("comments") or {}
        if comments.get("pageInfo", {}).get("hasNextPage"):
            raise RuntimeError("incomplete review thread comments")
        items = [item for item in (comments.get("nodes") or []) if isinstance(item, dict)]
        if not items:
            raise RuntimeError("review thread has no comments")
        if not node.get("isResolved"):
            unresolved += 1
            continue
        if GATE.resolved_thread_is_untreated(
            items, head_sha, outdated=bool(node.get("isOutdated"))
        ):
            untreated += 1
    return unresolved, untreated


def thread_disposition(owner: str, repo: str, pr: int, head_sha: str = "") -> tuple[int, int]:
    query = """
    query($o:String!,$n:String!,$p:Int!,$after:String){
      repository(owner:$o,name:$n){
        pullRequest(number:$p){
          reviewThreads(first:100, after:$after){
            nodes {
              isResolved
              isOutdated
              comments(first:100){
                pageInfo { hasNextPage }
                nodes { author { login __typename } commit { oid } }
              }
            }
            pageInfo { hasNextPage endCursor }
          }
        }
      }
    }
    """
    after = None
    unresolved = 0
    untreated = 0
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
        if data.get("errors"):
            raise RuntimeError("GraphQL reviewThreads query returned errors")
        pr_data = (((data.get("data") or {}).get("repository") or {}).get("pullRequest"))
        if not pr_data:
            raise RuntimeError("pull request missing from GraphQL")
        threads = pr_data.get("reviewThreads")
        if not isinstance(threads, dict):
            raise RuntimeError("reviewThreads snapshot is missing")
        nodes = threads.get("nodes")
        page = threads.get("pageInfo")
        if not isinstance(nodes, list) or not isinstance(page, dict):
            raise RuntimeError("reviewThreads snapshot is malformed")
        if not isinstance(page.get("hasNextPage"), bool):
            raise RuntimeError("reviewThreads pagination is malformed")
        more_unresolved, more_untreated = count_thread_dispositions(nodes, head_sha)
        unresolved += more_unresolved
        untreated += more_untreated
        if not page.get("hasNextPage"):
            return unresolved, untreated
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


def require_open_default_same_repo(
    pr_json: dict[str, Any], repository: str, repo_json: dict[str, Any]
) -> None:
    if str(pr_json.get("state") or "").lower() != "open":
        raise RuntimeError("pull request is not open")
    default_branch = str(repo_json.get("default_branch") or "")
    base_ref = str((pr_json.get("base") or {}).get("ref") or "")
    if not default_branch or base_ref != default_branch:
        raise RuntimeError("pull request does not target the repository default branch")
    head_repo = str(((pr_json.get("head") or {}).get("repo") or {}).get("full_name") or "")
    if head_repo != repository:
        raise RuntimeError("pull request head is not this repository")


def unique_open_pr_numbers(entries: Any, pr: int) -> set[int]:
    if not isinstance(entries, list):
        raise RuntimeError("HEAD pull membership is malformed")
    open_heads = {
        int(item.get("number") or 0)
        for item in entries
        if isinstance(item, dict) and str(item.get("state") or "").lower() == "open"
    }
    if pr not in open_heads or len(open_heads) != 1:
        raise RuntimeError("HEAD is shared by another open pull request")
    return open_heads


def paginate_commit_pulls(repository: str, head: str) -> list[Any]:
    proc = subprocess.run(
        ["gh", "api", f"repos/{repository}/commits/{head}/pulls", "--paginate", "--slurp"],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "HEAD pull membership paginate failed")
    pages = json.loads(proc.stdout or "[]")
    if not isinstance(pages, list):
        raise RuntimeError("HEAD pull membership is malformed")
    if not pages:
        return []
    if all(isinstance(page, list) for page in pages):
        return [item for page in pages for item in page]
    if all(isinstance(item, dict) for item in pages):
        return pages
    raise RuntimeError("HEAD pull membership is malformed")


def collect(repository: str, pr: int) -> dict[str, Any]:
    owner, _, repo = repository.partition("/")
    pr_json = gh_json(["api", f"repos/{repository}/pulls/{pr}"])
    repo_json = gh_json(["api", f"repos/{repository}"])
    require_open_default_same_repo(pr_json, repository, repo_json)
    head = str(pr_json.get("head", {}).get("sha") or "")
    if not head:
        raise RuntimeError("PR HEAD SHA is missing")
    related = paginate_commit_pulls(repository, head)
    unique_open_pr_numbers(related, pr)
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
    if checks_proc.returncode != 0:
        raise RuntimeError(checks_proc.stderr.strip() or "required checks collection failed")
    payload = json.loads(checks_proc.stdout)
    checks = payload.get("checks") if isinstance(payload, dict) else []
    if not isinstance(checks, list) or not checks:
        raise RuntimeError("required checks snapshot is empty")
    requested = gh_json(["api", f"repos/{repository}/pulls/{pr}/requested_reviewers"])
    pending_copilot = any(
        (user.get("login") in GATE.COPILOT_LOGINS)
        for user in (requested.get("users") or [])
        if isinstance(user, dict)
    )
    reviews = paginate_reviews(repository, pr)
    unresolved, untreated_threads = thread_disposition(owner, repo, pr, head)
    snapshot = {
        "pr_number": pr,
        "head_sha": head,
        "current_head_sha": head,
        "is_draft": bool(pr_json.get("draft")),
        "review_decision": gate_fields["review_decision"],
        "review_decision_source": "graphql",
        "review_decision_unavailable": False,
        "pr_author_login": gate_fields["pr_author_login"],
        "unresolved_threads": unresolved,
        "untreated_threads": untreated_threads,
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
        unresolved, untreated_threads = thread_disposition(owner, repo, pr, head)
        snapshot["unresolved_threads"] = max(int(snapshot["unresolved_threads"]), unresolved)
        snapshot["untreated_threads"] = max(int(snapshot["untreated_threads"]), untreated_threads)
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
        latest_id = latest.get("id")
        if isinstance(latest_id, bool) or not isinstance(latest_id, int) or latest_id <= 0:
            snapshot["api_error"] = True
            snapshot["api_error_message"] = "Copilot review id is missing"
            return snapshot
        prior = LEDGER.reconstruct_prior_outcomes_from_reviews(reviews, latest_id)
        snapshot["finding_ledger"] = list((prior[-1].get("finding_ledger") or [])) if prior else []
        outcome = classify.classify_review(classify.review_input_from_github(latest))
        outcome = classify.apply_loop_guards(outcome, prior)
        snapshot["previously_missed_titles"] = list(outcome.get("previously_missed_titles") or [])
        snapshot["suppressed_comment_titles"] = list(outcome.get("suppressed_comment_titles") or [])
        snapshot["open_finding_titles"] = list(outcome.get("open_finding_titles") or [])
        snapshot["copilot_classification"] = str(outcome.get("classification") or "")
        snapshot["requires_human"] = bool(outcome.get("requires_human"))
        snapshot["requires_fixer"] = bool(outcome.get("requires_fixer"))
        snapshot["human_stop_review_ids"] = [
            str(item) for item in (outcome.get("human_stop_review_ids") or []) if str(item)
        ]
        if snapshot["human_stop_review_ids"]:
            snapshot["requires_human"] = True
        if outcome.get("loop_guard"):
            snapshot["loop_guard"] = str(outcome.get("loop_guard"))
        if not snapshot["copilot_classification"]:
            snapshot["api_error"] = True
            snapshot["api_error_message"] = "Copilot classification is empty"
            return snapshot
        snapshot["untreated_pr_level_findings"] = [
            title
            for title in snapshot["open_finding_titles"]
            if title and title not in snapshot["previously_missed_titles"]
        ]
    # Re-read eligibility and HEAD after collection (race 1).
    fresh = gh_json(["api", f"repos/{repository}/pulls/{pr}"])
    repo_json = gh_json(["api", f"repos/{repository}"])
    require_open_default_same_repo(fresh, repository, repo_json)
    snapshot["current_head_sha"] = str(fresh.get("head", {}).get("sha") or "")
    if not snapshot["current_head_sha"]:
        raise RuntimeError("PR HEAD SHA is missing")
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
