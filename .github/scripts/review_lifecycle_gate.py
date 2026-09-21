#!/usr/bin/env python3
"""Fail-closed pull-request review lifecycle gate.

Separates GitHub collection from a pure PASS/FAIL/PENDING/SKIP decision on a
JSON snapshot. The decision engine must not touch the network.

Policy: Copilot Code Review is the final reviewer. PASS requires a GitHub
review with state APPROVED from copilot-pull-request-reviewer on the current
HEAD. Human or other-bot approvals do not satisfy the gate. COMMENTED is
never rewritten as APPROVED.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any


COPILOT_REVIEWER_LOGINS = {
	"copilot-pull-request-reviewer",
}
COPILOT_AUTHOR_LOGINS = {
	"copilot",
	"copilot-swe-agent",
	"copilot-pull-request-reviewer",
	"app/copilot-swe-agent",
}
COPILOT_CHECK_NAMES = {
	"copilot-pull-request-reviewer",
}
ADVISORY_REVIEWER_LOGINS = {
	"amazon-q-developer",
	"coderabbitai",
	"cubic-dev-ai",
	"cursor",
	"cursoragent",
	"sourcery-ai",
}
IN_FLIGHT_CHECK_STATUSES = {
	"queued",
	"in_progress",
	"waiting",
	"pending",
	"requested",
	"waiting_for_deployment",
}
BAD_CHECK_CONCLUSIONS = {
	"cancelled",
	"failure",
	"timed_out",
	"action_required",
	"startup_failure",
	"stale",
}
GRAPHQL_PR_ERROR = "Failed to retrieve pull request data from GraphQL"
NO_COPILOT_HEAD_REVIEW = "no completed Copilot review is tied to the current HEAD"
COPILOT_APPROVED_REQUIRED = "Copilot APPROVED is required on the current HEAD"
# Live Protect develop required contexts (REST ruleset 16457466, 2026-09-21).
REQUIRED_TECHNICAL_CHECK_NAMES = (
	"Build x64 Release",
	"Build Win32 Release",
	"Lint build files",
	"Vcpkg manifest sanity",
	"Format Check",
	"Documentation Check",
	"secret-scan",
	"gitleaks",
	"PR Gate",
	"Analyze (c-cpp)",
	"SonarCloud Code Analysis",
)


@dataclass
class GateResult:
	status: str
	reasons: list[str] = field(default_factory=list)

	@property
	def ok(self) -> bool:
		return self.status == "pass"


def _norm(value: Any) -> str:
	return str(value or "").strip()


def _lower(value: Any) -> str:
	return _norm(value).lower()


def _login(value: Any) -> str:
	text = _lower(value)
	if text.endswith("[bot]"):
		text = text[: -len("[bot]")]
	return text


def _author_login(item: dict[str, Any]) -> str:
	author = item.get("author")
	if isinstance(author, dict):
		return _login(author.get("login"))
	return _login(item.get("author") or item.get("author_login") or item.get("login"))


def _commit_oid(review: dict[str, Any]) -> str:
	commit = review.get("commit")
	if isinstance(commit, dict):
		return _norm(commit.get("oid") or commit.get("sha"))
	return _norm(review.get("commit_oid") or review.get("commitOid") or review.get("commit_id"))


def _is_copilot_reviewer(login: str) -> bool:
	return _login(login) in COPILOT_REVIEWER_LOGINS


def _is_advisory_reviewer(login: str) -> bool:
	return _login(login) in ADVISORY_REVIEWER_LOGINS


def _is_copilot_author(login: str) -> bool:
	return _login(login) in COPILOT_AUTHOR_LOGINS


def _is_copilot_check(item: dict[str, Any]) -> bool:
	return _lower(item.get("name")) in COPILOT_CHECK_NAMES


def _policy_flag(policy: dict[str, Any], key: str, default: bool) -> bool:
	if key not in policy:
		return default
	return bool(policy.get(key))


def _pull_request_from_graphql(payload: Any) -> dict[str, Any]:
	"""Return the pullRequest object or raise a fail-closed collection error."""

	if not isinstance(payload, dict):
		raise RuntimeError(GRAPHQL_PR_ERROR)
	errors = payload.get("errors")
	if errors:
		raise RuntimeError("GraphQL response contained errors; failing closed")
	data = payload.get("data")
	if not isinstance(data, dict):
		raise RuntimeError(GRAPHQL_PR_ERROR)
	repository = data.get("repository")
	if not isinstance(repository, dict):
		raise RuntimeError(GRAPHQL_PR_ERROR)
	pr = repository.get("pullRequest")
	if not isinstance(pr, dict):
		raise RuntimeError(GRAPHQL_PR_ERROR)
	return pr


def _resolve_pr_number(env: dict[str, str] | None = None) -> str:
	"""Read a numeric PR id from PR_NUMBER or GITHUB_REF_NAME."""

	source = os.environ if env is None else env
	pr_number = _norm(source.get("PR_NUMBER"))
	if not pr_number:
		ref_parts = _norm(source.get("GITHUB_REF_NAME")).split("/", 1)
		pr_number = ref_parts[0] if ref_parts else ""
	if not pr_number.isdigit():
		raise RuntimeError("PR_NUMBER must be set")
	return pr_number


def _check_matches_head(check: Any, head_sha: str) -> dict[str, Any] | None:
	if not isinstance(check, dict):
		return None
	check_sha = _norm(check.get("head_sha") or check.get("headSha") or head_sha)
	if check_sha and check_sha != head_sha:
		return None
	return check


def _index_named_checks(checks: Any, head_sha: str) -> dict[str, dict[str, Any]] | None:
	if checks is None:
		checks = []
	if not isinstance(checks, list):
		return None
	by_name: dict[str, dict[str, Any]] = {}
	for check in checks:
		matched = _check_matches_head(check, head_sha)
		if matched is None:
			continue
		name = _norm(matched.get("name"))
		if name:
			by_name[name] = matched
	return by_name


def _required_check_outcome(check: dict[str, Any] | None, name: str) -> tuple[str, str]:
	if check is None:
		return "pending", f"required technical check {name} is not reported for this HEAD"
	status = _lower(check.get("status"))
	if status in IN_FLIGHT_CHECK_STATUSES or status == "":
		return "pending", f"required technical check {name} is still running"
	conclusion = _lower(check.get("conclusion"))
	if status == "completed" and conclusion == "success":
		return "ok", ""
	return "fail", f"required technical check {name} is not successful"


def _technical_check_results(
	snapshot: dict[str, Any],
	head_sha: str,
	require_technical_checks: bool,
) -> tuple[list[str], list[str]]:
	if not require_technical_checks:
		return [], []
	by_name = _index_named_checks(snapshot.get("technical_checks"), head_sha)
	if by_name is None:
		return ["invalid technical check data"], []
	reasons: list[str] = []
	pending: list[str] = []
	for name in REQUIRED_TECHNICAL_CHECK_NAMES:
		kind, message = _required_check_outcome(by_name.get(name), name)
		if kind == "pending":
			pending.append(message)
		elif kind == "fail":
			reasons.append(message)
	return reasons, pending


def _copilot_check_label(check: dict[str, Any]) -> str:
	status = _lower(check.get("status"))
	conclusion = _lower(check.get("conclusion"))
	if status in IN_FLIGHT_CHECK_STATUSES or status == "":
		return "in_flight"
	if status == "completed" and conclusion == "success":
		return "completed"
	if status == "completed" and conclusion in BAD_CHECK_CONCLUSIONS:
		return "bad"
	return "other"


def _copilot_check_state(copilot_checks: list[Any], head_sha: str) -> tuple[bool, bool, bool]:
	labels = []
	for check in copilot_checks:
		matched = _check_matches_head(check, head_sha)
		if matched is None:
			continue
		if not _is_copilot_check(matched):
			continue
		labels.append(_copilot_check_label(matched))
	return "in_flight" in labels, "bad" in labels, "completed" in labels


def _has_changes_requested(opinionated: list[Any]) -> bool:
	latest_state_by_author: dict[str, str] = {}
	for review in opinionated:
		if not isinstance(review, dict):
			continue
		login = _author_login(review)
		state = _lower(review.get("state"))
		if login and state and state != "dismissed":
			latest_state_by_author[login] = state
	return any(state == "changes_requested" for state in latest_state_by_author.values())


def _latest_copilot_review_on_head(reviews: list[Any], head_sha: str) -> dict[str, Any] | None:
	candidates: list[dict[str, Any]] = []
	for review in reviews:
		if not isinstance(review, dict):
			continue
		if _commit_oid(review) != head_sha:
			continue
		if _lower(review.get("state")) == "dismissed":
			continue
		if not _is_copilot_reviewer(_author_login(review)):
			continue
		candidates.append(review)
	if not candidates:
		return None

	def _submitted_at(review: dict[str, Any]) -> str:
		return _norm(review.get("submittedAt") or review.get("submitted_at") or "")

	if any(_submitted_at(review) for review in candidates):
		return max(candidates, key=_submitted_at)
	return candidates[-1]


def _latest_copilot_review_is_approved(reviews: list[Any], head_sha: str) -> bool:
	latest = _latest_copilot_review_on_head(reviews, head_sha)
	return latest is not None and _lower(latest.get("state")) == "approved"


def _requested_reviewer_logins(snapshot: dict[str, Any]) -> set[str]:
	logins: set[str] = set()
	event_login = _login(snapshot.get("requested_reviewer") or snapshot.get("requestedReviewer"))
	if event_login:
		logins.add(event_login)
	raw = snapshot.get("requested_reviewers") or []
	if not isinstance(raw, list):
		return logins
	for item in raw:
		if isinstance(item, str):
			logins.add(_login(item))
		elif isinstance(item, dict):
			logins.add(_author_login(item))
	return logins


def _copilot_is_currently_requested(
	snapshot: dict[str, Any],
	head_sha: str,
	reviews: list[Any] | None = None,
) -> bool:
	# Fresh re-request always restarts the cycle, even if an older HEAD review exists.
	event_action = _lower(snapshot.get("event_action") or snapshot.get("eventAction"))
	if event_action == "review_requested":
		requested = _login(snapshot.get("requested_reviewer") or snapshot.get("requestedReviewer"))
		if _is_copilot_reviewer(requested):
			return True
	if not any(_is_copilot_reviewer(login) for login in _requested_reviewer_logins(snapshot)):
		return False
	# GitHub can leave Copilot in reviewRequests after it already submitted a
	# HEAD review. Treat that leftover as stale once a non-dismissed Copilot
	# review is tied to this SHA; otherwise wait for the first HEAD review.
	if reviews is None:
		raw = snapshot.get("reviews")
		reviews = raw if isinstance(raw, list) else []
	return _latest_copilot_review_on_head(reviews, head_sha) is None


def _header_result(snapshot: dict[str, Any]) -> tuple[str, GateResult | None]:
	head_sha = _norm(snapshot.get("head_sha") or snapshot.get("headRefOid"))
	if not head_sha:
		return "", GateResult("fail", ["missing head SHA"])
	target_branch = _norm(snapshot.get("base_ref") or snapshot.get("baseRefName"))
	if not target_branch:
		return head_sha, GateResult("fail", ["missing base branch"])
	if target_branch != "develop":
		return head_sha, GateResult("skip", [f"pull request targets {target_branch}, not develop"])
	if snapshot.get("incomplete_data"):
		return head_sha, GateResult("fail", ["incomplete GitHub review data; failing closed"])
	if snapshot.get("pagination_unhandled") or snapshot.get("has_next_page"):
		return head_sha, GateResult("fail", ["pagination unhandled; failing closed"])
	if bool(snapshot.get("is_draft") or snapshot.get("isDraft")):
		return head_sha, GateResult(
			"skip",
			["pull request is draft; review cycle is evaluated when the PR is marked ready"],
		)
	reviews = snapshot.get("reviews")
	if not isinstance(reviews, list):
		reviews = []
	if _copilot_is_currently_requested(snapshot, head_sha, reviews):
		return head_sha, GateResult(
			"pending",
			["Copilot review is currently requested; waiting for a new HEAD review"],
		)
	return head_sha, None


def _author_from_snapshot(snapshot: dict[str, Any]) -> str:
	author_login = _login(snapshot.get("author_login"))
	if author_login:
		return author_login
	author = snapshot.get("author")
	if isinstance(author, dict):
		return _login(author.get("login"))
	return _login(author)


def _payload_or_fail(snapshot: dict[str, Any]) -> tuple[list[Any], list[Any], list[Any], dict[str, Any]] | GateResult:
	reviews = snapshot.get("reviews")
	if not isinstance(reviews, list):
		return GateResult("fail", ["missing reviews data"])
	if "latest_opinionated_reviews" in snapshot:
		opinionated = snapshot.get("latest_opinionated_reviews")
	elif "latestOpinionatedReviews" in snapshot:
		opinionated = snapshot.get("latestOpinionatedReviews")
	else:
		return GateResult("fail", ["missing latest opinionated review data"])
	if opinionated is None:
		return GateResult("fail", ["missing latest opinionated review data"])
	if not isinstance(opinionated, list):
		return GateResult("fail", ["invalid latest opinionated review data"])
	if "copilot_checks" in snapshot:
		copilot_checks = snapshot.get("copilot_checks")
	elif "check_runs" in snapshot:
		copilot_checks = snapshot.get("check_runs")
	else:
		return GateResult("fail", ["missing Copilot check data"])
	if copilot_checks is None:
		return GateResult("fail", ["missing Copilot check data"])
	if not isinstance(copilot_checks, list):
		return GateResult("fail", ["invalid Copilot check data"])
	policy = snapshot.get("policy", {})
	if not isinstance(policy, dict):
		return GateResult("fail", ["invalid policy data"])
	return reviews, opinionated, copilot_checks, policy


def _head_reviews(reviews: list[Any], head_sha: str) -> list[dict[str, Any]]:
	tied = []
	for review in reviews:
		if not isinstance(review, dict):
			continue
		if _commit_oid(review) != head_sha:
			continue
		if _lower(review.get("state")) == "dismissed":
			continue
		tied.append(review)
	return tied


def _copilot_cycle_notes(
	require_copilot_head_review: bool,
	copilot_head_reviews: list[Any],
	in_flight: bool,
	bad_copilot_check: bool,
	completed_copilot_check: bool,
) -> tuple[list[str], list[str]]:
	reasons: list[str] = []
	pending: list[str] = []
	if in_flight:
		pending.append("Copilot code review is still running for this HEAD")
		return reasons, pending
	if require_copilot_head_review and bad_copilot_check and not copilot_head_reviews:
		reasons.append("Copilot code review for this HEAD did not complete successfully")
	if require_copilot_head_review and not copilot_head_reviews:
		pending.append(NO_COPILOT_HEAD_REVIEW)
	if require_copilot_head_review and completed_copilot_check and not copilot_head_reviews:
		if NO_COPILOT_HEAD_REVIEW not in pending:
			pending.append(NO_COPILOT_HEAD_REVIEW)
	return reasons, pending


def _independent_copilot_author_ok(head_reviews: list[dict[str, Any]], author_login: str) -> bool:
	for review in head_reviews:
		if _lower(review.get("state")) != "approved":
			continue
		login = _author_login(review)
		if _is_copilot_reviewer(login):
			continue
		if login == author_login:
			continue
		if _is_advisory_reviewer(login):
			continue
		return True
	return False


def decide(snapshot: dict[str, Any]) -> GateResult:
	"""Return the review lifecycle decision for a pull-request snapshot."""

	head_sha, early = _header_result(snapshot)
	if early is not None:
		return early
	payload = _payload_or_fail(snapshot)
	if isinstance(payload, GateResult):
		return payload
	reviews, opinionated, copilot_checks, policy = payload
	author_login = _author_from_snapshot(snapshot)
	require_copilot_approval = _policy_flag(policy, "require_copilot_approval", True)
	require_copilot_head_review = _policy_flag(policy, "require_copilot_head_review", True)
	require_independent = _policy_flag(policy, "require_independent_for_copilot_author", True)
	require_technical_checks = _policy_flag(policy, "require_technical_checks", True)

	reasons, pending_reasons = _technical_check_results(snapshot, head_sha, require_technical_checks)
	if reasons and reasons[0] == "invalid technical check data":
		return GateResult("fail", reasons)
	if _has_changes_requested(opinionated):
		reasons.append("active CHANGES_REQUESTED review")

	head_reviews = _head_reviews(reviews, head_sha)
	copilot_head_reviews = [review for review in head_reviews if _is_copilot_reviewer(_author_login(review))]
	in_flight, bad_copilot_check, completed_copilot_check = _copilot_check_state(copilot_checks, head_sha)
	cycle_fail, cycle_pending = _copilot_cycle_notes(
		require_copilot_head_review,
		copilot_head_reviews,
		in_flight,
		bad_copilot_check,
		completed_copilot_check,
	)
	reasons.extend(cycle_fail)
	pending_reasons.extend(cycle_pending)
	if reasons:
		return GateResult("fail", reasons + pending_reasons)
	if pending_reasons:
		return GateResult("pending", pending_reasons)
	if require_copilot_approval and not _latest_copilot_review_is_approved(reviews, head_sha):
		return GateResult("fail", [COPILOT_APPROVED_REQUIRED])
	if require_independent and _is_copilot_author(author_login):
		if not _independent_copilot_author_ok(head_reviews, author_login):
			return GateResult("fail", ["Copilot-authored pull request lacks an independent approval"])
	return GateResult("pass", ["review lifecycle is complete for the current HEAD"])


def _run_gh(args: list[str]) -> Any:
	env = os.environ.copy()
	token = env.get("GH_TOKEN") or env.get("GITHUB_TOKEN")
	if not token:
		raise RuntimeError("GH_TOKEN or GITHUB_TOKEN is required")
	env["GH_TOKEN"] = token
	completed = subprocess.run(
		["gh", *args],
		check=True,
		capture_output=True,
		text=True,
		env=env,
	)
	if not completed.stdout.strip():
		raise RuntimeError("GitHub API returned an empty response")
	return json.loads(completed.stdout)


def _run_gh_graphql(query: str, variables: dict[str, Any]) -> dict[str, Any]:
	cmd = ["api", "graphql", "-f", f"query={query}"]
	for key, value in variables.items():
		if value is None:
			continue
		flag = "-F" if isinstance(value, (int, float)) or key.endswith("Cursor") or key == "number" else "-f"
		if key.endswith("Cursor") and isinstance(value, str):
			flag = "-f"
		cmd.extend([flag, f"{key}={value}"])
	return _run_gh(cmd)


def _paginate_pr_connection(
	owner: str,
	name: str,
	number: int,
	field: str,
	node_fields: str,
) -> list[dict[str, Any]]:
	query = f"""
query($owner:String!, $name:String!, $number:Int!, $cursor:String) {{
  repository(owner:$owner, name:$name) {{
    pullRequest(number:$number) {{
      {field}(first:100, after:$cursor) {{
        pageInfo {{ hasNextPage endCursor }}
        nodes {{ {node_fields} }}
      }}
    }}
  }}
}}
"""
	nodes: list[dict[str, Any]] = []
	cursor = None
	for _ in range(20):
		variables: dict[str, Any] = {"owner": owner, "name": name, "number": number}
		if cursor:
			variables["cursor"] = cursor
		payload = _run_gh_graphql(query, variables)
		pr = _pull_request_from_graphql(payload)
		connection = pr.get(field)
		if not isinstance(connection, dict):
			raise RuntimeError(f"Failed to retrieve {field} from GraphQL")
		page = connection.get("pageInfo")
		if not isinstance(page, dict):
			raise RuntimeError(f"pagination of {field} missing pageInfo; failing closed")
		nodes.extend(connection.get("nodes") or [])
		if page.get("hasNextPage") is True:
			cursor = page.get("endCursor")
			if not cursor:
				raise RuntimeError(f"pagination of {field} reported hasNextPage without a cursor")
			continue
		if page.get("hasNextPage") is False:
			return nodes
		raise RuntimeError(f"pagination of {field} missing hasNextPage; failing closed")
	raise RuntimeError(f"pagination of {field} exceeded the fail-closed page limit")


def _normalize_check_runs(runs: list[Any], head_sha: str) -> list[dict[str, Any]]:
	checks: list[dict[str, Any]] = []
	for run in runs:
		if not isinstance(run, dict):
			continue
		checks.append(
			{
				"name": run.get("name"),
				"status": run.get("status"),
				"conclusion": run.get("conclusion"),
				"head_sha": run.get("head_sha") or head_sha,
			}
		)
	return checks


def _fetch_check_runs_page(repo: str, head_sha: str, page: int) -> tuple[list[Any], int | None]:
	payload = _run_gh(
		["api", f"repos/{repo}/commits/{head_sha}/check-runs?per_page=100&page={page}"]
	)
	if not isinstance(payload, dict):
		raise RuntimeError("check-runs response was not an object")
	runs = payload.get("check_runs")
	if not isinstance(runs, list):
		raise RuntimeError("check-runs response did not include check_runs")
	raw_total = payload.get("total_count")
	total = raw_total if isinstance(raw_total, int) else None
	return runs, total


def _collect_commit_checks(repo: str, head_sha: str) -> list[dict[str, Any]]:
	# Paginate explicitly: a single per_page=100 page is not enough after reruns.
	all_runs: list[Any] = []
	total: int | None = None
	for page in range(1, 51):
		runs, page_total = _fetch_check_runs_page(repo, head_sha, page)
		all_runs.extend(runs)
		if page_total is not None:
			total = page_total
		if total is not None and len(all_runs) >= total:
			return _normalize_check_runs(all_runs, head_sha)
		if len(runs) < 100:
			if total is not None and len(all_runs) < total:
				raise RuntimeError("check-runs pagination truncated; failing closed")
			return _normalize_check_runs(all_runs, head_sha)
	raise RuntimeError("check-runs pagination exceeded the fail-closed page limit")


def collect_snapshot_from_github() -> dict[str, Any]:
	repo = os.environ.get("GITHUB_REPOSITORY", "")
	if "/" not in repo:
		raise RuntimeError("GITHUB_REPOSITORY must be set to owner/repo")
	owner, name = repo.split("/", 1)
	pr_number = _resolve_pr_number()

	header_query = """
query($owner:String!, $name:String!, $number:Int!) {
  repository(owner:$owner, name:$name) {
    pullRequest(number:$number) {
      isDraft
      headRefOid
      baseRefName
      author { login }
    }
  }
}
"""
	header = _run_gh_graphql(header_query, {"owner": owner, "name": name, "number": int(pr_number)})
	pr = _pull_request_from_graphql(header)
	head_sha = _norm(pr.get("headRefOid"))
	if not head_sha:
		raise RuntimeError("pull request head SHA was empty")

	reviews = _paginate_pr_connection(
		owner,
		name,
		int(pr_number),
		"reviews",
		"state submittedAt author { login } commit { oid }",
	)
	opinionated = _paginate_pr_connection(
		owner,
		name,
		int(pr_number),
		"latestOpinionatedReviews",
		"state author { login } commit { oid }",
	)
	req_nodes = _paginate_pr_connection(
		owner,
		name,
		int(pr_number),
		"reviewRequests",
		"requestedReviewer { __typename ... on Bot { login } ... on User { login } ... on Team { slug } }",
	)
	requested_reviewers = []
	for node in req_nodes:
		reviewer = node.get("requestedReviewer") if isinstance(node, dict) else None
		if isinstance(reviewer, dict):
			requested_reviewers.append(reviewer.get("login") or reviewer.get("slug"))
	all_checks = _collect_commit_checks(repo, head_sha)
	copilot_checks = [check for check in all_checks if _is_copilot_check(check)]
	technical_checks = [
		check for check in all_checks if _norm(check.get("name")) in REQUIRED_TECHNICAL_CHECK_NAMES
	]
	author = pr.get("author")
	return {
		"head_sha": head_sha,
		"base_ref": pr.get("baseRefName"),
		"is_draft": bool(pr.get("isDraft")),
		"author_login": author.get("login") if isinstance(author, dict) else None,
		"event_action": os.environ.get("REVIEW_GATE_EVENT_ACTION", ""),
		"requested_reviewer": os.environ.get("REVIEW_GATE_REQUESTED_REVIEWER", ""),
		"requested_reviewers": requested_reviewers,
		"reviews": reviews,
		"latest_opinionated_reviews": opinionated,
		"copilot_checks": copilot_checks,
		"technical_checks": technical_checks,
		"incomplete_data": False,
		"policy": {
			"require_copilot_approval": os.environ.get("REVIEW_GATE_REQUIRE_COPILOT_APPROVAL", "true").lower()
			== "true",
			"require_copilot_head_review": os.environ.get("REVIEW_GATE_REQUIRE_COPILOT_HEAD_REVIEW", "true").lower()
			== "true",
			"require_independent_for_copilot_author": True,
			"require_technical_checks": os.environ.get("REVIEW_GATE_REQUIRE_TECHNICAL_CHECKS", "true").lower()
			== "true",
		},
	}


def format_result(result: GateResult) -> str:
	lines = [f"Review Lifecycle Gate: {result.status.upper()}"]
	for reason in result.reasons:
		lines.append(f"- {reason}")
	return "\n".join(lines)


def main(argv: list[str]) -> int:
	parser = argparse.ArgumentParser()
	parser.add_argument("--input", help="JSON snapshot to evaluate")
	args = parser.parse_args(argv)

	try:
		if args.input:
			with open(args.input, "r", encoding="utf-8") as handle:
				snapshot = json.load(handle)
		else:
			snapshot = collect_snapshot_from_github()
		result = decide(snapshot)
	except Exception as exc:
		print(f"Review Lifecycle Gate: FAIL ({exc})", file=sys.stderr)
		print("Review Lifecycle Gate: FAIL")
		print("- GitHub collection or evaluation failed closed")
		return 1

	print(format_result(result))
	if result.status in {"pass", "skip"}:
		return 0
	if result.status == "pending":
		advisory = os.environ.get("REVIEW_GATE_ADVISORY", "false").lower() == "true"
		print("::warning::Review Lifecycle Gate is pending; the current HEAD is not merge-ready.")
		return 0 if advisory else 1
	return 1


if __name__ == "__main__":
	raise SystemExit(main(sys.argv[1:]))
