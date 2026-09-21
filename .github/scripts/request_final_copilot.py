#!/usr/bin/env python3
"""Decide whether to request a final Copilot Code Review.

Pure decision engine. Trusted workflows call this, then mutate reviewers
with GitHub GraphQL from inline bash so this file is never executed from
an untrusted pull-request checkout with pull-requests:write.
"""

from __future__ import annotations

from typing import Any

from review_lifecycle_gate import (
	IN_FLIGHT_CHECK_STATUSES,
	REQUIRED_TECHNICAL_CHECK_NAMES,
	_author_login,
	_collect_commit_checks,
	_commit_oid,
	_is_copilot_check,
	_is_copilot_reviewer,
	_login,
	_lower,
	_norm,
	_paginate_pr_connection,
	_pull_request_from_graphql,
	_run_gh_graphql,
	_technical_check_results,
)


def _requested_logins(snapshot: dict[str, Any]) -> set[str]:
	logins: set[str] = set()
	raw = snapshot.get("requested_reviewers") or []
	if not isinstance(raw, list):
		return logins
	for item in raw:
		if isinstance(item, str):
			logins.add(_login(item))
		elif isinstance(item, dict):
			logins.add(_author_login(item))
	return logins


def _changes_requested_reason(snapshot: dict[str, Any]) -> str | None:
	if "latest_opinionated_reviews" not in snapshot:
		return "missing latest opinionated review data"
	opinionated = snapshot.get("latest_opinionated_reviews")
	if opinionated is None:
		return "missing latest opinionated review data"
	if not isinstance(opinionated, list):
		return "invalid opinionated review data"
	for review in opinionated:
		if not isinstance(review, dict):
			continue
		if _lower(review.get("state")) == "changes_requested":
			return "active CHANGES_REQUESTED review"
	return None


def _pre_review_block_reason(snapshot: dict[str, Any], head: str) -> str | None:
	blocked = _changes_requested_reason(snapshot)
	if blocked:
		return blocked
	fail, pending = _technical_check_results(snapshot, head, True)
	if fail:
		first = fail[0]
		if first == "invalid technical check data":
			return first
		return f"pre-review not finished: {first}"
	if pending:
		return f"pre-review not finished: {pending[0]}"
	return None


def _copilot_running_reason(snapshot: dict[str, Any], head: str) -> str | None:
	if "copilot_checks" not in snapshot:
		return "missing Copilot check data"
	copilot_checks = snapshot.get("copilot_checks")
	if copilot_checks is None:
		return "missing Copilot check data"
	if not isinstance(copilot_checks, list):
		return "invalid Copilot check data"
	for check in copilot_checks:
		if not isinstance(check, dict):
			continue
		if not _is_copilot_check(check):
			continue
		check_sha = _norm(check.get("head_sha") or head)
		if check_sha and check_sha != head:
			continue
		status = _lower(check.get("status"))
		if status in IN_FLIGHT_CHECK_STATUSES or status == "":
			return "Copilot review is already running"
	return None


def _copilot_reviewed_head_reason(snapshot: dict[str, Any], head: str) -> str | None:
	reviews = snapshot.get("reviews") or []
	if not isinstance(reviews, list):
		return "invalid reviews data"
	for review in reviews:
		if not isinstance(review, dict):
			continue
		if _commit_oid(review) != head:
			continue
		if _lower(review.get("state")) == "dismissed":
			continue
		if _is_copilot_reviewer(_author_login(review)):
			return "Copilot already reviewed this HEAD"
	return None


def _copilot_already_active_reason(snapshot: dict[str, Any], head: str, force: bool) -> str | None:
	if force:
		return None
	if any(_is_copilot_reviewer(login) for login in _requested_logins(snapshot)):
		return "Copilot is already requested"
	running = _copilot_running_reason(snapshot, head)
	if running:
		return running
	return _copilot_reviewed_head_reason(snapshot, head)


def _request_shape_reason(snapshot: dict[str, Any]) -> str | None:
	if not bool(snapshot.get("is_open", True)):
		return "pull request is not open"
	if bool(snapshot.get("is_draft") or snapshot.get("isDraft")):
		return "pull request is draft"
	base = _norm(snapshot.get("base_ref") or snapshot.get("baseRefName"))
	if base != "develop":
		return f"base is {base or 'missing'}, not develop"
	if snapshot.get("same_repo") is False:
		return "fork pull request"
	head = _norm(snapshot.get("head_sha") or snapshot.get("headRefOid"))
	if not head:
		return "missing head SHA"
	expected = _norm(snapshot.get("expected_sha") or head)
	if expected and head != expected:
		return "HEAD changed since the triggering workflow"
	if snapshot.get("incomplete_data") or snapshot.get("pagination_unhandled"):
		return "incomplete GitHub data; failing closed without request"
	return None


def should_request_copilot(snapshot: dict[str, Any], *, force: bool = False) -> dict[str, str]:
	"""Return action=request|noop and a reason. Never contacts the network."""

	shape = _request_shape_reason(snapshot)
	if shape:
		return {"action": "noop", "reason": shape}
	head = _norm(snapshot.get("head_sha") or snapshot.get("headRefOid"))
	blocked = _pre_review_block_reason(snapshot, head)
	if blocked:
		return {"action": "noop", "reason": blocked}
	busy = _copilot_already_active_reason(snapshot, head, force)
	if busy:
		return {"action": "noop", "reason": busy}
	return {"action": "request", "reason": "pre-review ready; request one final Copilot review"}


def collect_live_request_snapshot(owner: str, name: str, number: int, expected_sha: str) -> dict[str, Any]:
	header = _run_gh_graphql(
		"""
query($owner:String!, $name:String!, $number:Int!) {
  repository(owner:$owner, name:$name) {
    pullRequest(number:$number) {
      id
      isDraft
      state
      isCrossRepository
      headRefOid
      baseRefName
    }
  }
}
""",
		{"owner": owner, "name": name, "number": number},
	)
	pr = _pull_request_from_graphql(header)
	head = _norm(pr.get("headRefOid"))
	all_checks = _collect_commit_checks(f"{owner}/{name}", head)
	reviews = _paginate_pr_connection(
		owner, name, number, "reviews", "state author { login } commit { oid }"
	)
	opinionated = _paginate_pr_connection(
		owner, name, number, "latestOpinionatedReviews", "state author { login } commit { oid }"
	)
	req_nodes = _paginate_pr_connection(
		owner,
		name,
		number,
		"reviewRequests",
		"requestedReviewer { __typename ... on Bot { login } ... on User { login id } ... on Team { slug id } }",
	)
	requested = []
	for node in req_nodes:
		reviewer = node.get("requestedReviewer") if isinstance(node, dict) else None
		if isinstance(reviewer, dict):
			requested.append(reviewer.get("login") or reviewer.get("slug"))
	return {
		"is_open": _lower(pr.get("state")) == "open",
		"is_draft": bool(pr.get("isDraft")),
		"base_ref": pr.get("baseRefName"),
		"same_repo": not bool(pr.get("isCrossRepository")),
		"head_sha": head,
		"expected_sha": expected_sha or head,
		"reviews": reviews,
		"latest_opinionated_reviews": opinionated,
		"requested_reviewers": requested,
		"copilot_checks": [check for check in all_checks if _is_copilot_check(check)],
		"technical_checks": [
			check for check in all_checks if _norm(check.get("name")) in REQUIRED_TECHNICAL_CHECK_NAMES
		],
		"incomplete_data": False,
		"pr_id": pr.get("id"),
	}


if __name__ == "__main__":
	import argparse
	import json

	parser = argparse.ArgumentParser()
	parser.add_argument("--snapshot")
	parser.add_argument("--collect-output")
	parser.add_argument("--owner")
	parser.add_argument("--name")
	parser.add_argument("--number", type=int)
	parser.add_argument("--expected-sha", default="")
	parser.add_argument("--force", action="store_true")
	args = parser.parse_args()
	if args.collect_output:
		if not args.owner or not args.name or not args.number:
			raise SystemExit("--collect-output requires --owner --name --number")
		snapshot = collect_live_request_snapshot(args.owner, args.name, args.number, args.expected_sha)
		with open(args.collect_output, "w", encoding="utf-8") as handle:
			json.dump(snapshot, handle)
		print(json.dumps({"pr": args.number, "head": snapshot.get("head_sha")}))
		raise SystemExit(0)
	if not args.snapshot:
		raise SystemExit("--snapshot or --collect-output is required")
	with open(args.snapshot, "r", encoding="utf-8") as handle:
		snapshot = json.load(handle)
	decision = should_request_copilot(snapshot, force=args.force)
	print(json.dumps(decision, indent=2))
	raise SystemExit(0 if decision["action"] in {"request", "noop"} else 1)
