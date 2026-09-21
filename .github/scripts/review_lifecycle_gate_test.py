#!/usr/bin/env python3
import json
import os
import tempfile
import unittest

from request_final_copilot import should_request_copilot
from review_lifecycle_gate import (
	REQUIRED_TECHNICAL_CHECK_NAMES,
	_pull_request_from_graphql,
	_resolve_pr_number,
	decide,
	main,
)


HEAD = "abc123"
OLD = "old456"


def technical_ok(head=HEAD):
	return [
		{
			"name": name,
			"status": "completed",
			"conclusion": "success",
			"head_sha": head,
		}
		for name in REQUIRED_TECHNICAL_CHECK_NAMES
	]


def snapshot(**overrides):
	data = {
		"head_sha": HEAD,
		"is_draft": False,
		"base_ref": "develop",
		"author_login": "mika3578",
		"threads": [{"isResolved": True}],
		"reviews": [
			{
				"state": "APPROVED",
				"author": {"login": "copilot-pull-request-reviewer"},
				"commit": {"oid": HEAD},
			}
		],
		"latest_opinionated_reviews": [
			{
				"state": "APPROVED",
				"author": {"login": "copilot-pull-request-reviewer"},
				"commit": {"oid": HEAD},
			}
		],
		"copilot_checks": [
			{
				"name": "copilot-pull-request-reviewer",
				"status": "completed",
				"conclusion": "success",
				"head_sha": HEAD,
			}
		],
		"technical_checks": technical_ok(),
		"incomplete_data": False,
		"policy": {
			"require_copilot_approval": True,
			"require_copilot_head_review": True,
			"require_independent_for_copilot_author": True,
			"require_technical_checks": True,
		},
	}
	data.update(overrides)
	return data


def request_snapshot(**overrides):
	data = {
		"is_open": True,
		"is_draft": False,
		"base_ref": "develop",
		"same_repo": True,
		"head_sha": HEAD,
		"expected_sha": HEAD,
		"reviews": [],
		"latest_opinionated_reviews": [],
		"requested_reviewers": [],
		"copilot_checks": [],
		"technical_checks": technical_ok(),
		"incomplete_data": False,
	}
	data.update(overrides)
	return data


class ReviewLifecycleGateTest(unittest.TestCase):
	def assertStatus(self, data, status, text=None):
		result = decide(data)
		self.assertEqual(result.status, status, result.reasons)
		if text:
			self.assertIn(text, " ".join(result.reasons))
		return result

	def test_copilot_approved_on_current_head_passes(self):
		self.assertStatus(snapshot(), "pass")

	def test_copilot_commented_on_current_head_is_not_pass(self):
		data = snapshot(
			reviews=[
				{
					"state": "COMMENTED",
					"author": {"login": "copilot-pull-request-reviewer"},
					"commit": {"oid": HEAD},
				}
			],
			latest_opinionated_reviews=[],
		)
		self.assertStatus(data, "fail", "Copilot APPROVED is required")

	def test_copilot_approved_on_old_head_is_not_pass(self):
		data = snapshot(
			reviews=[
				{
					"state": "APPROVED",
					"author": {"login": "copilot-pull-request-reviewer"},
					"commit": {"oid": OLD},
				}
			],
			latest_opinionated_reviews=[],
			copilot_checks=[],
		)
		self.assertStatus(data, "pending", "no completed Copilot review")

	def test_copilot_approved_dismissed_is_not_pass(self):
		data = snapshot(
			reviews=[
				{
					"state": "DISMISSED",
					"author": {"login": "copilot-pull-request-reviewer"},
					"commit": {"oid": HEAD},
				}
			],
			latest_opinionated_reviews=[],
			copilot_checks=[],
		)
		self.assertStatus(data, "pending", "no completed Copilot review")

	def test_human_approved_alone_is_not_pass(self):
		data = snapshot(
			reviews=[
				{"state": "APPROVED", "author": {"login": "reviewer"}, "commit": {"oid": HEAD}},
				{
					"state": "COMMENTED",
					"author": {"login": "copilot-pull-request-reviewer"},
					"commit": {"oid": HEAD},
				},
			],
			latest_opinionated_reviews=[
				{"state": "APPROVED", "author": {"login": "reviewer"}, "commit": {"oid": HEAD}}
			],
		)
		self.assertStatus(data, "fail", "Copilot APPROVED is required")

	def test_cursor_or_other_ai_approved_alone_is_not_pass(self):
		data = snapshot(
			reviews=[
				{"state": "APPROVED", "author": {"login": "cursor"}, "commit": {"oid": HEAD}},
				{"state": "APPROVED", "author": {"login": "amazon-q-developer"}, "commit": {"oid": HEAD}},
				{
					"state": "COMMENTED",
					"author": {"login": "copilot-pull-request-reviewer"},
					"commit": {"oid": HEAD},
				},
			],
			latest_opinionated_reviews=[],
		)
		self.assertStatus(data, "fail", "Copilot APPROVED is required")

	def test_no_approval_is_not_pass(self):
		data = snapshot(
			reviews=[
				{
					"state": "COMMENTED",
					"author": {"login": "copilot-pull-request-reviewer"},
					"commit": {"oid": HEAD},
				}
			],
			latest_opinionated_reviews=[],
		)
		self.assertStatus(data, "fail", "Copilot APPROVED is required")

	def test_copilot_in_progress_is_pending(self):
		data = snapshot(
			reviews=[],
			latest_opinionated_reviews=[],
			copilot_checks=[
				{
					"name": "copilot-pull-request-reviewer",
					"status": "in_progress",
					"conclusion": None,
					"head_sha": HEAD,
				}
			],
		)
		self.assertStatus(data, "pending", "still running")

	def test_copilot_review_requested_after_approval_same_head_is_pending(self):
		self.assertStatus(
			snapshot(event_action="review_requested", requested_reviewer="copilot-pull-request-reviewer"),
			"pending",
			"currently requested",
		)

	def test_live_requested_reviewers_without_head_review_is_pending(self):
		self.assertStatus(
			snapshot(
				requested_reviewers=["copilot-pull-request-reviewer"],
				reviews=[],
				latest_opinionated_reviews=[],
				copilot_checks=[],
			),
			"pending",
			"currently requested",
		)

	def test_stale_copilot_request_after_approved_head_review_is_not_pending(self):
		# GitHub may keep Copilot in reviewRequests after APPROVED; that must not block PASS.
		self.assertStatus(
			snapshot(requested_reviewers=["copilot-pull-request-reviewer"]),
			"pass",
		)

	def test_stale_copilot_request_with_commented_head_still_requires_approval(self):
		data = snapshot(
			requested_reviewers=["copilot-pull-request-reviewer"],
			reviews=[
				{
					"state": "COMMENTED",
					"author": {"login": "copilot-pull-request-reviewer"},
					"commit": {"oid": HEAD},
				}
			],
			latest_opinionated_reviews=[],
		)
		self.assertStatus(data, "fail", "Copilot APPROVED is required")

	def test_new_push_after_copilot_approval_is_not_pass(self):
		self.assertStatus(snapshot(head_sha="new789", copilot_checks=[], technical_checks=technical_ok("new789")), "pending", "no completed Copilot review")

	def test_copilot_login_alias_is_not_accepted_as_final_reviewer(self):
		data = snapshot(
			reviews=[
				{"state": "APPROVED", "author": {"login": "Copilot"}, "commit": {"oid": HEAD}},
			],
			latest_opinionated_reviews=[],
			copilot_checks=[],
		)
		self.assertStatus(data, "pending", "no completed Copilot review")

	def test_latest_copilot_review_must_be_approved(self):
		data = snapshot(
			reviews=[
				{
					"state": "APPROVED",
					"author": {"login": "copilot-pull-request-reviewer"},
					"commit": {"oid": HEAD},
					"submittedAt": "2026-09-21T08:00:00Z",
				},
				{
					"state": "COMMENTED",
					"author": {"login": "copilot-pull-request-reviewer"},
					"commit": {"oid": HEAD},
					"submittedAt": "2026-09-21T09:00:00Z",
				},
			],
			latest_opinionated_reviews=[],
		)
		self.assertStatus(data, "fail", "Copilot APPROVED is required")

	def test_unresolved_threads_do_not_fail_ci_gate(self):
		self.assertStatus(snapshot(threads=[{"isResolved": False}]), "pass")

	def test_human_review_request_does_not_reset_copilot_cycle(self):
		self.assertStatus(snapshot(event_action="review_requested", requested_reviewer="reviewer"), "pass")

	def test_changes_requested_fails(self):
		data = snapshot(
			latest_opinionated_reviews=[
				{"state": "CHANGES_REQUESTED", "author": {"login": "second"}, "commit": {"oid": HEAD}}
			]
		)
		self.assertStatus(data, "fail", "CHANGES_REQUESTED")

	def test_draft_skips_before_review_cycle(self):
		self.assertStatus(snapshot(is_draft=True, threads=[{"isResolved": False}]), "skip", "draft")

	def test_missing_data_fails_closed(self):
		self.assertStatus(snapshot(reviews=None), "fail", "missing reviews")

	def test_missing_opinionated_reviews_fails_closed(self):
		data = snapshot()
		del data["latest_opinionated_reviews"]
		self.assertStatus(data, "fail", "missing latest opinionated")

	def test_null_opinionated_reviews_fails_closed(self):
		self.assertStatus(snapshot(latest_opinionated_reviews=None), "fail", "missing latest opinionated")

	def test_missing_copilot_checks_fails_closed(self):
		data = snapshot()
		del data["copilot_checks"]
		self.assertStatus(data, "fail", "missing Copilot check")

	def test_incomplete_data_fails_closed(self):
		self.assertStatus(snapshot(incomplete_data=True), "fail", "incomplete")

	def test_pagination_unhandled_fails_closed(self):
		self.assertStatus(snapshot(pagination_unhandled=True), "fail", "pagination")

	def test_incomplete_data_fails_closed_even_for_draft(self):
		self.assertStatus(snapshot(is_draft=True, incomplete_data=True), "fail", "incomplete")

	def test_advisory_comment_is_not_copilot_completion_or_approval(self):
		data = snapshot(
			reviews=[
				{"state": "COMMENTED", "author": {"login": "amazon-q-developer"}, "commit": {"oid": HEAD}},
				{"state": "COMMENTED", "author": {"login": "sourcery-ai"}, "commit": {"oid": HEAD}},
				{"state": "COMMENTED", "author": {"login": "coderabbitai"}, "commit": {"oid": HEAD}},
			],
			latest_opinionated_reviews=[],
			copilot_checks=[],
		)
		result = self.assertStatus(data, "pending", "no completed Copilot review")
		self.assertNotIn("pass", result.status)

	def test_copilot_commented_is_not_transformed_into_approval(self):
		data = snapshot(
			reviews=[
				{
					"state": "COMMENTED",
					"author": {"login": "copilot-pull-request-reviewer"},
					"commit": {"oid": HEAD},
				}
			],
			latest_opinionated_reviews=[],
		)
		self.assertStatus(data, "fail", "Copilot APPROVED is required")

	def test_copilot_authored_pr_requires_independent_approval(self):
		data = snapshot(author_login="copilot-swe-agent")
		self.assertStatus(data, "fail", "independent approval")

	def test_cancelled_copilot_check_without_head_review_fails_closed(self):
		data = snapshot(
			reviews=[],
			latest_opinionated_reviews=[],
			copilot_checks=[
				{
					"name": "copilot-pull-request-reviewer",
					"status": "completed",
					"conclusion": "cancelled",
					"head_sha": HEAD,
				}
			],
		)
		self.assertStatus(data, "fail", "did not complete successfully")

	def test_missing_head_sha_fails_closed(self):
		self.assertStatus(snapshot(head_sha=""), "fail", "missing head SHA")

	def test_non_develop_target_is_skipped(self):
		self.assertStatus(snapshot(base_ref="main"), "skip")

	def test_main_fails_closed_on_missing_input(self):
		rc = main(["--input", "/tmp/review-lifecycle-gate-missing.json"])
		self.assertEqual(rc, 1)

	def test_main_fails_closed_on_invalid_json(self):
		with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
			handle.write("{")
			path = handle.name
		try:
			self.assertEqual(main(["--input", path]), 1)
		finally:
			os.unlink(path)

	def test_main_pass_snapshot_exits_zero(self):
		with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
			json.dump(snapshot(), handle)
			path = handle.name
		try:
			self.assertEqual(main(["--input", path]), 0)
		finally:
			os.unlink(path)

	def test_main_draft_skip_exits_zero(self):
		with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
			json.dump(snapshot(is_draft=True), handle)
			path = handle.name
		try:
			self.assertEqual(main(["--input", path]), 0)
		finally:
			os.unlink(path)

	def test_main_pending_head_review_exits_one(self):
		with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
			json.dump(snapshot(head_sha="new789", copilot_checks=[], technical_checks=technical_ok("new789")), handle)
			path = handle.name
		old = os.environ.pop("REVIEW_GATE_ADVISORY", None)
		try:
			self.assertEqual(main(["--input", path]), 1)
		finally:
			os.unlink(path)
			if old is None:
				os.environ.pop("REVIEW_GATE_ADVISORY", None)
			else:
				os.environ["REVIEW_GATE_ADVISORY"] = old

	def test_main_pending_advisory_exits_zero(self):
		with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
			json.dump(snapshot(head_sha="new789", copilot_checks=[], technical_checks=technical_ok("new789")), handle)
			path = handle.name
		old = os.environ.get("REVIEW_GATE_ADVISORY")
		os.environ["REVIEW_GATE_ADVISORY"] = "true"
		try:
			self.assertEqual(main(["--input", path]), 0)
		finally:
			os.unlink(path)
			if old is None:
				os.environ.pop("REVIEW_GATE_ADVISORY", None)
			else:
				os.environ["REVIEW_GATE_ADVISORY"] = old

	def test_graphql_missing_pull_request_fails_closed(self):
		with self.assertRaises(RuntimeError):
			_pull_request_from_graphql({"data": {"repository": {}}})

	def test_graphql_errors_fail_closed(self):
		with self.assertRaises(RuntimeError):
			_pull_request_from_graphql(
				{"data": {"repository": {"pullRequest": {}}}, "errors": [{"message": "x"}]}
			)

	def test_graphql_valid_pull_request_is_returned(self):
		pr = _pull_request_from_graphql({"data": {"repository": {"pullRequest": {"isDraft": True}}}})
		self.assertTrue(pr["isDraft"])

	def test_pr_number_from_env(self):
		self.assertEqual(_resolve_pr_number({"PR_NUMBER": "299"}), "299")

	def test_pr_number_from_github_ref_name(self):
		self.assertEqual(_resolve_pr_number({"GITHUB_REF_NAME": "299/merge"}), "299")

	def test_pr_number_missing_fails_closed(self):
		with self.assertRaises(RuntimeError):
			_resolve_pr_number({"PR_NUMBER": "", "GITHUB_REF_NAME": ""})

	def test_pr_number_non_digit_fails_closed(self):
		with self.assertRaises(RuntimeError):
			_resolve_pr_number({"GITHUB_REF_NAME": "chore/review-lifecycle-gate"})


class RequestFinalCopilotTest(unittest.TestCase):
	def test_pre_review_not_finished_does_not_request(self):
		decision = should_request_copilot(request_snapshot(technical_checks=[]))
		self.assertEqual(decision["action"], "noop")
		self.assertIn("pre-review not finished", decision["reason"])

	def test_pre_review_finished_requests_once(self):
		decision = should_request_copilot(request_snapshot())
		self.assertEqual(decision["action"], "request")

	def test_already_requested_is_noop(self):
		decision = should_request_copilot(
			request_snapshot(requested_reviewers=["copilot-pull-request-reviewer"])
		)
		self.assertEqual(decision["action"], "noop")
		self.assertIn("already requested", decision["reason"])

	def test_already_running_is_noop(self):
		decision = should_request_copilot(
			request_snapshot(
				copilot_checks=[
					{
						"name": "copilot-pull-request-reviewer",
						"status": "in_progress",
						"head_sha": HEAD,
					}
				]
			)
		)
		self.assertEqual(decision["action"], "noop")
		self.assertIn("already running", decision["reason"])

	def test_already_reviewed_same_head_is_noop(self):
		decision = should_request_copilot(
			request_snapshot(
				reviews=[
					{
						"state": "COMMENTED",
						"author": {"login": "copilot-pull-request-reviewer"},
						"commit": {"oid": HEAD},
					}
				]
			)
		)
		self.assertEqual(decision["action"], "noop")
		self.assertIn("already reviewed", decision["reason"])

	def test_force_rerequest_after_review_is_request(self):
		decision = should_request_copilot(
			request_snapshot(
				reviews=[
					{
						"state": "COMMENTED",
						"author": {"login": "copilot-pull-request-reviewer"},
						"commit": {"oid": HEAD},
					}
				]
			),
			force=True,
		)
		self.assertEqual(decision["action"], "request")


if __name__ == "__main__":
	unittest.main()
