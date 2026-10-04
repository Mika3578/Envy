#!/usr/bin/env python3
"""Offline tests for exact-HEAD Final review gate."""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location(
    "final_review_gate_mod", SCRIPTS / "final-review-gate.py"
)
MOD = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = MOD
_SPEC.loader.exec_module(MOD)

HEAD = "a" * 40
OLD = "b" * 40
COPILOT = "copilot-pull-request-reviewer[bot]"


def snap(**kwargs):
    base = {
        "pr_number": 397,
        "head_sha": HEAD,
        "current_head_sha": HEAD,
        "is_draft": False,
        "review_decision": "APPROVED",
        "review_decision_source": "graphql",
        "review_decision_unavailable": False,
        "merge_state_status": "CLEAN",
        "pr_author_login": "alice",
        "copilot_classification": "APPROVED",
        "unresolved_threads": 0,
        "untreated_threads": 0,
        "untreated_pr_level_findings": [],
        "previously_missed_titles": [],
        "suppressed_comment_titles": [],
        "open_finding_titles": [],
        "changed_files": ["Envy/Buffer.cpp"],
        "required_checks": [{"name": "Format Check", "state": "SUCCESS"}],
        "reviews": [
            {
                "id": 1,
                "user": {"login": COPILOT},
                "commit_id": HEAD,
                "state": "APPROVED",
            }
        ],
        "finding_ledger": [],
        "copilot_request_pending": False,
        "bot_findings_before_copilot": 3,
        "copilot_findings_after_stabilization": 0,
    }
    base.update(kwargs)
    for review in base.get("reviews") or []:
        if not isinstance(review, dict):
            continue
        user = review.setdefault("user", {})
        if "type" not in user:
            login = str(user.get("login") or "")
            user["type"] = (
                "Bot"
                if login.endswith("[bot]") or "copilot" in login.casefold()
                else "User"
            )
    return base


class FinalReviewGateTests(unittest.TestCase):
    def test_exact_head_approved_success(self):
        out = MOD.evaluate_final_review_gate(snap())
        self.assertEqual(out["state"], MOD.STATE_SUCCESS)
        self.assertTrue(out["allow_publish"])
        self.assertEqual(out["publish_sha"], HEAD)
        self.assertEqual(out["context"], "Final review gate")

    def test_commented_blocked(self):
        out = MOD.evaluate_final_review_gate(
            snap(reviews=[{"user": {"login": COPILOT}, "commit_id": HEAD, "state": "COMMENTED"}])
        )
        self.assertEqual(out["state"], MOD.STATE_FAILURE)
        self.assertIn("COMMENTED", out["reason"])

    def test_changes_requested_blocked(self):
        out = MOD.evaluate_final_review_gate(snap(review_decision="CHANGES_REQUESTED"))
        self.assertEqual(out["state"], MOD.STATE_FAILURE)

    def test_missing_review_pending(self):
        out = MOD.evaluate_final_review_gate(snap(reviews=[]))
        self.assertEqual(out["state"], MOD.STATE_PENDING)
        self.assertIn("no Copilot review", out["reason"])

    def test_review_pending_blocked(self):
        out = MOD.evaluate_final_review_gate(snap(copilot_request_pending=True, reviews=[]))
        self.assertEqual(out["state"], MOD.STATE_PENDING)
        self.assertIn("pending", out["reason"])

    def test_old_head_approved_blocked(self):
        out = MOD.evaluate_final_review_gate(
            snap(
                reviews=[
                    {"user": {"login": COPILOT}, "commit_id": OLD, "state": "APPROVED"}
                ]
            )
        )
        self.assertEqual(out["state"], MOD.STATE_PENDING)
        self.assertNotEqual(out["state"], MOD.STATE_SUCCESS)

    def test_push_after_approved_blocked(self):
        out = MOD.evaluate_final_review_gate(
            snap(
                head_sha=HEAD,
                current_head_sha=HEAD,
                reviews=[
                    {"user": {"login": COPILOT}, "commit_id": OLD, "state": "APPROVED"}
                ],
            )
        )
        self.assertNotEqual(out["state"], MOD.STATE_SUCCESS)

    def test_late_old_review_event_blocked(self):
        out = MOD.evaluate_final_review_gate(
            snap(
                head_sha=HEAD,
                reviews=[
                    {"user": {"login": COPILOT}, "commit_id": OLD, "state": "APPROVED"}
                ],
            )
        )
        self.assertNotEqual(out["state"], MOD.STATE_SUCCESS)

    def test_unresolved_thread_blocked(self):
        out = MOD.evaluate_final_review_gate(snap(unresolved_threads=2))
        self.assertEqual(out["state"], MOD.STATE_FAILURE)

    def test_pr_level_finding_without_inline_thread_blocked(self):
        out = MOD.evaluate_final_review_gate(
            snap(untreated_pr_level_findings=["Overview: bounds defect"])
        )
        self.assertEqual(out["state"], MOD.STATE_FAILURE)

    def test_previously_missed_blocked(self):
        out = MOD.evaluate_final_review_gate(
            snap(previously_missed_titles=["BOM bypass"])
        )
        self.assertEqual(out["state"], MOD.STATE_FAILURE)

    def test_api_error_fail_closed(self):
        out = MOD.evaluate_final_review_gate(snap(api_error=True))
        self.assertEqual(out["state"], MOD.STATE_ERROR)
        self.assertFalse(out["allow_publish"])

    def test_unknown_reviewer_fail_closed(self):
        out = MOD.evaluate_final_review_gate(
            snap(
                reviews=[
                    {
                        "user": {"login": "copilot-imposter"},
                        "commit_id": HEAD,
                        "state": "APPROVED",
                    }
                ]
            )
        )
        self.assertEqual(out["state"], MOD.STATE_ERROR)
        self.assertFalse(out["allow_publish"])

    def test_duplicate_events_idempotent(self):
        a = MOD.evaluate_final_review_gate(snap())
        b = MOD.evaluate_final_review_gate(snap())
        self.assertEqual(a["state"], b["state"])
        self.assertEqual(a["publish_sha"], b["publish_sha"])
        self.assertEqual(a["reasons"], b["reasons"])

    def test_duplicate_request_same_sha_prevented(self):
        out = MOD.should_request_copilot(snap())
        self.assertFalse(out["request"])

    def test_request_once_when_stable_without_review(self):
        out = MOD.should_request_copilot(snap(reviews=[]))
        self.assertTrue(out["request"])
        blocked = MOD.should_request_copilot(snap(reviews=[], requires_human=True))
        self.assertFalse(blocked["request"])
        blocked = MOD.should_request_copilot(snap(reviews=[], loop_guard="persistent_human_decision"))
        self.assertFalse(blocked["request"])
        blocked = MOD.should_request_copilot(snap(reviews=[], human_stop_review_ids=["1"]))
        self.assertFalse(blocked["request"])

    def test_head_change_during_evaluation_no_stale_success(self):
        out = MOD.evaluate_final_review_gate(snap(current_head_sha=OLD))
        self.assertNotEqual(out["state"], MOD.STATE_SUCCESS)
        self.assertFalse(out["allow_publish"])

    def test_privileged_rename_source_requires_human(self):
        out = MOD.evaluate_final_review_gate(
            snap(
                changed_files=[
                    {
                        "filename": "docs/README.md",
                        "previous_filename": "AGENTS.md",
                    }
                ]
            )
        )
        self.assertEqual(out["state"], MOD.STATE_FAILURE)
        self.assertTrue(out["privileged_paths"])

    def test_privileged_governance_requires_human(self):
        out = MOD.evaluate_final_review_gate(
            snap(changed_files=["AGENTS.md", ".github/workflows/build.yml"])
        )
        self.assertEqual(out["state"], MOD.STATE_FAILURE)
        self.assertTrue(out["privileged_paths"])
        self.assertIn("human APPROVED", out["reason"])

    def test_dismissed_human_approval_does_not_count(self):
        out = MOD.evaluate_final_review_gate(
            snap(
                changed_files=["AGENTS.md"],
                reviews=[
                    {
                        "id": 1,
                        "user": {"login": COPILOT, "type": "Bot"},
                        "commit_id": HEAD,
                        "state": "APPROVED",
                    },
                    {
                        "id": 2,
                        "user": {"login": "bob", "type": "User"},
                        "commit_id": HEAD,
                        "state": "APPROVED",
                    },
                    {
                        "id": 3,
                        "user": {"login": "bob", "type": "User"},
                        "commit_id": HEAD,
                        "state": "DISMISSED",
                    },
                ],
            )
        )
        self.assertEqual(out["state"], MOD.STATE_FAILURE)
        self.assertTrue(out["privileged_paths"])
        self.assertIn("independent human APPROVED", out["reason"])

    def test_dismissed_human_approval_newest_first_api_order(self):
        # GitHub may return newest-first; an older APPROVED must not overwrite
        # a later DISMISSED just because it appears later in the list.
        out = MOD.evaluate_final_review_gate(
            snap(
                changed_files=[".github/review-ledgers/pr-1.json"],
                reviews=[
                    {
                        "id": 30,
                        "user": {"login": COPILOT, "type": "Bot"},
                        "commit_id": HEAD,
                        "state": "APPROVED",
                    },
                    {
                        "id": 20,
                        "user": {"login": "bob", "type": "User"},
                        "commit_id": HEAD,
                        "state": "DISMISSED",
                        "submitted_at": "2026-10-04T02:00:00Z",
                    },
                    {
                        "id": 10,
                        "user": {"login": "bob", "type": "User"},
                        "commit_id": HEAD,
                        "state": "APPROVED",
                        "submitted_at": "2026-10-04T01:00:00Z",
                    },
                ],
            )
        )
        self.assertEqual(out["state"], MOD.STATE_FAILURE)
        self.assertTrue(out["privileged_paths"])
        self.assertTrue(MOD.is_privileged_path(".github/review-ledgers/pr-1.json"))
        self.assertIn("independent human APPROVED", out["reason"])

    def test_privileged_with_human_and_copilot_success(self):
        out = MOD.evaluate_final_review_gate(
            snap(
                changed_files=[".github/scripts/final-review-gate.py"],
                reviews=[
                    {
                        "user": {"login": COPILOT},
                        "commit_id": HEAD,
                        "state": "APPROVED",
                    },
                    {
                        "user": {"login": "bob"},
                        "commit_id": HEAD,
                        "state": "APPROVED",
                    },
                ],
            )
        )
        self.assertEqual(out["state"], MOD.STATE_SUCCESS)
        self.assertTrue(out["privileged_paths"])

    def test_self_only_gate_check_cannot_succeed(self):
        out = MOD.evaluate_final_review_gate(
            snap(required_checks=[{
                "name": "Final review gate",
                "integration_id": MOD.GATE_PUBLISHER_INTEGRATION_ID,
                "state": "SUCCESS",
            }])
        )
        self.assertNotEqual(out["state"], MOD.STATE_SUCCESS)

    def test_scripts_review_is_privileged(self):
        out = MOD.evaluate_final_review_gate(
            snap(changed_files=["scripts/review/required_checks.py"])
        )
        self.assertTrue(out["privileged_paths"])
        self.assertEqual(out["state"], MOD.STATE_FAILURE)

    def test_pr_cannot_count_own_gate_check(self):
        out = MOD.evaluate_final_review_gate(
            snap(
                required_checks=[
                    {"name": "Format Check", "state": "SUCCESS"},
                    {
                        "name": "Final review gate",
                        "integration_id": MOD.GATE_PUBLISHER_INTEGRATION_ID,
                        "state": "PENDING",
                    },
                ]
            )
        )
        self.assertEqual(out["state"], MOD.STATE_SUCCESS)

    def test_foreign_final_review_gate_receipt_is_required(self):
        out = MOD.evaluate_final_review_gate(
            snap(
                required_checks=[
                    {"name": "Format Check", "state": "SUCCESS"},
                    {
                        "name": "Final review gate",
                        "integration_id": 99999,
                        "state": "FAILURE",
                    },
                ]
            )
        )
        self.assertEqual(out["state"], MOD.STATE_FAILURE)

    def test_draft_not_success(self):
        out = MOD.evaluate_final_review_gate(snap(is_draft=True))
        self.assertEqual(out["state"], MOD.STATE_PENDING)

    def test_cli_round_trip(self):
        import subprocess

        proc = subprocess.run(
            [sys.executable, str(SCRIPTS / "final-review-gate.py")],
            input=json.dumps(snap()),
            text=True,
            capture_output=True,
            check=True,
        )
        data = json.loads(proc.stdout)
        self.assertEqual(data["state"], MOD.STATE_SUCCESS)

    def test_post_review_new_thread_not_success(self):
        pre = snap(unresolved_threads=0, reviews=[])
        self.assertTrue(MOD.should_request_copilot(pre)["request"])
        post = snap(
            reviews=[{"user": {"login": COPILOT}, "commit_id": HEAD, "state": "COMMENTED"}],
            unresolved_threads=1,
            open_finding_titles=["PowerShell caret"],
        )
        gate = MOD.evaluate_final_review_gate(post)
        self.assertNotEqual(gate["state"], MOD.STATE_SUCCESS)
        self.assertFalse(gate.get("allow_publish") and gate["state"] == MOD.STATE_SUCCESS)

    def test_overview_finding_without_thread_not_success(self):
        out = MOD.evaluate_final_review_gate(
            snap(
                unresolved_threads=0,
                open_finding_titles=["Overview bounds defect"],
                reviews=[{"user": {"login": COPILOT}, "commit_id": HEAD, "state": "COMMENTED"}],
            )
        )
        self.assertNotEqual(out["state"], MOD.STATE_SUCCESS)

    def test_pre_copilot_snapshot_cannot_publish_success(self):
        out = MOD.evaluate_final_review_gate(snap(snapshot_phase="pre_copilot_request"))
        self.assertNotEqual(out["state"], MOD.STATE_SUCCESS)

    def test_revalidate_refuses_success_when_late_thread_appears(self):
        first = MOD.evaluate_final_review_gate(snap())
        self.assertEqual(first["state"], MOD.STATE_SUCCESS)
        live = snap(unresolved_threads=1)
        out = MOD.revalidate_gate_before_success(first, live)
        self.assertNotEqual(out["state"], MOD.STATE_SUCCESS)
        self.assertFalse(out["allow_publish"])

    def test_revalidate_refuses_success_when_head_moved(self):
        first = MOD.evaluate_final_review_gate(snap())
        live = snap(current_head_sha=OLD, head_sha=OLD, reviews=[])
        out = MOD.revalidate_gate_before_success(first, live)
        self.assertNotEqual(out["state"], MOD.STATE_SUCCESS)
        self.assertFalse(out["allow_publish"])


    def test_graphql_changes_requested_blocks_success(self):
        out = MOD.evaluate_final_review_gate(snap(review_decision="CHANGES_REQUESTED"))
        self.assertEqual(out["state"], MOD.STATE_FAILURE)
        self.assertIn("CHANGES_REQUESTED", out["reason"])

    def test_review_decision_unavailable_fail_closed(self):
        out = MOD.evaluate_final_review_gate(snap(review_decision_unavailable=True))
        self.assertEqual(out["state"], MOD.STATE_ERROR)
        self.assertFalse(out["allow_publish"])

    def test_rest_review_decision_source_fail_closed(self):
        out = MOD.evaluate_final_review_gate(snap(review_decision_source="rest"))
        self.assertEqual(out["state"], MOD.STATE_ERROR)

    def test_empty_review_decision_blocks_success(self):
        out = MOD.evaluate_final_review_gate(snap(review_decision=""))
        self.assertEqual(out["state"], MOD.STATE_FAILURE)
        self.assertIn("not APPROVED", out["reason"])

    def test_review_required_decision_blocks_success(self):
        out = MOD.evaluate_final_review_gate(snap(review_decision="REVIEW_REQUIRED"))
        self.assertEqual(out["state"], MOD.STATE_FAILURE)

    def test_author_cannot_satisfy_privileged_human_approval(self):
        out = MOD.evaluate_final_review_gate(
            snap(
                pr_author_login="alice",
                changed_files=["AGENTS.md"],
                reviews=[
                    {"user": {"login": COPILOT}, "commit_id": HEAD, "state": "APPROVED"},
                    {"user": {"login": "alice"}, "commit_id": HEAD, "state": "APPROVED"},
                ],
            )
        )
        self.assertEqual(out["state"], MOD.STATE_FAILURE)
        self.assertIn("independent human APPROVED", out["reason"])

    def test_bot_cannot_satisfy_privileged_human_approval(self):
        out = MOD.evaluate_final_review_gate(
            snap(
                changed_files=["AGENTS.md"],
                reviews=[
                    {"user": {"login": COPILOT}, "commit_id": HEAD, "state": "APPROVED"},
                    {
                        "user": {"login": "github-actions[bot]"},
                        "commit_id": HEAD,
                        "state": "APPROVED",
                    },
                ],
            )
        )
        self.assertEqual(out["state"], MOD.STATE_FAILURE)

    def test_approved_github_state_malformed_classification_blocked(self):
        out = MOD.evaluate_final_review_gate(snap(copilot_classification="MALFORMED"))
        self.assertEqual(out["state"], MOD.STATE_FAILURE)

    def test_approved_github_state_closer_look_blocked(self):
        out = MOD.evaluate_final_review_gate(
            snap(copilot_classification="CLOSER_LOOK_DIAGNOSTIC")
        )
        self.assertEqual(out["state"], MOD.STATE_FAILURE)

    def test_approved_github_state_validation_missing_blocked(self):
        out = MOD.evaluate_final_review_gate(snap(copilot_classification="VALIDATION_MISSING"))
        self.assertEqual(out["state"], MOD.STATE_FAILURE)

    def test_missing_classification_fail_closed(self):
        out = MOD.evaluate_final_review_gate(snap(copilot_classification=""))
        self.assertEqual(out["state"], MOD.STATE_ERROR)
        self.assertFalse(out["allow_publish"])

    def test_classifier_missing_flag_fail_closed(self):
        out = MOD.evaluate_final_review_gate(snap(classifier_missing=True))
        self.assertEqual(out["state"], MOD.STATE_ERROR)

    def test_canonical_skipped_required_check_is_not_gate_success(self):
        # SKIPPED remains a Draft/host scheduling receipt, not final-gate green.
        self.assertIn("SKIPPED", MOD.PASSING_CHECK_STATES)
        self.assertNotIn("SKIPPED", MOD.GATE_PASSING_CHECK_STATES)
        out = MOD.evaluate_final_review_gate(
            snap(required_checks=[{"name": "Build x64 Release", "state": "SKIPPED"}])
        )
        self.assertEqual(out["state"], MOD.STATE_FAILURE)

    def test_quota_review_does_not_retry_same_sha(self):
        out = MOD.should_request_copilot(
            snap(
                copilot_classification="COPILOT_QUOTA_BLOCKED",
                reviews=[
                    {
                        "user": {"login": COPILOT},
                        "commit_id": HEAD,
                        "state": "COMMENTED",
                    }
                ],
            )
        )
        self.assertFalse(out["request"])
        self.assertIn("already reviewed", out["reason"])

    def test_unsuffixed_bot_cannot_satisfy_human_approval(self):
        out = MOD.evaluate_final_review_gate(
            snap(
                changed_files=["AGENTS.md"],
                reviews=[
                    {"user": {"login": COPILOT, "type": "Bot"}, "commit_id": HEAD, "state": "APPROVED"},
                    {"user": {"login": "review-app", "type": "Bot"}, "commit_id": HEAD, "state": "APPROVED"},
                ],
            )
        )
        self.assertEqual(out["state"], MOD.STATE_FAILURE)

    def test_missing_current_head_sha_fail_closed(self):
        out = MOD.evaluate_final_review_gate(snap(current_head_sha=""))
        self.assertEqual(out["state"], MOD.STATE_ERROR)

    def test_should_request_rejects_mismatched_head(self):
        out = MOD.should_request_copilot(snap(reviews=[], current_head_sha=OLD))
        self.assertFalse(out["request"])

    def test_should_request_blocks_untreated_threads(self):
        out = MOD.should_request_copilot(snap(reviews=[], untreated_threads=1))
        self.assertFalse(out["request"])

    def test_should_request_blocks_suppressed_comment_titles(self):
        out = MOD.should_request_copilot(
            snap(reviews=[], suppressed_comment_titles=["Include suppressed comment titles"])
        )
        self.assertFalse(out["request"])
        self.assertEqual(out["reason"], "untreated findings remain")

    def test_should_request_blocks_behind_or_unknown_merge_state(self):
        for state in ("BEHIND", "DIRTY", "UNSTABLE", "UNKNOWN", ""):
            with self.subTest(state=state):
                out = MOD.should_request_copilot(snap(reviews=[], merge_state_status=state))
                self.assertFalse(out["request"])
                self.assertIn("merge state not ready", out["reason"])
        allowed = MOD.should_request_copilot(snap(reviews=[], merge_state_status="BLOCKED"))
        self.assertTrue(allowed["request"])

    def test_should_request_rejects_non_int_unresolved_threads(self):
        out = MOD.should_request_copilot(snap(reviews=[], unresolved_threads=None))
        self.assertFalse(out["request"])
        self.assertIn("unresolved", out["reason"])

    def test_success_requires_ready_merge_state(self):
        out = MOD.evaluate_final_review_gate(snap(merge_state_status="BEHIND"))
        self.assertEqual(out["state"], MOD.STATE_FAILURE)
        self.assertIn("merge state not ready", out["reasons"][0])
        blocked = MOD.evaluate_final_review_gate(snap(merge_state_status="BLOCKED"))
        self.assertEqual(blocked["state"], MOD.STATE_FAILURE)

    def test_skipped_required_check_blocks_gate_success(self):
        out = MOD.evaluate_final_review_gate(
            snap(required_checks=[{"name": "Build x64 Release", "state": "SKIPPED"}])
        )
        self.assertEqual(out["state"], MOD.STATE_FAILURE)
        self.assertTrue(any("SKIPPED" in reason for reason in out["reasons"]))

    def test_revalidate_rejects_skipped_required_check(self):
        ok = MOD.evaluate_final_review_gate(snap())
        self.assertEqual(ok["state"], MOD.STATE_SUCCESS)
        live = snap(required_checks=[{"name": "Build x64 Release", "state": "SKIPPED"}])
        out = MOD.revalidate_gate_before_success(ok, live)
        self.assertNotEqual(out["state"], MOD.STATE_SUCCESS)
        self.assertFalse(out["allow_publish"])

    def test_should_request_blocks_self_only_required_check(self):
        out = MOD.should_request_copilot(
            snap(reviews=[], required_checks=[{
                "name": "Final review gate",
                "integration_id": MOD.GATE_PUBLISHER_INTEGRATION_ID,
                "state": "SUCCESS",
            }])
        )
        self.assertFalse(out["request"])

    def test_resolved_without_reply_blocks_success(self):
        out = MOD.evaluate_final_review_gate(snap(untreated_threads=1))
        self.assertEqual(out["state"], MOD.STATE_FAILURE)

    def test_latest_copilot_review_uses_highest_id(self):
        reviews = [
            {"id": 9, "user": {"login": COPILOT}, "commit_id": HEAD, "state": "COMMENTED",
             "submitted_at": "2026-10-03T19:00:00Z"},
            {"id": 2, "user": {"login": COPILOT}, "commit_id": HEAD, "state": "APPROVED",
             "submitted_at": "2026-10-03T18:00:00Z"},
        ]
        latest = MOD.latest_copilot_review(reviews, HEAD)
        self.assertEqual(latest["id"], 9)
        self.assertEqual(latest["state"], "COMMENTED")

    def test_persistent_human_stop_blocks_success(self):
        out = MOD.evaluate_final_review_gate(snap(requires_human=True, loop_guard="persistent_human_decision"))
        self.assertEqual(out["state"], MOD.STATE_FAILURE)
        out = MOD.evaluate_final_review_gate(snap(human_stop_review_ids=["prior-human-review"]))
        self.assertEqual(out["state"], MOD.STATE_FAILURE)

    def test_copilot_authored_pr_cannot_self_approve(self):
        out = MOD.evaluate_final_review_gate(snap(pr_author_login="copilot-swe-agent[bot]"))
        self.assertEqual(out["state"], MOD.STATE_FAILURE)

    def test_thanks_reply_is_not_a_disposition(self):
        comments = [
            {"author": {"login": COPILOT, "__typename": "Bot"}, "commit": {"oid": HEAD}},
            {"author": {"login": "alice", "__typename": "User"}, "commit": {"oid": HEAD},
             "body": "thanks"},
        ]
        self.assertTrue(MOD.resolved_thread_is_untreated(comments, HEAD))
        comments[1]["body"] = f"Fixed on `{HEAD[:7]}`. Regression selftest covers the bound."
        self.assertFalse(MOD.resolved_thread_is_untreated(comments, HEAD))

    def test_marker_only_disposition_is_untreated(self):
        comments = [
            {"author": {"login": COPILOT, "__typename": "Bot"}, "commit": {"oid": HEAD}},
            {"author": {"login": "alice", "__typename": "User"}, "commit": {"oid": HEAD},
             "body": "<!-- envy-disposition -->"},
        ]
        self.assertTrue(MOD.resolved_thread_is_untreated(comments, HEAD))

    def test_outdated_thread_requires_current_head_cite(self):
        comments = [
            {"author": {"login": COPILOT, "__typename": "Bot"}, "commit": {"oid": "b" * 40}},
            {"author": {"login": "alice", "__typename": "User"}, "commit": {"oid": "b" * 40},
             "body": f"Fixed on `{'b' * 7}`. Old justification without current HEAD."},
        ]
        self.assertTrue(MOD.resolved_thread_is_untreated(comments, HEAD, outdated=True))
        comments[1]["body"] = f"Fixed on `{HEAD[:7]}`. Revalidated on current HEAD after later push."
        self.assertFalse(MOD.resolved_thread_is_untreated(comments, HEAD, outdated=True))

    def test_copilot_logins_exclude_swe_coding_agent(self):
        self.assertNotIn("copilot-swe-agent", MOD.COPILOT_LOGINS)
        self.assertNotIn("copilot-swe-agent[bot]", MOD.COPILOT_LOGINS)
        self.assertIn("copilot-pull-request-reviewer[bot]", MOD.COPILOT_LOGINS)
        # SWE-agent must not satisfy "Copilot already reviewed this HEAD".
        reviews = [{"id": 1, "user": {"login": "copilot-swe-agent[bot]"},
                    "commit_id": HEAD, "state": "COMMENTED"}]
        self.assertIsNone(MOD.latest_copilot_review(reviews, HEAD))
        out = MOD.should_request_copilot(snap(reviews=reviews))
        self.assertNotEqual(out.get("reason"), "Copilot already reviewed this HEAD")


if __name__ == "__main__":
    unittest.main()
