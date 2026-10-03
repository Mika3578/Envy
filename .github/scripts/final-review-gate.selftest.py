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
        "unresolved_threads": 0,
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

    def test_head_change_during_evaluation_no_stale_success(self):
        out = MOD.evaluate_final_review_gate(snap(current_head_sha=OLD))
        self.assertNotEqual(out["state"], MOD.STATE_SUCCESS)
        self.assertFalse(out["allow_publish"])

    def test_privileged_governance_requires_human(self):
        out = MOD.evaluate_final_review_gate(
            snap(changed_files=["AGENTS.md", ".github/workflows/build.yml"])
        )
        self.assertEqual(out["state"], MOD.STATE_FAILURE)
        self.assertTrue(out["privileged_paths"])
        self.assertIn("human APPROVED", out["reason"])

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
                        "user": {"login": "Mika3578"},
                        "commit_id": HEAD,
                        "state": "APPROVED",
                    },
                ],
            )
        )
        self.assertEqual(out["state"], MOD.STATE_SUCCESS)
        self.assertTrue(out["privileged_paths"])

    def test_pr_cannot_count_own_gate_check(self):
        out = MOD.evaluate_final_review_gate(
            snap(
                required_checks=[
                    {"name": "Format Check", "state": "SUCCESS"},
                    {"name": "Final review gate", "state": "PENDING"},
                ]
            )
        )
        self.assertEqual(out["state"], MOD.STATE_SUCCESS)

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


if __name__ == "__main__":
    unittest.main()
