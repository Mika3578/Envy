#!/usr/bin/env python3
"""Regression tests for evaluate-pr-review-gate.py (no network)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
FIXTURES = SCRIPTS / "fixtures" / "pr-review-gate"
_SPEC = importlib.util.spec_from_file_location(
    "evaluate_pr_review_gate_mod", SCRIPTS / "evaluate-pr-review-gate.py"
)
MOD = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = MOD
_SPEC.loader.exec_module(MOD)


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def evaluate_fixture(name: str) -> dict:
    return MOD.evaluate_snapshot(load_fixture(name))


class EvaluatePrReviewGateTests(unittest.TestCase):
    def test_approved_fresh_head_ready(self):
        out = evaluate_fixture("ready-to-merge.json")
        self.assertTrue(out["review_complete"])
        self.assertTrue(out["merge_approval_valid"])
        self.assertTrue(out["ready_to_merge"])
        self.assertEqual(out["next_action"], MOD.READY_TO_MERGE)

    def test_stale_approved_after_push(self):
        out = evaluate_fixture("stale-after-push.json")
        self.assertFalse(out["review_complete"])
        self.assertFalse(out["merge_approval_valid"])
        self.assertTrue(out["copilot"]["stale"])
        self.assertEqual(out["next_action"], MOD.STALE_REVIEW)
        self.assertIn("stale", out["report"].lower())

    def test_commented_with_findings(self):
        out = evaluate_fixture("commented-with-findings.json")
        self.assertTrue(out["review_complete"])
        self.assertEqual(out["next_action"], MOD.ACTIONABLE_FINDINGS)
        self.assertFalse(out["ready_to_merge"])

    def test_closer_look_none_no_arbitrary_fix(self):
        out = evaluate_fixture("closer-look-none.json")
        self.assertEqual(
            out["next_action"], MOD.NO_ACTIONABLE_FINDINGS_REQUIRES_CONFIRMATION
        )
        self.assertIn("arbitrarily", out["report"])

    def test_review_already_running(self):
        out = evaluate_fixture("review-in-progress.json")
        self.assertEqual(out["next_action"], MOD.WAIT_COPILOT)

    def test_quota_blocked(self):
        out = evaluate_fixture("quota-blocked.json")
        self.assertEqual(out["next_action"], MOD.COPILOT_QUOTA_BLOCKED)

    def test_copilot_error_retryable(self):
        out = evaluate_fixture("copilot-error.json")
        self.assertEqual(out["next_action"], MOD.COPILOT_RETRYABLE_ERROR)

    def test_external_thread_blocks_merge(self):
        out = evaluate_fixture("cubic-thread-open.json")
        self.assertTrue(out["review_complete"])
        self.assertTrue(out["merge_approval_valid"])
        self.assertFalse(out["ready_to_merge"])
        self.assertEqual(out["threads"]["unresolved_other_reviewer_threads"], 1)

    def test_required_check_red(self):
        out = evaluate_fixture("codeql-failed.json")
        self.assertTrue(out["merge_approval_valid"])
        self.assertFalse(out["ready_to_merge"])
        self.assertIn("Analyze (c-cpp)", " ".join(out["blockers"]))

    def test_assessment_green_not_github_approved(self):
        out = evaluate_fixture("assessment-green-commented.json")
        self.assertTrue(out["review_complete"])
        self.assertFalse(out["merge_approval_valid"])
        self.assertEqual(out["next_action"], MOD.REVIEW_COMPLETE)
        self.assertIn("COMMENTED", " ".join(out["blockers"]))

    def test_request_when_no_head_review(self):
        out = evaluate_fixture("needs-request.json")
        self.assertEqual(out["next_action"], MOD.REQUEST_COPILOT)

    def test_generation_budget(self):
        out = evaluate_fixture("generation-budget.json")
        self.assertEqual(out["next_action"], MOD.GENERATION_BUDGET_EXCEEDED)

    def test_text_approved_is_not_github_approved(self):
        snapshot = load_fixture("needs-request.json")
        snapshot["reviews"] = [
            {
                "id": 1,
                "user": {"login": "cursor-bot"},
                "state": "COMMENTED",
                "commit_id": snapshot["head_sha"],
                "body": "Approved.\nLooks good.",
                "submitted_at": "2026-09-29T12:00:00Z",
            }
        ]
        out = MOD.evaluate_snapshot(snapshot)
        self.assertFalse(out["merge_approval_valid"])
        self.assertEqual(out["next_action"], MOD.REQUEST_COPILOT)

    def test_cli_round_trip(self):
        fixture = load_fixture("ready-to-merge.json")
        proc = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS / "evaluate-pr-review-gate.py"),
                "--snapshot-json",
                "-",
            ],
            input=json.dumps(fixture),
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(proc.stdout)
        self.assertTrue(data["ready_to_merge"])


if __name__ == "__main__":
    unittest.main()
