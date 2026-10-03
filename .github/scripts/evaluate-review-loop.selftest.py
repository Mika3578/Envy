#!/usr/bin/env python3
"""Offline tests for evaluate-review-loop.py."""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location(
    "evaluate_review_loop_mod", SCRIPTS / "evaluate-review-loop.py"
)
MOD = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = MOD
_SPEC.loader.exec_module(MOD)

HEAD = "a" * 40
OLD = "b" * 40


def snap(**kwargs):
    base = {
        "head_sha": HEAD,
        "review": {"commit_id": HEAD, "state": "APPROVED", "id": 1},
        "classification": "APPROVED",
        "requires_fixer": False,
        "requires_human": False,
        "review_decision": "APPROVED",
        "review_decision_source": "graphql",
        "unresolved_threads": 0,
        "human_unresolved_threads": 0,
        "untreated_threads": 0,
        "open_finding_titles": [],
        "previously_missed_titles": [],
        "suppressed_comment_titles": [],
        "finding_ledger": [],
        "required_checks": [{"name": "Format Check", "state": "SUCCESS"}],
    }
    base.update(kwargs)
    return base


class EvaluateReviewLoopTests(unittest.TestCase):
    def test_requested_changes_with_technical_findings_can_be_corrected(self):
        out = MOD.evaluate_review_loop(snap(review_decision="CHANGES_REQUESTED",
            classification="ACTIONABLE_FINDINGS", requires_fixer=True,
            open_finding_titles=["Bounds defect"]))
        self.assertEqual(out["decision"], MOD.DECISION_FIX_AGAIN)
        self.assertNotEqual(out["decision"], MOD.DECISION_CLEAN)

    def test_human_blocker_precedes_concrete_fixer_work(self):
        out = MOD.evaluate_review_loop(snap(
            classification="ACTIONABLE_FINDINGS", requires_fixer=True,
            requires_human=True, open_finding_titles=["Parsing bug"],
        ))
        self.assertEqual(out["decision"], MOD.DECISION_NEEDS_HUMAN)

    def test_clean_approved_current_head(self):
        out = MOD.evaluate_review_loop(snap())
        self.assertEqual(out["decision"], MOD.DECISION_CLEAN)
        self.assertIn("no active technical findings", out["reason"])

    def test_empty_graphql_decision_is_not_clean(self):
        out = MOD.evaluate_review_loop(snap(review_decision=""))
        self.assertNotEqual(out["decision"], MOD.DECISION_CLEAN)
        self.assertEqual(out["decision"], MOD.DECISION_NEEDS_HUMAN)

    def test_non_graphql_review_decision_is_not_clean(self):
        out = MOD.evaluate_review_loop(snap(review_decision_source="rest"))
        self.assertNotEqual(out["decision"], MOD.DECISION_CLEAN)
        self.assertEqual(out["decision"], MOD.DECISION_NEEDS_HUMAN)

    def test_approved_classification_with_commented_state_not_clean(self):
        out = MOD.evaluate_review_loop(
            snap(review={"commit_id": HEAD, "state": "COMMENTED", "id": 1})
        )
        self.assertEqual(out["decision"], MOD.DECISION_NEEDS_HUMAN)

    def test_approved_with_requires_human_not_clean(self):
        out = MOD.evaluate_review_loop(snap(requires_human=True))
        self.assertNotEqual(out["decision"], MOD.DECISION_CLEAN)
        self.assertEqual(out["decision"], MOD.DECISION_NEEDS_HUMAN)

    def test_stale_review_never_clean(self):
        out = MOD.evaluate_review_loop(
            snap(review={"commit_id": OLD, "state": "APPROVED", "id": 1})
        )
        self.assertEqual(out["decision"], MOD.DECISION_NEEDS_HUMAN)
        self.assertIn("older commit", out["reason"])

    def test_previously_missed_is_fix_again(self):
        out = MOD.evaluate_review_loop(
            snap(
                classification="ACTIONABLE_FINDINGS",
                requires_fixer=True,
                previously_missed_titles=["BOM bypass"],
            )
        )
        self.assertEqual(out["decision"], MOD.DECISION_FIX_AGAIN)
        self.assertTrue(any("Previously missed" in r for r in out["reasons"]))

    def test_empty_threads_not_clean_without_approved(self):
        out = MOD.evaluate_review_loop(
            snap(
                classification="CLOSER_LOOK_DIAGNOSTIC",
                requires_fixer=True,
                unresolved_threads=0,
                open_finding_titles=[],
            )
        )
        self.assertEqual(out["decision"], MOD.DECISION_FIX_AGAIN)

    def test_human_only_closer_look(self):
        out = MOD.evaluate_review_loop(
            snap(
                classification="HUMAN_REQUIRED",
                requires_fixer=False,
                requires_human=True,
            )
        )
        self.assertEqual(out["decision"], MOD.DECISION_NEEDS_HUMAN)

    def test_repeated_finding_budget(self):
        out = MOD.evaluate_review_loop(
            snap(
                classification="ACTIONABLE_FINDINGS",
                requires_fixer=True,
                open_finding_titles=["BOM bypass"],
                finding_ledger=[
                    {
                        "fingerprint": "bom-header",
                        "attempts": 2,
                        "status": "fixed_pending_rereview",
                    }
                ],
            )
        )
        self.assertEqual(out["decision"], MOD.DECISION_FIX_AGAIN)

    def test_global_human_decision_survives_clean_review_without_findings(self):
        out = MOD.evaluate_review_loop(snap(human_stop_review_ids=["prior-human-review"]))
        self.assertEqual(out["decision"], MOD.DECISION_NEEDS_HUMAN)

    def test_api_error_snapshot_is_not_clean(self):
        out = MOD.evaluate_review_loop(snap(api_error=True))
        self.assertEqual(out["decision"], MOD.DECISION_NEEDS_HUMAN)
        out = MOD.evaluate_review_loop(snap(review_decision_unavailable=True))
        self.assertEqual(out["decision"], MOD.DECISION_NEEDS_HUMAN)

    def test_non_list_required_checks_not_clean(self):
        out = MOD.evaluate_review_loop(snap(required_checks="oops"))
        self.assertEqual(out["decision"], MOD.DECISION_NEEDS_HUMAN)
        self.assertIn("empty", out["reason"])
    def test_empty_required_checks_not_clean(self):
        out = MOD.evaluate_review_loop(snap(required_checks=[]))
        self.assertEqual(out["decision"], MOD.DECISION_NEEDS_HUMAN)
        self.assertIn("empty", out["reason"])

    def test_approved_state_without_classification_not_clean(self):
        out = MOD.evaluate_review_loop(
            snap(
                classification="",
                review={"commit_id": HEAD, "state": "APPROVED", "id": 1},
            )
        )
        self.assertEqual(out["decision"], MOD.DECISION_NEEDS_HUMAN)

    def test_failing_required_check(self):
        out = MOD.evaluate_review_loop(
            snap(
                required_checks=[{"name": "secret-scan", "state": "FAILURE"}],
            )
        )
        self.assertEqual(out["decision"], MOD.DECISION_NEEDS_HUMAN)
        self.assertIn("failing", out["reason"])

    def test_no_review(self):
        out = MOD.evaluate_review_loop(snap(review={}))
        self.assertEqual(out["decision"], MOD.DECISION_NEEDS_HUMAN)
        self.assertIn("no review yet", out["reason"])

    def test_cli_round_trip(self):
        import subprocess

        proc = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS / "evaluate-review-loop.py"),
            ],
            input=json.dumps(snap()),
            text=True,
            capture_output=True,
            check=True,
        )
        data = json.loads(proc.stdout)
        self.assertEqual(data["decision"], MOD.DECISION_CLEAN)

    def test_pre_review_snapshot_never_clean_after_copilot_request(self):
        pre = snap(snapshot_phase=MOD.SNAPSHOT_PRE_COPILOT_REQUEST, unresolved_threads=0)
        out = MOD.decide_after_copilot_request(pre, pre)
        self.assertEqual(out["decision"], MOD.DECISION_WAITING_COPILOT)
        self.assertFalse(out["merge_ready"])

    def test_post_review_new_thread_is_fix_again(self):
        pre = snap(snapshot_phase=MOD.SNAPSHOT_PRE_COPILOT_REQUEST, unresolved_threads=0)
        post = snap(
            snapshot_phase=MOD.SNAPSHOT_POST_COPILOT_REVIEW,
            review={"commit_id": HEAD, "state": "COMMENTED", "id": 9},
            classification="ACTIONABLE_FINDINGS",
            requires_fixer=True,
            unresolved_threads=1,
            open_finding_titles=["PowerShell caret"],
        )
        out = MOD.decide_after_copilot_request(pre, post)
        self.assertEqual(out["decision"], MOD.DECISION_FIX_AGAIN)
        self.assertFalse(out["merge_ready"])
        self.assertNotEqual(MOD.evaluate_review_loop(pre)["decision"], MOD.DECISION_CLEAN)

    def test_overview_finding_without_thread_is_fix_again(self):
        out = MOD.evaluate_review_loop(
            snap(
                snapshot_phase=MOD.SNAPSHOT_POST_COPILOT_REVIEW,
                review={"commit_id": HEAD, "state": "COMMENTED", "id": 9},
                classification="ACTIONABLE_FINDINGS",
                requires_fixer=True,
                unresolved_threads=0,
                open_finding_titles=["Overview bounds defect"],
            )
        )
        self.assertEqual(out["decision"], MOD.DECISION_FIX_AGAIN)
        self.assertFalse(out["merge_ready"])

    def test_stale_old_sha_review_ignored_when_head_moved(self):
        out = MOD.evaluate_review_loop(
            snap(
                head_sha=HEAD,
                copilot_request_pending=True,
                review={"commit_id": OLD, "state": "COMMENTED", "id": 3},
            )
        )
        self.assertEqual(out["decision"], MOD.DECISION_WAITING_COPILOT)
        self.assertFalse(out["merge_ready"])
        self.assertNotEqual(out["decision"], MOD.DECISION_CLEAN)

    def test_late_thread_visibility_uses_stricter_reread(self):
        first = snap(
            snapshot_phase=MOD.SNAPSHOT_POST_COPILOT_REVIEW,
            review={"commit_id": HEAD, "state": "COMMENTED", "id": 9},
            classification="ACTIONABLE_FINDINGS",
            requires_fixer=True,
            unresolved_threads=0,
            open_finding_titles=[],
        )
        second = snap(
            snapshot_phase=MOD.SNAPSHOT_POST_COPILOT_REVIEW,
            review={"commit_id": HEAD, "state": "COMMENTED", "id": 9},
            classification="ACTIONABLE_FINDINGS",
            requires_fixer=True,
            unresolved_threads=1,
            open_finding_titles=["Late thread"],
        )
        merged = MOD.coalesce_post_review_reads(first, second)
        out = MOD.evaluate_review_loop(merged)
        self.assertEqual(merged["unresolved_threads"], 1)
        self.assertEqual(out["decision"], MOD.DECISION_FIX_AGAIN)
        self.assertFalse(out["merge_ready"])

    def test_canonical_skipped_required_check_is_not_clean(self):
        out = MOD.evaluate_review_loop(
            snap(required_checks=[{"name": "Build x64 Release", "state": "SKIPPED"}])
        )
        self.assertNotEqual(out["decision"], MOD.DECISION_CLEAN)
        self.assertFalse(out["merge_ready"])

    def test_missing_required_check_still_fail_closed(self):
        out = MOD.evaluate_review_loop(snap(required_checks=[]))
        self.assertEqual(out["decision"], MOD.DECISION_NEEDS_HUMAN)

    def test_self_only_final_review_gate_is_not_clean(self):
        out = MOD.evaluate_review_loop(
            snap(required_checks=[{"name": "Final review gate", "state": "SUCCESS"}])
        )
        self.assertEqual(out["decision"], MOD.DECISION_NEEDS_HUMAN)

    def test_missing_unresolved_count_not_clean(self):
        payload = snap()
        del payload["unresolved_threads"]
        out = MOD.evaluate_review_loop(payload)
        self.assertEqual(out["decision"], MOD.DECISION_NEEDS_HUMAN)

    def test_untreated_resolved_threads_not_clean(self):
        out = MOD.evaluate_review_loop(snap(untreated_threads=1))
        self.assertNotEqual(out["decision"], MOD.DECISION_CLEAN)


if __name__ == "__main__":
    unittest.main()
