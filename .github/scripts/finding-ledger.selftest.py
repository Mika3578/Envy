#!/usr/bin/env python3
"""Offline tests for finding-ledger.py."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location(
    "finding_ledger_mod", SCRIPTS / "finding-ledger.py"
)
MOD = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = MOD
_SPEC.loader.exec_module(MOD)


class FindingLedgerTests(unittest.TestCase):
    def test_current_rest_copilot_login_keeps_history_guard(self):
        reviews = [{"id": 1, "user": {"login": "Copilot", "type": "Bot"}}]
        with self.assertRaises(ValueError):
            MOD.check_review_history(reviews, 2, [])

    def test_overview_finding_acquiring_inline_path_keeps_attempts(self):
        ledger = []
        item = MOD.upsert_finding(ledger, source="copilot", path="", title="Bounds bug", head_sha="a")
        MOD.mark_fix_attempt(ledger, item["fingerprint"], "first")
        same = MOD.upsert_finding(ledger, source="copilot", path="a.py", title="Bounds bug", head_sha="b")
        self.assertIs(item, same)
        self.assertEqual(same["attempts"], 1)
        again = MOD.upsert_finding(ledger, source="copilot", path="a.py", title="Bounds bug", head_sha="c")
        self.assertIs(item, again)
        self.assertEqual(len(ledger), 1)

    def test_ambiguous_overview_path_requires_human_without_reset(self):
        ledger = []
        for path in ("a.py", "b.py"):
            item = MOD.upsert_finding(ledger, source="copilot", path=path, title="Bounds bug", head_sha="a")
            MOD.mark_fix_attempt(ledger, item["fingerprint"], "first")
        MOD.upsert_finding(ledger, source="copilot", path="", title="Bounds bug", head_sha="b")
        self.assertEqual(len(ledger), 2)
        self.assertTrue(all(item["status"] == MOD.STATUS_NEEDS_HUMAN and item["attempts"] == 1 for item in ledger))

    def test_mixed_inline_and_overview_findings_keep_all_sections(self):
        findings = MOD.merge_active_findings(
            [{"title": "Inline", "path": "a.py", "line": 10}],
            {"open_finding_titles": ["Inline", "Overview"],
             "previously_missed_titles": ["Missed"],
             "suppressed_comment_titles": ["Suppressed"]},
        )
        self.assertEqual([item["title"] for item in findings], ["Inline", "Overview", "Missed", "Suppressed"])
        self.assertEqual(findings[0]["path"], "a.py")

    def test_fingerprint_stable(self):
        a = MOD.fingerprint("copilot", "a.py", "BOM bypass")
        b = MOD.fingerprint("copilot", "a.py", "  bom   bypass ")
        self.assertEqual(a, b)

    def test_fingerprint_excludes_location(self):
        a = MOD.fingerprint("copilot", "a.py", "BOM bypass", "L10")
        b = MOD.fingerprint("copilot", "a.py", "BOM bypass", "L20")
        # Location is metadata only; same path/title share one budget key.
        self.assertEqual(a, b)
        c = MOD.fingerprint("copilot", "b.py", "BOM bypass", "L10")
        self.assertNotEqual(a, c)

    def test_upsert_and_budget(self):
        ledger: list = []
        MOD.upsert_finding(
            ledger,
            source="copilot",
            path="a.py",
            title="BOM bypass",
            head_sha="a" * 40,
        )
        fp = ledger[0]["fingerprint"]
        MOD.mark_fix_attempt(ledger, fp, "c1")
        self.assertEqual(ledger[0]["status"], MOD.STATUS_FIXED_PENDING)
        MOD.mark_fix_attempt(ledger, fp, "c2")
        self.assertEqual(ledger[0]["status"], MOD.STATUS_FIXED_PENDING)
        self.assertEqual(ledger[0]["attempts"], 2)

    def test_reconcile_resolves_absent(self):
        ledger: list = []
        MOD.upsert_finding(
            ledger,
            source="copilot",
            path="a.py",
            title="BOM bypass",
            head_sha="a" * 40,
        )
        fp = ledger[0]["fingerprint"]
        MOD.mark_fix_attempt(ledger, fp, "c1")
        MOD.reconcile_after_review(ledger, active_fingerprints=[], head_sha="b" * 40)
        self.assertEqual(ledger[0]["status"], MOD.STATUS_RESOLVED)

    def test_many_attempts_preserve_history_without_automatic_human_stop(self):
        ledger = []
        item = MOD.upsert_finding(ledger, source="copilot", path="a.py", title="BOM bypass", head_sha="a" * 40)
        MOD.mark_fix_attempt(ledger, item["fingerprint"], "c1")
        MOD.mark_fix_attempt(ledger, item["fingerprint"], "c2")
        MOD.reconcile_after_review(ledger, [], "b" * 40)
        self.assertEqual(item["status"], MOD.STATUS_RESOLVED)
        self.assertEqual(item["attempts"], 2)
        MOD.upsert_finding(ledger, source="copilot", path="a.py", title="BOM bypass", head_sha="c" * 40)
        self.assertEqual(item["status"], MOD.STATUS_OPEN)
        MOD.reconcile_after_review(ledger, [item["fingerprint"]], "c" * 40)
        self.assertEqual(item["status"], MOD.STATUS_OPEN)
        self.assertEqual(item["attempts"], 2)

    def test_old_head_review_without_ledger_stops(self):
        reviews = [{"id": 1, "user": {"login": "copilot-pull-request-reviewer[bot]"}, "commit_id": "old"}]
        with self.assertRaisesRegex(ValueError, "refusing to reset"):
            MOD.check_review_history(reviews, 2, [])

    def test_same_head_prior_review_without_ledger_stops(self):
        reviews = [{"id": i, "user": {"login": "copilot-pull-request-reviewer[bot]"}, "commit_id": "same"} for i in (1, 2)]
        with self.assertRaisesRegex(ValueError, "refusing to reset"):
            MOD.check_review_history(reviews, 2, [])

    def test_first_review_and_human_reviews_do_not_require_prior_ledger(self):
        reviews = [{"id": 2, "user": {"login": "copilot-pull-request-reviewer[bot]"}}, {"id": 1, "user": {"login": "maintainer"}}]
        self.assertEqual(MOD.check_review_history(reviews, 2, []), 0)

    def test_prior_reviews_with_durable_state_are_allowed(self):
        reviews = [{"id": i, "user": {"login": "copilot-pull-request-reviewer[bot]"}} for i in (1, 2)]
        self.assertEqual(MOD.check_review_history(reviews, 2, [{
            "review_id": "1", "head_sha": "old", "classification": "HUMAN_REQUIRED", "finding_ledger": []}]), 1)
        with self.assertRaises(ValueError):
            MOD.check_review_history(reviews, 2, 1)

    def test_partial_and_malformed_durable_history_cannot_reset_state(self):
        reviews = [{"id": i, "user": {"login": "copilot-pull-request-reviewer[bot]"}} for i in (1, 2)]
        first = {"review_id": "1", "head_sha": "old", "classification": "APPROVED", "finding_ledger": []}
        with self.assertRaises(ValueError):
            MOD.check_review_history(reviews, 3, [first])
        with self.assertRaises(ValueError):
            MOD.check_review_history(reviews, 3, [{"review_id": "1"}])

    def test_malformed_review_history_fails_closed(self):
        for reviews in ({}, [None], [{"user": {"login": "copilot-pull-request-reviewer[bot]"}, "id": True}]):
            with self.subTest(reviews=reviews), self.assertRaises(ValueError):
                MOD.check_review_history(reviews, 2, [])

    def test_history_cli_rejects_missing_state_and_accepts_first_review(self):
        command = [sys.executable, str(SCRIPTS / "finding-ledger.py"),
                   "check-history", "--review-id", "2", "--prior-outcomes-json", "[]"]
        old_review = {"id": 1, "user": {"login": "copilot-pull-request-reviewer[bot]"}, "commit_id": "old"}
        result = subprocess.run(command, input=json.dumps([old_review]), text=True, capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("refusing to reset", result.stderr)
        result = subprocess.run(command, input="[]", text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_policy_status_aliases(self):
        self.assertEqual(MOD.canonical_status("NEW"), MOD.STATUS_OPEN)
        self.assertEqual(MOD.canonical_status("FIXED"), MOD.STATUS_FIXED_PENDING)
        self.assertEqual(MOD.canonical_status("JUSTIFIED"), MOD.STATUS_RESOLVED)
        self.assertEqual(MOD.canonical_status("RECURRED"), MOD.STATUS_OPEN)
        self.assertEqual(MOD.canonical_status("NEEDS_HUMAN"), MOD.STATUS_NEEDS_HUMAN)


if __name__ == "__main__":
    unittest.main()
