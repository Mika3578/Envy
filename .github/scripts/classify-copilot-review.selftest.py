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
    def test_rest_copilot_alias_has_same_classification(self):
        fixture = load_fixture("changes-one-finding.json")
        expected = MOD.classify_review(MOD.review_input_from_github(fixture))["classification"]
        for login in ("Copilot", "copilot-pull-request-reviewer", "copilot-pull-request-reviewer[bot]"):
            fixture["user"]["login"] = login
            self.assertEqual(MOD.classify_review(MOD.review_input_from_github(fixture))["classification"], expected)

    def test_dotfile_and_hidden_directory_path_are_technical(self):
        for path in (".editorconfig:57", ".github/workflows/foo.yml:10"):
            self.assertTrue(MOD._rationale_has_technical_issue(path))

    def test_generic_oversized_input_is_not_diff_api_error(self):
        self.assertFalse(MOD._DIFF_TOO_LARGE_BODY.search("The input buffer can become too large and must be bounded."))

    def test_mixed_technical_and_human_blocker_keeps_both(self):
        fixture = load_fixture("changes-one-finding.json")
        fixture["body"] = fixture["body"].replace(
            "Address the validation edge case and production-path test coverage.",
            "Fix the parsing bug; final human validation and missing runtime evidence remain.",
        )
        out = MOD.classify_review(MOD.review_input_from_github(fixture))
        self.assertTrue(out["requires_fixer"])
        self.assertTrue(out["requires_human"])

    def test_approved_github_state(self):
        out = classify_fixture("approved-none.json")
        self.assertEqual(out["classification"], MOD.CLASSIFICATION_APPROVED)
        self.assertFalse(out["requires_fixer"])
        self.assertEqual(out["finding_count"], 0)

    def test_approved_with_human_rationale_disqualifies(self):
        fixture = load_fixture("approved-none.json")
        fixture["body"] = fixture["body"].replace(
            "Required evidence is present and no blocking defects remain on the current HEAD.",
            "Approved heading present but this still needs human validation before merge.",
        )
        out = MOD.classify_review(MOD.review_input_from_github(fixture))
        self.assertEqual(out["classification"], MOD.CLASSIFICATION_HUMAN_REQUIRED)
        self.assertTrue(out["requires_human"])
        self.assertFalse(out["requires_fixer"])

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
        # Named technical defect in the free-text rationale is fixer work even
        # when Findings: None and there are no unresolved inline threads.
        self.assertTrue(out["requires_fixer"])
        self.assertFalse(out["requires_human"])
        self.assertIn("en.pot", out["rationale"])

    def test_closer_look_none_with_resolved_section(self):
        out = classify_fixture("closer-look-none-resolved.json")
        # Rationale lists themes without a concrete file/path/technical signal.
        self.assertEqual(out["classification"], MOD.CLASSIFICATION_HUMAN_REQUIRED)
        self.assertFalse(out["requires_fixer"])
        self.assertTrue(out["requires_human"])
        self.assertGreaterEqual(len(out["resolved_since_last_titles"]), 1)

    def test_previously_missed_is_actionable(self):
        out = classify_fixture("closer-look-previously-missed.json")
        self.assertEqual(out["classification"], MOD.CLASSIFICATION_ACTIONABLE_FINDINGS)
        self.assertTrue(out["requires_fixer"])
        self.assertEqual(out["finding_count"], 2)
        self.assertEqual(len(out["previously_missed_titles"]), 2)
        self.assertTrue(
            any("UTF-8 policy" in t for t in out["previously_missed_titles"])
        )
        self.assertTrue(
            any("BOM bypasses" in t for t in out["previously_missed_titles"])
        )

    def test_suppressed_comments_are_actionable(self):
        out = classify_fixture("closer-look-suppressed-comments.json")
        self.assertEqual(out["classification"], MOD.CLASSIFICATION_ACTIONABLE_FINDINGS)
        self.assertTrue(out["requires_fixer"])
        self.assertEqual(out["finding_count"], 1)
        self.assertTrue(out["suppressed_comment_titles"])

    def test_broad_human_only_stops_automation(self):
        out = classify_fixture("closer-look-broad-human-only.json")
        self.assertEqual(out["classification"], MOD.CLASSIFICATION_HUMAN_REQUIRED)
        self.assertTrue(out["requires_human"])
        self.assertFalse(out["requires_fixer"])

    def test_named_technical_closer_look_needs_fixer(self):
        out = classify_fixture("closer-look-named-technical.json")
        self.assertEqual(out["classification"], MOD.CLASSIFICATION_CLOSER_LOOK_DIAGNOSTIC)
        self.assertTrue(out["requires_fixer"])
        self.assertFalse(out["requires_human"])

    def test_unresolved_prior_issue_keeps_human_blocker(self):
        out = classify_fixture("closer-look-unresolved-prior.json")
        self.assertEqual(out["classification"], MOD.CLASSIFICATION_CLOSER_LOOK_DIAGNOSTIC)
        self.assertTrue(out["requires_fixer"])
        self.assertTrue(out["requires_human"])

    def test_assessment_approved_without_github_approved(self):
        fixture = load_fixture("approved-none.json")
        fixture["state"] = "COMMENTED"
        out = MOD.classify_review(MOD.review_input_from_github(fixture))
        self.assertEqual(out["classification"], MOD.CLASSIFICATION_HUMAN_REQUIRED)
        self.assertFalse(out["requires_fixer"])
        self.assertTrue(out["requires_human"])

    def test_quota_blocked(self):
        out = classify_fixture("copilot-quota.json")
        self.assertEqual(out["classification"], MOD.CLASSIFICATION_QUOTA_BLOCKED)
        self.assertTrue(out["requires_human"])
        self.assertFalse(out["requires_fixer"])

    def test_diff_too_large(self):
        out = classify_fixture("copilot-diff-too-large.json")
        self.assertEqual(out["classification"], MOD.CLASSIFICATION_DIFF_TOO_LARGE)
        self.assertTrue(out["requires_human"])

    def test_large_input_finding_is_not_a_review_size_error(self):
        fixture = load_fixture("closer-look-named-technical.json")
        fixture["body"] = fixture["body"].replace(
            "The privileged review workflow",
            "The input buffer can become too large. The privileged review workflow",
        )
        out = MOD.classify_review(MOD.review_input_from_github(fixture))
        self.assertEqual(out["assessment"], MOD.ASSESSMENT_NEEDS_CLOSER_LOOK)
        self.assertEqual(out["classification"], MOD.CLASSIFICATION_CLOSER_LOOK_DIAGNOSTIC)
        self.assertTrue(out["requires_fixer"])

    def test_human_validation_rationale(self):
        out = classify_fixture("closer-look-human-validation.json")
        self.assertEqual(out["classification"], MOD.CLASSIFICATION_HUMAN_REQUIRED)
        self.assertTrue(out["requires_human"])
        self.assertFalse(out["requires_fixer"])

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
        self.assertEqual(out["classification"], MOD.CLASSIFICATION_HUMAN_REQUIRED)
        self.assertFalse(out["requires_fixer"])
        self.assertTrue(out["requires_human"])

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
        self.assertEqual(guarded["classification"], MOD.CLASSIFICATION_CLOSER_LOOK_DIAGNOSTIC)
        self.assertFalse(guarded["requires_fixer"])
        self.assertTrue(guarded["requires_human"])
        self.assertIn(str(current["review_id"]), guarded["human_stop_review_ids"])
        self.assertEqual(guarded.get("loop_guard"), "repeat_closer_look_requires_changed_diagnosis")

    def test_prior_human_decision_without_findings_is_sticky(self):
        current = {"classification": "APPROVED", "requires_human": False, "requires_fixer": False}
        prior = [{"classification": "HUMAN_REQUIRED", "review_id": "1", "finding_ledger": []}]
        guarded = MOD.apply_loop_guards(current, prior)
        self.assertTrue(guarded["requires_human"])
        self.assertEqual(guarded["human_stop_review_ids"], ["1"])
        prior[0]["human_disposition"] = {"actor": "other", "status": "resolved", "evidence": "Checked"}
        self.assertTrue(MOD.apply_loop_guards(current, prior)["requires_human"])
        prior[0]["human_disposition"]["actor"] = "Mika3578"
        self.assertFalse(MOD.apply_loop_guards(current, prior)["requires_human"])

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
        fixture = load_fixture("approved-none.json")
        proc = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS / "classify-copilot-review.py"),
                "--review-json",
                "-",
            ],
            input=json.dumps(fixture),
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(proc.stdout)
        self.assertEqual(data["classification"], MOD.CLASSIFICATION_APPROVED)

    def test_cli_rejects_file_review_json_path(self):
        proc = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS / "classify-copilot-review.py"),
                "--review-json",
                str(FIXTURES / "approved-none.json"),
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("invalid choice", proc.stderr)


if __name__ == "__main__":
    unittest.main()
