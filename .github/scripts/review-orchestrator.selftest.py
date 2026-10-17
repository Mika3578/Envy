#!/usr/bin/env python3
"""Regression tests for the free review orchestrator (no network)."""

import importlib.util
from pathlib import Path
import unittest


SCRIPTS = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "review_orchestrator", SCRIPTS / "review-orchestrator.py"
)
ORCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ORCH)

ALL = ORCH.enabled_reviewers(None)


def pr(draft=False, sha="a" * 40, changed=100, state="open"):
    return {
        "state": state,
        "draft": draft,
        "head": {"sha": sha},
        "additions": changed,
        "deletions": 0,
    }


def thread(body, resolved=False, outdated=False, line=7):
    return {
        "isResolved": resolved,
        "isOutdated": outdated,
        "path": "Envy/Foo.cpp",
        "line": line,
        "author": "bot",
        "body": body,
        "url": "https://example.invalid/t",
    }


class PlanTests(unittest.TestCase):
    def test_ready_head_requests_every_enabled_reviewer(self):
        chosen, reason = ORCH.plan_request(pr(), {"rounds": []}, ALL, 2)
        self.assertEqual(chosen, ALL)
        self.assertEqual(reason, "requested")

    def test_draft_and_closed_are_never_reviewed(self):
        self.assertEqual(ORCH.plan_request(pr(draft=True), {"rounds": []}, ALL, 2)[0], [])
        self.assertEqual(ORCH.plan_request(pr(state="closed"), {"rounds": []}, ALL, 2)[0], [])

    def test_same_head_is_not_requested_twice(self):
        state = {"rounds": [{"sha": "a" * 40, "reviewers": ALL}]}
        self.assertEqual(ORCH.plan_request(pr(), state, ALL, 2)[0], [])

    def test_round_budget_stops_requests(self):
        state = {"rounds": [{"sha": "b" * 40, "reviewers": ALL},
                            {"sha": "c" * 40, "reviewers": ALL}]}
        chosen, reason = ORCH.plan_request(pr(), state, ALL, 2)
        self.assertEqual(chosen, [])
        self.assertIn("budget", reason)

    def test_large_diff_skips_sourcery_budget(self):
        big = ORCH.SOURCERY_MAX_CHANGED_LINES + 1
        chosen, _ = ORCH.plan_request(pr(changed=big), {"rounds": []}, ALL, 2)
        self.assertNotIn("sourcery", chosen)
        self.assertIn("coderabbit", chosen)

    def test_unknown_reviewer_is_rejected(self):
        with self.assertRaises(ValueError):
            ORCH.enabled_reviewers("coderabbit,copilot")


class StateTests(unittest.TestCase):
    def test_state_round_trips_through_comment(self):
        state = {"rounds": [{"sha": "d" * 40, "reviewers": ["gemini"]}]}
        body = ORCH.render_state(state, 2)
        self.assertEqual(ORCH.parse_state(body), state)

    def test_missing_state_starts_empty(self):
        self.assertEqual(ORCH.parse_state("hello"), {"rounds": []})

    def test_oversized_state_is_rejected(self):
        blob = '{"rounds":[],"pad":"' + "x" * ORCH.MAX_STATE_CHARS + '"}'
        with self.assertRaises(ValueError):
            ORCH.parse_state(f"{ORCH.STATE_MARKER} {blob} -->")


class DigestTests(unittest.TestCase):
    def test_digest_separates_blocking_nits_outdated_and_resolved(self):
        threads = [
            thread("_⚠️ Potential issue_\n\nBuffer overflow when nLength is 0"),
            thread("**nitpick:** rename variable"),
            thread("old finding", outdated=True),
            thread("fixed", resolved=True),
        ]
        body = ORCH.render_digest(12, "e" * 40, threads)
        self.assertIn("**1 to treat** | 1 nits | 1 outdated | 1 resolved", body)
        self.assertIn("Buffer overflow when nLength is 0", body.split("<details>")[0])
        self.assertIn("rename variable", body)
        self.assertTrue(body.startswith(ORCH.DIGEST_MARKER))

    def test_summary_strips_markup_and_truncates(self):
        text = "<!-- meta -->\n![high](x.png)\n**issue (bug_risk):** " + "x" * 200
        summary = ORCH.summarize(text)
        self.assertTrue(summary.startswith("issue (bug_risk):"))
        self.assertLessEqual(len(summary), 140)


if __name__ == "__main__":
    unittest.main()
