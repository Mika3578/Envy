#!/usr/bin/env python3
"""Self-test for scripts/check-maintenance-review.py (no GitHub token)."""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

_spec = importlib.util.spec_from_file_location(
    "check_maintenance_review",
    Path(__file__).with_name("check-maintenance-review.py"),
)
assert _spec and _spec.loader
cmr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cmr)


SAMPLE_IDEAS = """# Pre-issue idea register

## Last maintenance review

| Field | Value |
|-------|--------|
| Date | 2026-09-01 |
| Development revision | `abc1234deadbeef` |
| Merged PR baseline | [#392 — Align Remote access with localhost bind policy](https://example.invalid/392) |
"""

PENDING_ENTRY = """## Some idea — Do a useful thing

### Status
Pending review
"""

PENDING_LINE = """## Other idea — Compact status

Status: Pending review
"""


class ParseTests(unittest.TestCase):
    def test_parse_last_review(self) -> None:
        parsed = cmr.parse_last_review(SAMPLE_IDEAS)
        self.assertEqual(parsed["date"], "2026-09-01")
        self.assertEqual(parsed["revision"], "abc1234deadbeef")
        self.assertEqual(parsed["merged_pr_baseline"], "392")

    def test_count_pending_block_and_line(self) -> None:
        text = PENDING_ENTRY + "\n" + PENDING_LINE
        self.assertEqual(cmr.count_pending_in_text(text), 2)

    def test_count_inbox_missing_dir(self) -> None:
        self.assertEqual(cmr.count_inbox_pending(Path("/no/such/envy-inbox")), {})

    def test_count_inbox_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            inbox = Path(tmp)
            (inbox / "ideas.md").write_text(PENDING_ENTRY, encoding="utf-8")
            (inbox / "ci.md").write_text(PENDING_LINE, encoding="utf-8")
            (inbox / "empty.md").write_text("# empty\n", encoding="utf-8")
            counts = cmr.count_inbox_pending(inbox)
            self.assertEqual(counts["ideas"], 1)
            self.assertEqual(counts["ci"], 1)
            self.assertNotIn("empty", counts)

    def test_days_since(self) -> None:
        from datetime import date

        self.assertEqual(cmr.days_since("2026-09-01", today=date(2026, 10, 6)), 35)
        self.assertIsNone(cmr.days_since(None))

    def test_recommend_thresholds(self) -> None:
        yes, reason = cmr.recommend(10, 0, 0)
        self.assertTrue(yes)
        self.assertIn("pending", reason)
        yes, reason = cmr.recommend(0, 11, 0)
        self.assertTrue(yes)
        self.assertIn("merged PR", reason)
        yes, reason = cmr.recommend(0, 0, 30)
        self.assertTrue(yes)
        self.assertIn("day", reason)
        yes, reason = cmr.recommend(1, 1, 1)
        self.assertFalse(yes)
        self.assertIn("no configured", reason)
        yes, reason = cmr.recommend(0, None, 5)
        self.assertFalse(yes)

    def test_format_report_without_inbox(self) -> None:
        text = cmr.format_report(
            inbox_counts={},
            inbox_present=False,
            merged_prs=None,
            elapsed_days=24,
            review={"date": "2026-09-01", "revision": "abc1234", "merged_pr_baseline": "392"},
            yes=False,
            reason="no configured threshold reached",
        )
        self.assertIn("no .local/inbox", text)
        self.assertIn("Review recommended: NO", text)
        self.assertIn("Merged PR baseline: #392", text)

    def test_committed_ideas_md_parses(self) -> None:
        ideas = ROOT / "docs" / "10_dev" / "ideas.md"
        parsed = cmr.parse_last_review(ideas.read_text(encoding="utf-8"))
        self.assertIsNotNone(parsed["date"])
        self.assertIsNotNone(parsed["revision"])
        self.assertIsNotNone(parsed["merged_pr_baseline"])


if __name__ == "__main__":
    unittest.main()
