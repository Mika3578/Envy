#!/usr/bin/env python3
"""Regression tests for the review scoreboard (no network)."""

import importlib.util
from pathlib import Path
import unittest


SCRIPTS = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("review_scoreboard", SCRIPTS / "review-scoreboard.py")
SB = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SB)

NOW = SB.parse_time("2026-10-20T12:00:00Z")
CONFIG = SB.Config({})
COLD = SB.rank({}, CONFIG, NOW)


def finding(author, *replies):
    return {"author": author, "replies": [{"author": "maintainer", "body": r} for r in replies]}


def record(threads=(), reviews=(), comments=(), requested=()):
    return {"threads": list(threads), "reviews": list(reviews), "comments": list(comments),
            "requested": list(requested)}


class OutcomeTests(unittest.TestCase):
    def test_outcomes_follow_the_treating_reply(self):
        bot = "coderabbitai[bot]"
        self.assertEqual(SB.classify_thread(finding(bot, "Fixed in 4b8ac88b: done.")), "useful")
        self.assertEqual(SB.classify_thread(finding(bot, "Partly fixed in a66d0844: x")), "useful")
        self.assertEqual(SB.classify_thread(finding(bot, "No change: intended.")), "rejected")
        self.assertEqual(SB.classify_thread(finding(bot, "Not reproduced: see test.")), "rejected")
        self.assertEqual(SB.classify_thread(finding(bot, "Thanks, will look.")), "unclassified")
        own = {"author": bot, "replies": [{"author": bot, "body": "Fixed in abcdef1"}]}
        self.assertEqual(SB.classify_thread(own), "unclassified")

    def test_request_needs_the_command_at_the_start(self):
        self.assertEqual(SB.request_key("@coderabbitai review\nHead: abc1234", CONFIG.commands),
                         "coderabbit")
        self.assertEqual(SB.request_key("/q review", CONFIG.commands), "amazonq")
        self.assertIsNone(SB.request_key("Please run /q review later", CONFIG.commands))
        self.assertIsNone(SB.request_key("/q reviewer", CONFIG.commands))


class AnalyzeTests(unittest.TestCase):
    def test_counts_requests_answers_latency_limits_and_reviewer_requests(self):
        records = [record(
            threads=[finding("coderabbitai[bot]", "Fixed in 1234567"),
                     finding("coderabbitai[bot]", "No change: by design."),
                     finding("github-actions[bot]", "Fixed in 1234567")],
            reviews=[{"login": "coderabbitai[bot]", "submitted_at": "2026-10-20T03:00:00Z"},
                     {"login": "copilot-pull-request-reviewer[bot]",
                      "submitted_at": "2026-10-20T02:30:00Z"}],
            comments=[
                {"login": "maintainer", "body": "@coderabbitai review\nHead: abc1234",
                 "created_at": "2026-10-20T01:00:00Z"},
                {"login": "maintainer", "body": "/gemini review",
                 "created_at": "2026-10-20T01:00:00Z"},
                {"login": "maintainer", "body": "@sourcery-ai review",
                 "created_at": "2026-10-19T01:00:00Z"},
                {"login": "sourcery-ai[bot]", "body": "Sorry, you have hit the review limit.",
                 "created_at": "2026-10-19T01:05:00Z"},
            ],
            requested=[{"login": "copilot-pull-request-reviewer[bot]",
                        "created_at": "2026-10-20T02:00:00Z"}],
        )]
        stats = SB.analyze(records, CONFIG, NOW)
        rabbit = stats["coderabbitai[bot]"]
        self.assertEqual((rabbit["findings"], rabbit["useful"], rabbit["rejected"]), (2, 1, 1))
        self.assertEqual((rabbit["requests"], rabbit["answered"], rabbit["latencies"]), (1, 1, [2.0]))
        self.assertNotIn("github-actions[bot]", stats)
        gemini = stats["gemini-code-assist[bot]"]
        self.assertEqual((gemini["requests"], gemini["timeouts"]), (1, 1))
        self.assertEqual(gemini["pending_since"], "2026-10-20T01:00:00Z")
        self.assertEqual(stats["sourcery-ai[bot]"]["limited_at"], "2026-10-19T01:05:00Z")
        copilot = stats["copilot-pull-request-reviewer[bot]"]
        self.assertEqual((copilot["requests"], copilot["answered"], copilot["latencies"]), (1, 1, [0.5]))
        # Recomputing from the same records gives the same numbers: no double count.
        self.assertEqual(SB.analyze(records, CONFIG, NOW), stats)


class AvailabilityTests(unittest.TestCase):
    def test_limits_caps_and_silence(self):
        item = dict(SB.blank(), limited_at="2026-10-20T01:00:00Z")
        self.assertFalse(SB.availability(item, "sourcery", NOW, CONFIG)[0])
        later = SB.parse_time("2026-10-21T02:00:00Z")
        self.assertTrue(SB.availability(item, "sourcery", later, CONFIG)[0])
        reset = SB.Config({"ENVY_REVIEWER_RESET_DAYS": "sourcery=1"})
        self.assertFalse(SB.availability(item, "sourcery", later, reset)[0])
        self.assertTrue(SB.availability(item, "sourcery", SB.parse_time("2026-11-01T00:00:00Z"), reset)[0])
        capped = SB.Config({"ENVY_REVIEWER_MONTHLY_CAPS": "gemini=5"})
        self.assertFalse(SB.availability(dict(SB.blank(), requests_month=5), "gemini", NOW, capped)[0])
        silent = dict(SB.blank(), pending_since="2026-10-20T04:00:00Z")
        self.assertFalse(SB.availability(silent, "gemini", NOW, CONFIG)[0])
        self.assertTrue(SB.availability(silent, "gemini", SB.parse_time("2026-10-21T05:00:00Z"), CONFIG)[0])

    def test_configured_hold_and_per_app_cooldown(self):
        held = SB.Config({"ENVY_REVIEWER_HELD": "copilot=2026-11-01"})
        self.assertFalse(SB.availability(SB.blank(), "copilot", NOW, held)[0])
        self.assertTrue(SB.availability(SB.blank(), "copilot", SB.parse_time("2026-11-01T00:00:00Z"), held)[0])
        hourly = SB.Config({"ENVY_REVIEWER_COOLDOWN_HOURS": "coderabbit=1"})
        item = dict(SB.blank(), limited_at="2026-10-20T10:30:00Z")
        self.assertTrue(SB.availability(item, "coderabbit", NOW, hourly)[0])
        self.assertFalse(SB.availability(item, "coderabbit", NOW, CONFIG)[0])

    def test_copilot_reviewer_requests_are_counted(self):
        events = [{"event": "review_requested", "created_at": "2026-10-20T01:00:00Z",
                   "requested_reviewer": {"login": "Copilot"}},
                  {"event": "review_requested", "created_at": "2026-10-20T01:00:00Z",
                   "requested_reviewer": {"login": "Mika3578"}},
                  {"event": "labeled", "created_at": "2026-10-20T01:00:00Z"}]
        self.assertEqual(SB.requested_apps(events),
                         [{"login": "copilot-pull-request-reviewer[bot]",
                           "created_at": "2026-10-20T01:00:00Z"}])

    def test_window_start_handles_short_months_and_january(self):
        self.assertEqual(SB.window_start(SB.parse_time("2026-02-15T00:00:00Z"), 31),
                         SB.parse_time("2026-01-31T00:00:00Z"))
        self.assertEqual(SB.window_start(SB.parse_time("2026-01-05T00:00:00Z"), 18),
                         SB.parse_time("2025-12-18T00:00:00Z"))


class RankingTests(unittest.TestCase):
    def test_cold_start_recommends_the_default_primary(self):
        self.assertEqual([row["key"] for row in COLD], CONFIG.reviewers)
        self.assertEqual(SB.recommend(COLD), ("coderabbit", "copilot"))

    def test_precision_reorders_and_volume_tempers_luck(self):
        stats = {"amazon-q-developer[bot]": dict(SB.blank(), useful=9, rejected=1),
                 "coderabbitai[bot]": dict(SB.blank(), useful=2, rejected=8)}
        ranking = SB.rank(stats, CONFIG, NOW)
        self.assertEqual(ranking[0]["key"], "amazonq")
        self.assertEqual(ranking[-1]["key"], "coderabbit")
        self.assertLess(SB.score(dict(SB.blank(), useful=2)), SB.score(dict(SB.blank(), useful=10)))

    def test_held_reviewers_are_skipped_in_the_recommendation(self):
        stats = {"coderabbitai[bot]": dict(SB.blank(), useful=10, limited_at="2026-10-20T11:00:00Z")}
        ranking = SB.rank(stats, CONFIG, NOW)
        self.assertEqual(ranking[0]["key"], "coderabbit")
        self.assertFalse(ranking[0]["available"])
        self.assertEqual(SB.recommend(ranking), ("copilot", "amazonq"))
        self.assertEqual(SB.recommend([dict(r, available=False) for r in COLD]), (None, None))


class SilenceTests(unittest.TestCase):
    def ask(self, when):
        return {"login": "maintainer", "body": "/gemini review", "created_at": when}

    def test_silence_runs_from_the_earliest_open_request(self):
        records = [record(comments=[self.ask("2026-10-19T01:00:00Z")]),
                   record(comments=[self.ask("2026-10-20T11:00:00Z")])]
        stats = SB.analyze(records, CONFIG, NOW)
        self.assertEqual(stats["gemini-code-assist[bot]"]["pending_since"], "2026-10-19T01:00:00Z")

    def test_an_answer_restarts_the_clock_at_the_next_open_request(self):
        records = [
            record(comments=[self.ask("2026-10-19T01:00:00Z")]),
            record(comments=[self.ask("2026-10-20T02:00:00Z"),
                             {"login": "gemini-code-assist[bot]", "body": "Review done",
                              "created_at": "2026-10-20T02:10:00Z"}]),
            record(comments=[self.ask("2026-10-20T11:00:00Z")]),
        ]
        stats = SB.analyze(records, CONFIG, NOW)
        self.assertEqual(stats["gemini-code-assist[bot]"]["pending_since"], "2026-10-20T11:00:00Z")


class RenderTests(unittest.TestCase):
    def test_comment_terminator_in_state_cannot_break_parsing(self):
        config = SB.Config({"ENVY_REVIEWER_LOGINS": "gemini=evil-->bot[bot]"})
        stats = {"evil-->bot[bot]": SB.blank()}
        body = SB.render_scoreboard(stats, SB.rank(stats, config, NOW), NOW, 90, 1)
        self.assertEqual(body.splitlines()[0].count("-->"), 1)
        self.assertIn("evil-->bot[bot]", SB.parse_scoreboard(body)["stats"])

    def test_scoreboard_round_trips_and_recommends_without_requesting(self):
        body = SB.render_scoreboard(SB.analyze([], CONFIG, NOW), COLD, NOW, 90, 0)
        self.assertEqual(SB.parse_scoreboard(body)["ranking"], COLD)
        self.assertIn("Primary reviewer: `coderabbit`, ask with `@coderabbitai review`.", body)
        self.assertIn("`copilot`, ask with a reviewer request", body)
        self.assertIn("Nothing here requests a review.", body)
        self.assertIsNone(SB.parse_scoreboard("no marker"))
        with self.assertRaises(ValueError):
            SB.parse_scoreboard(f"{SB.SCOREBOARD_MARKER} {{\"x\":1}} -->")

    def test_bot_logins_from_graphql_are_normalized(self):
        self.assertEqual(SB.rest_login({"login": "coderabbitai", "__typename": "Bot"}), "coderabbitai[bot]")
        self.assertEqual(SB.rest_login({"login": "Mika3578", "__typename": "User"}), "Mika3578")

    def test_config_parses_repository_variables(self):
        config = SB.Config({"ENVY_REVIEWERS": "amazonq,coderabbit",
                            "ENVY_REVIEWER_RESET_DAYS": "amazonq=18, coderabbit=1",
                            "ENVY_REVIEWER_MONTHLY_CAPS": "amazonq=40",
                            "ENVY_REVIEWER_LOGINS": "amazonq=q-x[bot]",
                            "ENVY_REVIEW_TIMEOUT_HOURS": "3"})
        self.assertEqual(config.reviewers, ["amazonq", "coderabbit"])
        self.assertEqual(config.reset_days, {"amazonq": 18, "coderabbit": 1})
        self.assertEqual(config.caps, {"amazonq": 40})
        self.assertEqual(config.logins["amazonq"], "q-x[bot]")
        self.assertEqual(config.timeout, 3.0)
        with self.assertRaises(ValueError):
            SB.Config({"ENVY_REVIEWERS": "coderabbit,cubic"})


if __name__ == "__main__":
    unittest.main()
