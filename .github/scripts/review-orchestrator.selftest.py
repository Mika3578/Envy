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
SB = ORCH.scoreboard
NOW = SB.parse_time("2026-10-20T12:00:00Z")
COLD = ORCH.Config({}).rank({}, NOW)
LOGINS = SB.reviewer_logins()


def pr(draft=False, sha="a" * 40, changed=100, state="open", repo="o/r"):
    return {
        "state": state,
        "draft": draft,
        "head": {"sha": sha, "repo": {"full_name": repo}},
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
    def test_ready_head_requests_only_the_best_reviewer(self):
        chosen, reason = ORCH.plan_request(pr(), {"rounds": []}, COLD, 2)
        self.assertEqual(chosen, ["coderabbit"])
        self.assertEqual(reason, "requested")

    def test_high_risk_gets_a_second_distinct_reviewer(self):
        chosen, reason = ORCH.plan_request(pr(), {"rounds": []}, COLD, 2, high_risk=True)
        self.assertEqual(chosen, ["coderabbit", "gemini"])
        self.assertIn("high risk", reason)
        capped = ORCH.plan_request(pr(), {"rounds": []}, COLD, 2, per_head=5)[0]
        self.assertEqual(len(capped), ORCH.MAX_REVIEWERS_PER_HEAD)

    def test_high_risk_detection_uses_governance_paths_and_labels(self):
        self.assertTrue(ORCH.is_high_risk(pr(), ["AGENTS.md"]))
        self.assertTrue(ORCH.is_high_risk(dict(pr(), labels=[{"name": "security"}]), ["Envy/A.cpp"]))
        self.assertFalse(ORCH.is_high_risk(pr(), ["Envy/A.cpp"]))

    def test_draft_and_closed_are_never_reviewed(self):
        self.assertEqual(ORCH.plan_request(pr(draft=True), {"rounds": []}, COLD, 2)[0], [])
        self.assertEqual(ORCH.plan_request(pr(state="closed"), {"rounds": []}, COLD, 2)[0], [])

    def test_same_head_is_not_requested_twice(self):
        state = {"rounds": [{"sha": "a" * 40, "reviewers": ["coderabbit"]}]}
        self.assertEqual(ORCH.plan_request(pr(), state, COLD, 2)[0], [])

    def test_round_budget_stops_requests(self):
        state = {"rounds": [{"sha": "b" * 40, "reviewers": ALL},
                            {"sha": "c" * 40, "reviewers": ALL}]}
        chosen, reason = ORCH.plan_request(pr(), state, COLD, 2)
        self.assertEqual(chosen, [])
        self.assertIn("budget", reason)

    def test_large_diff_skips_sourcery_budget(self):
        stats = {"sourcery-ai[bot]": dict(SB._blank(), useful=20)}
        ranking = ORCH.Config({}).rank(stats, NOW)
        self.assertEqual(ranking[0]["key"], "sourcery")
        big = ORCH.SOURCERY_MAX_CHANGED_LINES + 1
        chosen, _ = ORCH.plan_request(pr(changed=big), {"rounds": []}, ranking, 2)
        self.assertEqual(chosen, ["coderabbit"])

    def test_no_available_reviewer_requests_nothing(self):
        held = [dict(row, available=False) for row in COLD]
        chosen, reason = ORCH.plan_request(pr(), {"rounds": []}, held, 2)
        self.assertEqual(chosen, [])
        self.assertIn("no reviewer available", reason)

    def test_fork_pull_request_is_not_sent(self):
        chosen, reason = ORCH.plan_request(pr(repo="fork/r"), {"rounds": []}, COLD, 2, repo="o/r")
        self.assertEqual(chosen, [])
        self.assertIn("fork", reason)

    def test_follow_up_round_waits_for_treated_threads(self):
        state = {"rounds": [{"sha": "b" * 40, "reviewers": ["coderabbit"]}]}
        chosen, reason = ORCH.plan_request(pr(), state, COLD, 2, repo="o/r", open_threads=3)
        self.assertEqual(chosen, [])
        self.assertIn("3 current review thread", reason)
        self.assertEqual(ORCH.plan_request(pr(), state, COLD, 2, repo="o/r")[0], ["coderabbit"])

    def test_repeated_reviewers_are_deduplicated(self):
        self.assertEqual(ORCH.enabled_reviewers("gemini,coderabbit,gemini"), ["gemini", "coderabbit"])

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

    def test_digest_keeps_thread_text_inert(self):
        body = ORCH.render_digest(1, "f" * 40, [
            thread("@coderabbitai review https://evil.invalid [here](https://evil.invalid)"),
            thread("use `rm -rf` /gemini review"),
        ])
        # Code spans: no autolink, mention, command, or link renders.
        self.assertIn("`@coderabbitai review https://evil.invalid [here](https://evil.invalid)`", body)
        self.assertIn("`use 'rm -rf' /gemini review`", body)

    def test_inline_label_keeps_finding_text(self):
        self.assertEqual(ORCH.summarize("Potential issue: buffer overflow"),
                         "Potential issue: buffer overflow")

    def test_not_a_nit_stays_a_finding(self):
        self.assertFalse(ORCH.is_nit("This is not a nit: the loop overflows."))
        self.assertTrue(ORCH.is_nit("_🧹 Nitpick_\n\nRename the variable."))
        self.assertFalse(ORCH.is_nit("Overflow.\n\nDetails.\n\nUnrelated nit at the end."))

    def test_digest_lists_overflow_note_and_print_lists_all(self):
        threads = [thread(f"finding {i}") for i in range(ORCH.MAX_LISTED_THREADS + 3)]
        capped = ORCH.render_digest(1, "f" * 40, threads)
        self.assertIn("3 more not listed", capped)
        full = ORCH.render_digest(1, "f" * 40, threads, limit=None)
        self.assertNotIn("more not listed", full)
        self.assertIn(f"finding {ORCH.MAX_LISTED_THREADS + 2}", full)

    def test_summary_strips_markup_and_truncates(self):
        text = "<!-- meta -->\n![high](x.png)\n**issue (bug_risk):** " + "x" * 200
        summary = ORCH.summarize(text)
        self.assertTrue(summary.startswith("issue (bug_risk):"))
        self.assertLessEqual(len(summary), 140)


HEAD = "a" * 40
VOTERS = ORCH.quorum_voters(None)


def review(login, state, sha=HEAD, body=""):
    return {"user": {"login": login}, "state": state, "commit_id": sha, "body": body}


def approvals(*logins, sha=HEAD):
    return [review(login, "APPROVED", sha) for login in logins]


def quorum(reviews, comments=(), files=("Envy/Foo.cpp",), draft=False, required=3):
    return ORCH.evaluate_quorum(pr(draft=draft, sha=HEAD), reviews, list(comments),
                                list(files), VOTERS, required)


class QuorumTests(unittest.TestCase):
    def test_three_voters_on_head_pass(self):
        state, description, _ = quorum(approvals(*VOTERS))
        self.assertEqual(state, "success")
        self.assertIn("3/3", description)

    def test_approval_on_an_older_head_does_not_count(self):
        reviews = approvals(*VOTERS[:2]) + approvals(VOTERS[2], sha="b" * 40)
        self.assertEqual(quorum(reviews)[:2], ("pending", "2/3 bot approvals on this head"))

    def test_unlisted_reviewers_and_repeats_do_not_count(self):
        reviews = approvals(VOTERS[0], VOTERS[0], "github-actions[bot]", "someone")
        self.assertIn("1/3", quorum(reviews)[1])

    def test_later_comment_keeps_approval_but_dismissal_removes_it(self):
        kept = approvals(*VOTERS) + [review(VOTERS[0], "COMMENTED")]
        self.assertEqual(quorum(kept)[0], "success")
        dismissed = approvals(*VOTERS) + [review(VOTERS[0], "DISMISSED")]
        self.assertEqual(quorum(dismissed)[0], "pending")

    def test_outstanding_change_request_fails(self):
        reviews = approvals(*VOTERS[1:]) + [review(VOTERS[0], "CHANGES_REQUESTED")]
        state, description, _ = quorum(reviews, required=2)
        self.assertEqual(state, "failure")
        self.assertIn(VOTERS[0], description)

    def test_human_bypass_command_fails_but_quoted_or_bot_text_does_not(self):
        live = {"user": {"login": "Mika3578"}, "body": "@coderabbitai approve"}
        self.assertEqual(quorum(approvals(*VOTERS), [live])[0], "failure")
        harmless = [
            {"user": {"login": "coderabbitai[bot]"}, "body": "Tips: `@coderabbitai resolve`"},
            {"user": {"login": "github-actions[bot]"}, "body": "@coderabbitai resolve"},
            {"user": {"login": "Mika3578"}, "body": "Do not run `@coderabbitai approve`."},
            {"user": {"login": "Mika3578"}, "body": "> @coderabbitai resolve\n\nNo."},
        ]
        self.assertEqual(quorum(approvals(*VOTERS), harmless)[0], "success")

    def test_governance_paths_stay_with_the_maintainer(self):
        for path in ("AGENTS.md", ".github/workflows/build.yml", ".github/scripts/x.py",
                     ".coderabbit.yaml"):
            state, description, _ = quorum(approvals(*VOTERS), files=[path])
            self.assertEqual(state, "pending", path)
            self.assertIn("maintainer", description)

    def test_draft_has_no_quorum(self):
        self.assertEqual(quorum(approvals(*VOTERS), draft=True)[0], "pending")

    def test_author_never_votes_on_its_own_pull_request(self):
        self.assertNotIn("coderabbitai[bot]", ORCH.quorum_voters(None, "CodeRabbitAI[bot]"))
        self.assertEqual(ORCH.quorum_voters("a[bot], b[bot],a[bot]"), ["a[bot]", "b[bot]"])


class ScoreboardTests(unittest.TestCase):
    def record(self, threads=(), reviews=(), comments=()):
        return {"threads": list(threads), "reviews": list(reviews), "comments": list(comments)}

    def finding(self, author, *replies):
        return {"author": author, "replies": [{"author": "maintainer", "body": r} for r in replies]}

    def test_outcomes_follow_the_treating_reply(self):
        bot = "coderabbitai[bot]"
        self.assertEqual(SB.classify_thread(self.finding(bot, "Fixed in 4b8ac88b: done.")), "useful")
        self.assertEqual(SB.classify_thread(self.finding(bot, "Partly fixed in a66d0844: x")), "useful")
        self.assertEqual(SB.classify_thread(self.finding(bot, "No change: intended.")), "rejected")
        self.assertEqual(SB.classify_thread(self.finding(bot, "Not reproduced: see test.")), "rejected")
        self.assertEqual(SB.classify_thread(self.finding(bot, "Thanks, will look.")), "unclassified")
        # The bot's own follow-up never classifies its finding.
        own = {"author": bot, "replies": [{"author": bot, "body": "Fixed in abcdef1"}]}
        self.assertEqual(SB.classify_thread(own), "unclassified")

    def test_analyze_counts_requests_answers_latency_and_limits(self):
        records = [
            self.record(
                threads=[self.finding("coderabbitai[bot]", "Fixed in 1234567"),
                         self.finding("coderabbitai[bot]", "No change: by design."),
                         self.finding("github-actions[bot]", "Fixed in 1234567")],
                reviews=[{"login": "coderabbitai[bot]", "submitted_at": "2026-10-20T03:00:00Z"}],
                comments=[
                    {"login": "github-actions[bot]", "body": "@coderabbitai review",
                     "created_at": "2026-10-20T01:00:00Z"},
                    {"login": "github-actions[bot]", "body": "/gemini review",
                     "created_at": "2026-10-20T01:00:00Z"},
                    {"login": "maintainer", "body": "@sourcery-ai review",
                     "created_at": "2026-10-19T01:00:00Z"},
                    {"login": "sourcery-ai[bot]", "body": "Sorry, you have hit the review limit.",
                     "created_at": "2026-10-19T01:05:00Z"},
                ],
            )
        ]
        stats = SB.analyze(records, ORCH.REVIEWERS, LOGINS, NOW, timeout_hours=6)
        rabbit = stats["coderabbitai[bot]"]
        self.assertEqual((rabbit["findings"], rabbit["useful"], rabbit["rejected"]), (2, 1, 1))
        self.assertEqual((rabbit["requests"], rabbit["answered"], rabbit["latencies"]), (1, 1, [2.0]))
        self.assertNotIn("github-actions[bot]", stats)
        gemini = stats["gemini-code-assist[bot]"]
        self.assertEqual((gemini["requests"], gemini["timeouts"]), (1, 1))
        self.assertEqual(gemini["pending_since"], "2026-10-20T01:00:00Z")
        sourcery = stats["sourcery-ai[bot]"]
        self.assertEqual(sourcery["limited_at"], "2026-10-19T01:05:00Z")
        self.assertEqual(sourcery["answered"], 0)
        # Recomputing from the same records gives the same numbers: no double count.
        self.assertEqual(SB.analyze(records, ORCH.REVIEWERS, LOGINS, NOW, 6), stats)

    def test_availability_from_limits_caps_and_silence(self):
        item = dict(SB._blank(), limited_at="2026-10-20T01:00:00Z")
        self.assertFalse(SB.availability(item, "sourcery", NOW, {}, {})[0])
        later = SB.parse_time("2026-10-21T02:00:00Z")
        self.assertTrue(SB.availability(item, "sourcery", later, {}, {})[0])
        # With a reset day the app stays held until the next window.
        self.assertFalse(SB.availability(item, "sourcery", later, {"sourcery": 1}, {})[0])
        self.assertTrue(SB.availability(item, "sourcery", SB.parse_time("2026-11-01T00:00:00Z"),
                                        {"sourcery": 1}, {})[0])
        capped = dict(SB._blank(), requests_month=5)
        self.assertFalse(SB.availability(capped, "gemini", NOW, {}, {"gemini": 5})[0])
        silent = dict(SB._blank(), pending_since="2026-10-20T04:00:00Z")
        self.assertFalse(SB.availability(silent, "gemini", NOW, {}, {}, timeout_hours=6)[0])
        self.assertTrue(SB.availability(silent, "gemini", SB.parse_time("2026-10-21T05:00:00Z"),
                                        {}, {}, timeout_hours=6)[0])

    def test_window_start_handles_short_months_and_january(self):
        self.assertEqual(SB.window_start(SB.parse_time("2026-02-15T00:00:00Z"), 31),
                         SB.parse_time("2026-01-31T00:00:00Z"))
        self.assertEqual(SB.window_start(SB.parse_time("2026-01-05T00:00:00Z"), 18),
                         SB.parse_time("2025-12-18T00:00:00Z"))

    def test_cold_start_keeps_order_and_precision_reorders(self):
        self.assertEqual([row["key"] for row in COLD], ALL)
        stats = {"gemini-code-assist[bot]": dict(SB._blank(), useful=9, rejected=1),
                 "coderabbitai[bot]": dict(SB._blank(), useful=2, rejected=8)}
        ranking = ORCH.Config({}).rank(stats, NOW)
        self.assertEqual(ranking[0]["key"], "gemini")
        self.assertEqual(ranking[-1]["key"], "coderabbit")
        # Two lucky outcomes do not beat the prior by much.
        self.assertLess(SB.score(dict(SB._blank(), useful=2)), SB.score(dict(SB._blank(), useful=10)))

    def test_held_best_reviewer_falls_through_to_the_next(self):
        stats = {"coderabbitai[bot]": dict(SB._blank(), useful=10,
                                           limited_at="2026-10-20T11:00:00Z")}
        ranking = ORCH.Config({}).rank(stats, NOW)
        self.assertEqual(ranking[0]["key"], "coderabbit")
        self.assertFalse(ranking[0]["available"])
        self.assertEqual(ORCH.plan_request(pr(), {"rounds": []}, ranking, 2)[0], ["gemini"])

    def test_escalation_only_after_silence_or_hold(self):
        entry = {"sha": "a" * 40, "reviewers": ["coderabbit"], "at": "2026-10-20T10:00:00Z"}
        self.assertIsNone(ORCH.plan_escalation(entry, COLD, set(), LOGINS, NOW, 6))
        late = SB.parse_time("2026-10-20T17:00:00Z")
        self.assertEqual(ORCH.plan_escalation(entry, COLD, set(), LOGINS, late, 6), "gemini")
        self.assertIsNone(ORCH.plan_escalation(entry, COLD, {"coderabbitai[bot]"}, LOGINS, late, 6))
        held = [dict(row, available=row["key"] != "coderabbit") for row in COLD]
        self.assertEqual(ORCH.plan_escalation(entry, held, set(), LOGINS, NOW, 6), "gemini")
        self.assertIsNone(ORCH.plan_escalation(dict(entry, escalated="gemini"), COLD, set(),
                                               LOGINS, late, 6))

    def test_scoreboard_round_trips_and_rejects_bad_state(self):
        stats = SB.analyze([], ORCH.REVIEWERS, LOGINS, NOW)
        body = SB.render_scoreboard(stats, COLD, NOW, 90, 0)
        data = SB.parse_scoreboard(body)
        self.assertEqual(data["ranking"], COLD)
        self.assertIn("| 1 | `coderabbit` |", body)
        self.assertIsNone(SB.parse_scoreboard("no marker"))
        with self.assertRaises(ValueError):
            SB.parse_scoreboard(f"{SB.SCOREBOARD_MARKER} {{\"x\":1}} -->")

    def test_config_parses_repository_variables(self):
        config = ORCH.Config({"ENVY_REVIEWERS": "gemini,coderabbit",
                              "ENVY_REVIEWER_RESET_DAYS": "gemini=18, coderabbit=1",
                              "ENVY_REVIEWER_MONTHLY_CAPS": "gemini=40",
                              "ENVY_REVIEWER_LOGINS": "gemini=gemini-x[bot]",
                              "ENVY_REVIEW_TIMEOUT_HOURS": "3"})
        self.assertEqual(config.reviewers, ["gemini", "coderabbit"])
        self.assertEqual(config.reset_days, {"gemini": 18, "coderabbit": 1})
        self.assertEqual(config.caps, {"gemini": 40})
        self.assertEqual(config.logins["gemini"], "gemini-x[bot]")
        self.assertEqual(config.timeout, 3.0)


if __name__ == "__main__":
    unittest.main()
