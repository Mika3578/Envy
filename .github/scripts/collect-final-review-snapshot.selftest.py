#!/usr/bin/env python3
"""Offline tests for GraphQL reviewDecision collection."""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location(
    "collect_final_review_snapshot_mod", SCRIPTS / "collect-final-review-snapshot.py"
)
MOD = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = MOD
_SPEC.loader.exec_module(MOD)

HEAD = "a" * 40


def gql_payload(decision, head=HEAD, author="alice", include_decision=True,
                merge_state="CLEAN", include_merge_state=True):
    pr = {"headRefOid": head, "author": {"login": author}}
    if include_decision:
        pr["reviewDecision"] = decision
    if include_merge_state:
        pr["mergeStateStatus"] = merge_state
    return {"data": {"repository": {"pullRequest": pr}}}


class CollectSnapshotTests(unittest.TestCase):
    def test_changes_requested_from_graphql(self):
        fields = MOD.graphql_pr_gate_fields(gql_payload("CHANGES_REQUESTED"), HEAD)
        self.assertEqual(fields["review_decision"], "CHANGES_REQUESTED")
        self.assertEqual(fields["review_decision_source"], "graphql")
        self.assertFalse(fields["review_decision_unavailable"])

    def test_missing_review_decision_field_fail_closed(self):
        with self.assertRaises(RuntimeError):
            MOD.graphql_pr_gate_fields(gql_payload(None, include_decision=False), HEAD)

    def test_graphql_errors_fail_closed(self):
        with self.assertRaises(RuntimeError):
            MOD.graphql_pr_gate_fields({"errors": [{"message": "boom"}]}, HEAD)

    def test_head_mismatch_fail_closed(self):
        with self.assertRaises(RuntimeError):
            MOD.graphql_pr_gate_fields(gql_payload("APPROVED"), "b" * 40)

    def test_empty_null_decision_is_explicit_graphql_empty(self):
        fields = MOD.graphql_pr_gate_fields(gql_payload(None), HEAD)
        self.assertEqual(fields["review_decision"], "")
        self.assertEqual(fields["review_decision_source"], "graphql")

    def test_approved_decision(self):
        fields = MOD.graphql_pr_gate_fields(gql_payload("APPROVED"), HEAD)
        self.assertEqual(fields["review_decision"], "APPROVED")
        self.assertEqual(fields["pr_author_login"], "alice")
        self.assertEqual(fields["merge_state_status"], "CLEAN")

    def test_missing_merge_state_fail_closed(self):
        with self.assertRaises(RuntimeError):
            MOD.graphql_pr_gate_fields(
                gql_payload("APPROVED", include_merge_state=False), HEAD
            )

    def test_missing_comments_pageinfo_fail_closed(self):
        with self.assertRaises(RuntimeError):
            MOD.count_thread_dispositions(
                [
                    {
                        "isResolved": True,
                        "comments": {
                            "nodes": [
                                {
                                    "author": {
                                        "login": "alice",
                                        "__typename": "User",
                                    },
                                    "commit": {"oid": HEAD},
                                }
                            ]
                        },
                    }
                ],
                HEAD,
            )

    def test_resolved_copilot_thread_without_reply_is_untreated(self):
        unresolved, untreated = MOD.count_thread_dispositions(
            [
                {
                    "isResolved": True,
                    "comments": {
                        "pageInfo": {"hasNextPage": False},
                        "nodes": [
                            {
                                "author": {
                                    "login": "copilot-pull-request-reviewer[bot]",
                                    "__typename": "Bot",
                                },
                                "commit": {"oid": HEAD},
                            }
                        ],
                    },
                }
            ],
            HEAD,
        )
        self.assertEqual(unresolved, 0)
        self.assertEqual(untreated, 1)

    def test_resolved_thread_with_reply_is_treated(self):
        unresolved, untreated = MOD.count_thread_dispositions(
            [
                {
                    "isResolved": True,
                    "comments": {
                        "pageInfo": {"hasNextPage": False},
                        "nodes": [
                            {
                                "author": {
                                    "login": "copilot-pull-request-reviewer[bot]",
                                    "__typename": "Bot",
                                },
                                "commit": {"oid": HEAD},
                            },
                            {
                                "author": {"login": "alice", "__typename": "User"},
                                "commit": {"oid": HEAD},
                            },
                        ],
                    },
                }
            ],
            HEAD,
        )
        self.assertEqual((unresolved, untreated), (0, 0))

    def test_bot_reply_does_not_treat_current_head_thread(self):
        unresolved, untreated = MOD.count_thread_dispositions(
            [
                {
                    "isResolved": True,
                    "comments": {
                        "pageInfo": {"hasNextPage": False},
                        "nodes": [
                            {
                                "author": {
                                    "login": "copilot-pull-request-reviewer[bot]",
                                    "__typename": "Bot",
                                },
                                "commit": {"oid": HEAD},
                            },
                            {
                                "author": {"login": "cursor[bot]", "__typename": "Bot"},
                                "commit": {"oid": HEAD},
                            },
                        ],
                    },
                }
            ],
            HEAD,
        )
        self.assertEqual((unresolved, untreated), (0, 1))

    def test_old_commit_reply_does_not_treat_current_head_thread(self):
        unresolved, untreated = MOD.count_thread_dispositions(
            [
                {
                    "isResolved": True,
                    "comments": {
                        "pageInfo": {"hasNextPage": False},
                        "nodes": [
                            {
                                "author": {
                                    "login": "copilot-pull-request-reviewer[bot]",
                                    "__typename": "Bot",
                                },
                                "commit": {"oid": HEAD},
                            },
                            {
                                "author": {"login": "alice", "__typename": "User"},
                                "commit": {"oid": "b" * 40},
                            },
                        ],
                    },
                }
            ],
            HEAD,
        )
        self.assertEqual((unresolved, untreated), (0, 1))

    def test_resolved_human_thread_without_reply_is_untreated(self):
        unresolved, untreated = MOD.count_thread_dispositions(
            [
                {
                    "isResolved": True,
                    "comments": {
                        "pageInfo": {"hasNextPage": False},
                        "nodes": [{"author": {"login": "alice"}}],
                    },
                }
            ]
        )
        self.assertEqual((unresolved, untreated), (0, 1))

    def test_outdated_thread_with_user_reply_is_treated(self):
        unresolved, untreated = MOD.count_thread_dispositions(
            [
                {
                    "isResolved": True,
                    "isOutdated": True,
                    "comments": {
                        "pageInfo": {"hasNextPage": False},
                        "nodes": [
                            {
                                "author": {
                                    "login": "copilot-pull-request-reviewer[bot]",
                                    "__typename": "Bot",
                                },
                                "commit": {"oid": "b" * 40},
                            },
                            {
                                "author": {"login": "alice", "__typename": "User"},
                                "commit": {"oid": "b" * 40},
                            },
                        ],
                    },
                }
            ],
            HEAD,
        )
        self.assertEqual((unresolved, untreated), (0, 0))

    def test_file_inventory_includes_rename_source(self):
        paths = MOD.file_inventory_paths(
            1,
            [
                {
                    "filename": "Envy/Buffer.cpp",
                    "previous_filename": "AGENTS.md",
                }
            ],
        )
        self.assertEqual(paths, ["Envy/Buffer.cpp", "AGENTS.md"])

    def test_closed_or_retargeted_pr_fails_closed(self):
        repo = {"default_branch": "develop"}
        with self.assertRaises(RuntimeError):
            MOD.require_open_default_same_repo(
                {"state": "closed", "base": {"ref": "develop"},
                 "head": {"repo": {"full_name": "Mika3578/Envy"}}},
                "Mika3578/Envy",
                repo,
            )
        with self.assertRaises(RuntimeError):
            MOD.require_open_default_same_repo(
                {"state": "open", "base": {"ref": "main"},
                 "head": {"repo": {"full_name": "Mika3578/Envy"}}},
                "Mika3578/Envy",
                repo,
            )
        with self.assertRaises(RuntimeError):
            MOD.require_open_default_same_repo(
                {"state": "open", "base": {"ref": "develop"},
                 "head": {"repo": {"full_name": "other/fork"}}},
                "Mika3578/Envy",
                repo,
            )

    def test_file_inventory_fails_closed_when_truncated(self):
        with self.assertRaises(RuntimeError):
            MOD.file_inventory_paths(2, [{"filename": "Envy/Buffer.cpp"}])

    def test_file_inventory_fails_closed_past_github_cap(self):
        with self.assertRaises(RuntimeError):
            MOD.file_inventory_paths(MOD.GITHUB_PR_FILES_CAP + 1, [])

    def test_unique_open_pr_refuses_shared_head(self):
        shared = [
            {"number": 397, "state": "open"},
            {"number": 398, "state": "open"},
        ]
        with self.assertRaises(RuntimeError):
            MOD.unique_open_pr_numbers(shared, 397)

    def test_unique_open_pr_accepts_single_open_head(self):
        entries = [
            {"number": 397, "state": "open"},
            {"number": 200, "state": "closed"},
        ]
        self.assertEqual(MOD.unique_open_pr_numbers(entries, 397), {397})

    def test_paginate_commit_pulls_flattens_slurp_pages(self):
        class Result:
            returncode = 0
            stderr = ""
            stdout = json.dumps(
                [
                    [{"number": 397, "state": "open"}],
                    [{"number": 398, "state": "open"}],
                ]
            )

        with patch.object(MOD.subprocess, "run", return_value=Result()) as call:
            related = MOD.paginate_commit_pulls("Mika3578/Envy", HEAD)
        argv = call.call_args.args[0]
        self.assertIn("--paginate", argv)
        self.assertIn("--slurp", argv)
        with self.assertRaises(RuntimeError):
            MOD.unique_open_pr_numbers(related, 397)

    def test_collector_reconstructs_prior_outcomes(self):
        text = (SCRIPTS / "collect-final-review-snapshot.py").read_text(encoding="utf-8")
        self.assertIn("reconstruct_prior_outcomes_from_reviews", text)
        self.assertIn("apply_loop_guards", text)


if __name__ == "__main__":
    unittest.main()
