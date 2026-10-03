#!/usr/bin/env python3
"""Offline tests for GraphQL reviewDecision collection."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location(
    "collect_final_review_snapshot_mod", SCRIPTS / "collect-final-review-snapshot.py"
)
MOD = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = MOD
_SPEC.loader.exec_module(MOD)

HEAD = "a" * 40


def gql_payload(decision, head=HEAD, author="alice", include_decision=True):
    pr = {"headRefOid": head, "author": {"login": author}}
    if include_decision:
        pr["reviewDecision"] = decision
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


if __name__ == "__main__":
    unittest.main()
