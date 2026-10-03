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


if __name__ == "__main__":
    unittest.main()
