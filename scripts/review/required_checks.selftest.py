#!/usr/bin/env python3
"""Required-context coverage and exact-commit receipt regression tests."""
import unittest
from unittest.mock import patch
import required_checks as checks


class CheckTests(unittest.TestCase):
    def test_missing_and_stale_receipts_remain_pending(self):
        stale = dict(name="Build", head_sha="old", id=3, status="completed", conclusion="success")
        receipts = checks.commit_checks("new", ["Build", "Security"], [stale], [])
        self.assertEqual([item["state"] for item in receipts], ["PENDING", "PENDING"])

    def test_delayed_old_start_cannot_override_new_generation(self):
        old = dict(name="Build", head_sha="new", id=3, status="completed", conclusion="success", started_at="later")
        new = dict(name="Build", head_sha="new", id=4, status="queued", conclusion=None, started_at="earlier")
        for runs in ([old, new], [new, old]):
            self.assertEqual(checks.commit_checks("new", ["Build"], runs, [])[0]["state"], "QUEUED")

    def test_unbound_check_and_status_merge_to_latest(self):
        run = dict(
            name="Build",
            head_sha="new",
            id=3,
            status="completed",
            conclusion="success",
            completed_at="2026-01-02T00:00:00Z",
        )
        status = dict(
            context="Build",
            id=4,
            state="failure",
            created_at="2026-01-01T00:00:00Z",
        )
        receipts = checks.commit_checks("new", ["Build"], [run], [status])
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0]["state"], "SUCCESS")
        # Newer failing status must win over an older successful check run.
        status["created_at"] = "2026-01-03T00:00:00Z"
        receipts = checks.commit_checks("new", ["Build"], [run], [status])
        self.assertEqual(receipts[0]["state"], "FAILURE")

    def test_incomplete_check_outranks_status_without_timestamps(self):
        run = dict(name="Build", head_sha="new", id=3, status="queued", conclusion=None)
        status = dict(context="Build", id=4, state="success", created_at="2026-01-03T00:00:00Z")
        receipts = checks.commit_checks("new", ["Build"], [run], [status])
        self.assertEqual(receipts[0]["state"], "QUEUED")

    def test_unrelated_app_cannot_satisfy_required_receipt(self):
        required = [{"context": "Build", "integration_id": 15368}]
        foreign = dict(name="Build", head_sha="new", id=9, status="completed",
                       conclusion="success", app={"id": 1})
        native = dict(name="Build", head_sha="new", id=10, status="queued",
                      conclusion=None, app={"id": 15368})
        receipts = checks.commit_checks("new", required, [foreign, native], [])
        self.assertEqual(receipts[0]["state"], "QUEUED")
        status = dict(context="Build", id=11, state="success")
        self.assertEqual(
            checks.commit_checks("new", required, [foreign], [status])[0]["state"],
            "PENDING",
        )

    def test_skipped_is_canonical_passing_state(self):
        self.assertIn("SKIPPED", checks.PASSING_CHECK_STATES)
        self.assertNotIn("SKIPPED", checks.GATE_PASSING_CHECK_STATES)
        run = dict(name="Build", head_sha="new", id=3, status="completed", conclusion="skipped")
        self.assertEqual(checks.commit_checks("new", ["Build"], [run], [])[0]["state"], "SKIPPED")

    def test_same_context_keeps_separate_integration_receipts(self):
        required = [
            {"context": "Build", "integration_id": 1},
            {"context": "Build", "integration_id": 2},
        ]
        first = dict(name="Build", head_sha="new", id=3, status="completed",
                     conclusion="success", app={"id": 1})
        second = dict(name="Build", head_sha="new", id=4, status="completed",
                      conclusion="failure", app={"id": 2})
        receipts = checks.commit_checks("new", required, [first, second], [])
        self.assertEqual(len(receipts), 2)
        by_app = {item["integration_id"]: item["state"] for item in receipts}
        self.assertEqual(by_app[1], "SUCCESS")
        self.assertEqual(by_app[2], "FAILURE")

    def test_unbound_integration_id_is_allowed(self):
        specs = checks.required_specs([
            {"context": "Build", "integration_id": None},
            {"context": "Security", "integration_id": 1},
        ])
        self.assertEqual(specs[0]["integration_id"], None)
        self.assertEqual(specs[1]["integration_id"], 1)

    def test_required_specs_reject_shared_actions_gate_enrollment(self):
        with self.assertRaises(ValueError):
            checks.required_specs([
                {
                    "context": "Final review gate",
                    "integration_id": checks.GATE_PUBLISHER_INTEGRATION_ID,
                }
            ])

    def test_required_specs_reject_shared_actions_gate_enrollment(self):
        with self.assertRaises(ValueError):
            checks.required_specs([
                {
                    "context": "Final review gate",
                    "integration_id": checks.GATE_PUBLISHER_INTEGRATION_ID,
                }
            ])

    def test_collect_exports_required_specs(self):
        rules = [{
            "type": "required_status_checks",
            "parameters": {
                "required_status_checks": [
                    {"context": "Build", "integration_id": 1},
                    {"context": "Build", "integration_id": 2},
                ]
            },
        }]
        with patch.object(checks, "gh", side_effect=[rules, [{"check_runs": []}], [[]]]):
            out = checks.collect_checks("Mika3578/Envy", "a" * 40)
        self.assertEqual(out["required_names"], ["Build", "Build"])
        self.assertEqual(
            out["required_specs"],
            [
                {"context": "Build", "integration_id": 1},
                {"context": "Build", "integration_id": 2},
            ],
        )

    def test_empty_policy_and_wrong_repository_fail_closed(self):
        with patch.object(checks, "gh", return_value=[]):
            with self.assertRaises(ValueError):
                checks.collect_checks("Mika3578/Envy", "a" * 40)
        with self.assertRaises(ValueError):
            checks.collect_checks("other/repo", "a" * 40)


if __name__ == "__main__":
    unittest.main()
