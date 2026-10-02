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

    def test_same_name_check_and_status_both_must_pass(self):
        run = dict(name="Build", head_sha="new", id=3, status="completed", conclusion="success")
        status = dict(context="Build", id=4, state="failure")
        receipts = checks.commit_checks("new", ["Build"], [run], [status])
        self.assertEqual({item["state"] for item in receipts}, {"SUCCESS", "FAILURE"})

    def test_empty_policy_and_wrong_repository_fail_closed(self):
        with patch.object(checks, "gh", return_value=[]):
            with self.assertRaises(ValueError):
                checks.collect_checks("Mika3578/Envy", "a" * 40)
        with self.assertRaises(ValueError):
            checks.collect_checks("other/repo", "a" * 40)


if __name__ == "__main__":
    unittest.main()
