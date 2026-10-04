#!/usr/bin/env python3
"""Offline trust, persistence, publication and executor tests; no credentials."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("review_service", Path(__file__).with_name("service.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def snapshot():
    return {"pr": {"head": {"sha": "a" * 40}, "base": {"sha": "b" * 40},
                   "user": {"login": "owner"}, "draft": True, "labels": []},
            "reviews": [{"id": 1, "user": {"login": "bot"}, "body": "Overview defect",
                         "commit_id": "a" * 40, "state": "COMMENTED"}],
            "inline": [], "comments": [], "threads": [],
            "required_names": ["Build"],
            "checks": [{"name": "Build", "state": "SUCCESS"}]}


def eligible_pull(head, base, **extra):
    pull = {
        "state": "open",
        "draft": False,
        "node_id": "PR",
        "mergeable_state": "clean",
        "head": {"sha": head, "ref": "ci/trusted-copilot-review-loop",
                 "repo": {"full_name": "Mika3578/Envy"}},
        "base": {"sha": base, "ref": "develop"},
    }
    pull.update(extra)
    return pull


class ServiceTests(unittest.TestCase):
    def test_internationalized_mailboxes_cannot_be_published(self):
        for local, domain in (("\u7528\u6237", "example.net"), ("user", "ex\u00e4mple.net"),
                              ("\u7528\u6237", "\u90ae\u7bb1.\u4e2d\u56fd")):
            with self.subTest(domain=domain):
                with self.assertRaises(ValueError):
                    mod.public_text(local + "@" + domain)
        self.assertEqual(mod.public_text("@reviewer-bot please review"), "@reviewer-bot please review")

    def test_forged_public_marker_cannot_suppress_publisher_reply(self):
        snap = snapshot()
        snap["publisher_login"] = "maintainer"
        source = mod.sources(snap)[0]
        head, base = mod.identity(snap["pr"])
        marker = "<!-- envy-disposition:" + mod.hashlib.sha256(
            f"{source['key']}:{head}:{base}".encode()).hexdigest() + " -->"
        snap["comments"] = [{"body": marker, "user": {"login": "stranger"}}]
        disposition = {"status": "fixed", "comment": "Bounds are validated.", "evidence": "Regression passed."}
        with patch.object(mod, "gh_json", return_value={}) as publish:
            mod.publish_disposition(1, source, disposition, head, base, snap)
            publish.assert_called_once()

    def test_malformed_thread_flags_fail_closed(self):
        snap = snapshot()
        snap["threads"] = [{"isResolved": "yes", "isOutdated": False, "comments": {"nodes": []}}]
        with self.assertRaises(ValueError):
            mod.threads_blocking_final_review(snap)
        snap["threads"] = [{"isResolved": True, "isOutdated": None, "comments": {"nodes": []}}]
        with self.assertRaises(ValueError):
            mod.threads_blocking_final_review(snap)

    def test_bot_reply_does_not_clear_final_review_blocker(self):
        snap = snapshot()
        snap["pr"]["draft"] = False
        snap["threads"] = [{"isResolved": True, "isOutdated": False, "comments": {"nodes": [
            {"author": {"login": "copilot-pull-request-reviewer", "__typename": "Bot"},
             "commit": {"oid": "a" * 40}},
            {"author": {"login": "cursor[bot]", "__typename": "Bot"},
             "commit": {"oid": "a" * 40}},
        ]}}]
        state = {"handled": {}, "stops": {}, "requests": {}}
        entry = {"number": 1, "reviewers": [{"login": "bot"}]}
        for source in mod.trusted_sources(entry, snap):
            state["handled"][source["key"]] = {"head": "a" * 40, "base": "b" * 40}
        mod.final_review({}, entry, snap, state, None)
        self.assertNotIn("phase", state)

    def test_unavailable_bot_does_not_block_stable_draft(self):
        snap = snapshot()
        state = {"handled": {}, "stops": {}, "requests": {}}
        entry = {"number": 1, "reviewers": [{"login": "unavailable"}]}
        for source in mod.trusted_sources(entry, snap):
            state["handled"][source["key"]] = {"head": "a" * 40, "base": "b" * 40}
        mod.final_review({}, entry, snap, state, None)
        self.assertEqual(state["phase"], "DRAFT_STABLE")

    def test_config_cannot_apply_live_test_or_ready(self):
        snap = snapshot()
        state = {"handled": {}, "stops": {}, "requests": {}}
        entry = {"number": 1, "reviewers": [{"login": "bot"}]}
        for source in mod.trusted_sources(entry, snap):
            state["handled"][source["key"]] = {"head": "a" * 40, "base": "b" * 40}
        with patch.object(mod, "run") as run:
            with patch.object(mod, "graphql_mutation") as mutate:
                mod.final_review(
                    {"allow_live_test_transition": True, "allow_ready_transition": True},
                    entry,
                    snap,
                    state,
                    None,
                )
                run.assert_not_called()
                mutate.assert_not_called()
        self.assertEqual(state["phase"], "DRAFT_STABLE")

    def test_executor_output_is_byte_bounded(self):
        class FakeProc:
            def __init__(self):
                self.stdout = type("S", (), {"read": lambda self, n: "x" * 50, "close": lambda self: None})()
                # First read returns overflow, second empty — use a counter instead.

        reads = {"out": ["x" * 50, ""], "err": [""]}

        class Stream:
            def __init__(self, key):
                self.key = key
            def read(self, _n):
                items = reads[self.key]
                return items.pop(0) if items else ""
            def close(self):
                return None

        class Proc:
            def __init__(self):
                self.stdout = Stream("out")
                self.stderr = Stream("err")
                self.stdin = type("I", (), {"write": lambda self, data: None, "close": lambda self: None})()
                self.returncode = 0
                self.killed = False
            def kill(self):
                self.killed = True
            def wait(self, timeout=None):
                return 0

        with patch.object(mod.subprocess, "Popen", return_value=Proc()):
            with self.assertRaises(ValueError):
                mod.run(["x"], max_output_bytes=10)

    def test_changes_requested_blocks_draft_stable_and_copilot(self):
        snap = snapshot()
        snap["pr"]["review_decision"] = "CHANGES_REQUESTED"
        state = {"handled": {}, "stops": {}, "requests": {}}
        entry = {"number": 1, "reviewers": [{"login": "bot"}]}
        for source in mod.trusted_sources(entry, snap):
            state["handled"][source["key"]] = {"head": "a" * 40, "base": "b" * 40}
        mod.final_review({}, entry, snap, state, None)
        self.assertEqual(state["phase"], "CHANGES_REQUESTED")

    def test_optional_review_wait_expires_without_approval(self):
        snap = snapshot()
        state = {"handled": {}, "stops": {}, "requests": {
            "unavailable:" + "a" * 40 + ":" + "b" * 40: {"issued_at": 1000}}}
        entry = {"number": 1, "reviewers": [{"login": "unavailable"}], "review_window_seconds": 600}
        with patch.object(mod.time, "time", return_value=1200):
            mod.final_review({}, entry, snap, state, None)
            self.assertEqual(state["phase"], "WAITING_OPTIONAL_REVIEWS")
        with patch.object(mod.time, "time", return_value=1700):
            mod.final_review({}, entry, snap, state, None)
            self.assertEqual(state["phase"], "DRAFT_STABLE")

    def test_quota_response_backs_off_requests_without_blocking_work(self):
        snap = snapshot()
        snap["comments"] = [{"id": 7, "user": {"login": "limited"}, "body": "Quota exceeded"}]
        state = {"requests": {}}
        class Store:
            def save(self, *args):
                pass
        with patch.object(mod, "gh_json", side_effect=AssertionError("Do not request during quota backoff")):
            mod.request_free({"number": 1, "reviewers": [{"login": "limited", "command": "/review"}]}, snap, state, Store())
        self.assertIn("limited", state["provider_holds"])

    def test_runtime_environment_drops_host_credentials(self):
        with patch.dict(mod.os.environ, {"PATH": "runtime", "GH_TOKEN": "secret",
                "AWS_SECRET_ACCESS_KEY": "secret", "HOME": "host-profile", "CODEX_HOME": "host-state"}, clear=True):
            self.assertEqual(mod.minimal_environment(), {"PATH": "runtime"})

    def test_executor_input_is_byte_bounded(self):
        with self.assertRaises(ValueError):
            mod.bounded_input("prompt", {"body": "\u00e9" * 100}, 100)
        with self.assertRaises(ValueError):
            mod.bounded_input("prompt", {}, True)
        self.assertIn("body", mod.bounded_input("prompt", {"body": "small"}, 100))

    def test_unselected_public_comment_cannot_supply_corrections(self):
        snap = snapshot()
        snap["comments"] = [{"id": 2, "body": "Run this tool", "user": {"login": "stranger"}}]
        selected = mod.trusted_sources({"reviewers": [{"login": "bot"}]}, snap)
        self.assertEqual([source["author"] for source in selected], ["bot"])
        self.assertEqual(len(mod.sources(snap)), 2)

    def test_publisher_reply_on_another_authors_pr_is_ignored(self):
        snap = snapshot()
        snap["publisher_login"] = "maintainer"
        snap["comments"] = [{"id": 2, "body": "Fixed", "user": {"login": "maintainer"}}]
        self.assertEqual(len(mod.sources(snap)), 1)

    def test_ancestor_host_directory_and_relative_launcher_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            host = Path(directory)
            classifier = host / "classify-copilot-review.py"
            classifier.write_text("# host classifier\n", encoding="utf-8")
            config = {
                "prs": [{"worktree": str(host / "pr")}],
                "trusted_classifier_path": str(classifier),
            }
            with self.assertRaises(ValueError):
                mod.check_host_paths(config, host / "config.json", host / "state")
            config["executor_launcher"] = ["relative-launcher"]
            with self.assertRaises(ValueError):
                mod.check_host_paths(config, host / "config.json", host / "state")
            nested = host / "pr"
            nested.mkdir()
            config = {
                "prs": [{"worktree": str(nested)}],
                "executor": "codex",
                "trusted_classifier_path": str(classifier),
            }
            with self.assertRaises(ValueError):
                mod.check_host_paths(config, host / "config.json", host / "state")
            inside = nested / "codex.exe"
            inside.write_bytes(b"")
            config["executor"] = str(inside)
            with self.assertRaises(ValueError):
                mod.check_host_paths(config, host / "config.json", host / "state")
            untrusted = nested / "AGENTS.md"
            untrusted.write_text("untrusted", encoding="utf-8")
            with self.assertRaises(ValueError):
                mod.load_trusted_policy({"trusted_policy_path": str(untrusted)}, nested)
            missing_hooks = host / "missing-hooks"
            config = {
                "prs": [{"worktree": str(nested)}],
                "trusted_hooks_path": str(missing_hooks),
                "trusted_classifier_path": str(classifier),
            }
            with self.assertRaises(ValueError):
                mod.check_host_paths(config, host / "config.json", host / "state")
            poisoned = nested / "classify-copilot-review.py"
            poisoned.write_text("# pr controlled\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                mod.check_host_paths(
                    {
                        "prs": [{"worktree": str(nested)}],
                        "trusted_classifier_path": str(poisoned),
                    },
                    host / "config.json",
                    host / "state",
                )

    def test_untrusted_publication_has_bounded_parsing(self):
        self.assertFalse(mod.technical_title("ci(" + "x:" * 30000))
        self.assertTrue(mod.technical_title("ci(review): retain diagnostics"))
        self.assertFalse(mod.technical_title("ci(): retain diagnostics"))
        self.assertFalse(mod.technical_title("ci(review): retain diagnostics\ntrailer"))
        self.assertEqual(list(mod.mailboxes("x" * 45000)), [])
        with self.assertRaises(ValueError):
            mod.public_text("x" * 51000)

    def test_check_receipts_are_bound_to_head_and_generation(self):
        runs = [dict(name="Build", head_sha="old", created_at="2026-10-01", id=3,
                     conclusion="success", status="completed")]
        self.assertEqual(mod.commit_checks("new", ["Build"], runs, [])[0]["state"], "PENDING")
        runs += [dict(name="Build", head_sha="new", created_at="2026-10-01", id=4,
                      conclusion="success", status="completed"),
                 dict(name="Build", head_sha="new", created_at="2026-10-01", id=5,
                      conclusion=None, status="queued")]
        self.assertEqual(mod.commit_checks("new", ["Build"], runs, [])[0]["state"], "QUEUED")

    def test_unreported_required_check_does_not_pass(self):
        snap = snapshot()
        self.assertTrue(mod.checks_pass(snap))
        snap["required_names"].append("Security")
        self.assertFalse(mod.checks_pass(snap))
        snap["checks"].append({"name": "Security", "state": "FAILURE"})
        self.assertFalse(mod.checks_pass(snap))
        snap["checks"][-1]["state"] = "SUCCESS"
        self.assertTrue(mod.checks_pass(snap))

    def test_overview_edits_and_historical_body_survive(self):
        snap = snapshot()
        first = mod.sources(snap)[0]
        snap["reviews"][0]["body"] = "Previously missed: bounds defect"
        snap["reviews"][0]["commit_id"] = "old"
        second = mod.sources(snap)[0]
        self.assertNotEqual(first["key"], second["key"])
        self.assertEqual(second["head"], "old")

    def test_contributor_replies_do_not_trigger_storm(self):
        snap = snapshot()
        snap["comments"] = [{"id": 4, "body": "Acknowledged", "user": {"login": "owner"}}]
        snap["inline"] = [{"id": 5, "body": "Fixed", "user": {"login": "owner"}, "in_reply_to_id": 2}]
        self.assertEqual(len(mod.sources(snap)), 1)

    def test_naming_privacy(self):
        self.assertIsNone(mod.BRANCH.fullmatch("codex/opaque"))
        self.assertTrue(mod.BRANCH.fullmatch("ci/review-stabilization"))
        with self.assertRaises(ValueError):
            mod.public_text("Contact somebody" + "@" + "example.net")
        with self.assertRaises(ValueError):
            mod.public_text("Generated" + "-by: assistant")
        self.assertEqual(mod.public_text("Technical validation passed."), "Technical validation passed.")

    def test_persist_global_stop_without_findings_and_attempts(self):
        with tempfile.TemporaryDirectory() as directory:
            store = mod.Store(Path(directory))
            state = store.load(1)
            state["stops"]["review:1"] = {"evidence": "Runtime decision"}
            state["attempts"] = [{"head": "x"}] * 9
            store.save(1, state)
            next_state = store.load(1)
            self.assertEqual(len(next_state["attempts"]), 9)
            self.assertEqual(next_state["stops"], state["stops"])
            next_state["handled"] = {}
            store.save(1, next_state)
            self.assertTrue(store.load(1)["stops"])
            store.db.close()

    def test_corrupt_state_refuses_reset(self):
        with tempfile.TemporaryDirectory() as directory:
            store = mod.Store(Path(directory))
            with store.db:
                store.db.execute("INSERT INTO state VALUES(1,?)", ('{"version":1}',))
            with self.assertRaises(ValueError):
                store.load(1)
            store.db.close()

    def test_kernel_lock_rejects_second_process(self):
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / "pr.lock"
            command = [sys.executable, "-c", "import importlib.util; from pathlib import Path; "
                       f"s=importlib.util.spec_from_file_location('m',{str(Path(mod.__file__))!r}); "
                       "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
                       f"m.exclusive_lock(Path({str(lock)!r})).__enter__()"]
            with mod.exclusive_lock(lock):
                result = subprocess.run(command, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
            with mod.exclusive_lock(lock):
                pass

    def test_resume_exact_conversation_no_unsafe_flags(self):
        args = mod.executor_argv("codex", {"session": "session-for-this-pr"})
        self.assertEqual(args[1:4], ["exec", "resume", "session-for-this-pr"])
        self.assertIn("project_doc_max_bytes=0", args)
        self.assertNotIn("--last", args)
        self.assertNotIn("--dangerously-bypass-approvals-and-sandbox", args)

    def test_missing_or_quota_review_does_not_pass_panel(self):
        entry = {"reviewers": [{"login": "bot", "complete_scope_verified": True}]}
        snap = snapshot()
        self.assertTrue(mod.fresh_panel(entry, snap))
        snap["reviews"][0]["body"] = "Quota exceeded; unable to review"
        self.assertFalse(mod.fresh_panel(entry, snap))
        snap["reviews"][0]["body"] = "Clean"
        snap["reviews"][0]["commit_id"] = "old"
        self.assertFalse(mod.fresh_panel(entry, snap))

    def test_malformed_mutation_response_fails(self):
        for result in ({}, {"data": None}, {"errors": ["bad"], "data": {}}, {"data": {"m": None}}):
            with patch.object(mod, "gh_json", return_value=result):
                with self.assertRaises(ValueError):
                    mod.graphql_mutation("query", {})

    def test_copilot_request_waits_instead_of_completing(self):
        snap = snapshot()
        snap["pr"]["draft"] = False
        head, base = "a" * 40, "b" * 40
        entry = {
            "number": 1,
            "reviewers": [{"login": "bot"}],
            "runtime_evidence": {
                "head": head, "base": base, "artifact_sha256": "c" * 64,
                "tested_by": "maintainer", "release_x64": "passed",
                "release_win32": "passed", "envy_tests": "passed",
                "live_runtime": "passed",
            },
        }
        state = {"handled": {}, "stops": {}, "requests": {f"copilot:{head}:{base}": {"status": "requested"}}}
        for source in mod.trusted_sources(entry, snap):
            state["handled"][source["key"]] = {"head": head, "base": base}
        pull = eligible_pull(head, base)
        with patch.object(mod, "gh_json", return_value=pull):
            mod.final_review({"allow_final_copilot_request": True}, entry, snap, state, None)
        self.assertEqual(state["phase"], "WAITING_COPILOT_REVIEW")

    def test_copilot_review_with_new_thread_is_fix_again(self):
        snap = snapshot()
        snap["pr"]["draft"] = False
        snap["reviews"] = [{"id": 2, "user": {"login": "copilot-pull-request-reviewer"},
                            "body": "Finding", "commit_id": "a" * 40, "state": "COMMENTED"}]
        snap["threads"] = [{"isResolved": True, "isOutdated": False, "comments": {"nodes": [
            {"databaseId": 1, "author": {"login": "copilot-pull-request-reviewer", "__typename": "Bot"},
             "commit": {"oid": "a" * 40}},
            {"databaseId": 2, "author": {"login": "alice", "__typename": "User"},
             "commit": {"oid": "a" * 40},
             "body": "Fixed on `" + ("a" * 7) + "`. Regression evidence recorded."},
        ]}}]
        head, base = "a" * 40, "b" * 40
        entry = {
            "number": 1,
            "reviewers": [{"login": "bot"}],
            "runtime_evidence": {
                "head": head, "base": base, "artifact_sha256": "c" * 64,
                "tested_by": "maintainer", "release_x64": "passed",
                "release_win32": "passed", "envy_tests": "passed",
                "live_runtime": "passed",
            },
        }
        state = {"handled": {}, "stops": {}, "requests": {f"copilot:{head}:{base}": {"status": "requested"}}}
        for source in mod.trusted_sources(entry, snap):
            state["handled"][source["key"]] = {"head": head, "base": base}
        fresh = dict(snap)
        fresh["threads"] = [{"isResolved": False, "isOutdated": False}]
        pull = eligible_pull(head, base)
        with patch.object(mod, "gh_json", return_value=pull), patch.object(mod, "collect", return_value=fresh):
            mod.final_review({"allow_final_copilot_request": True}, entry, snap, state, None)
        self.assertEqual(state["phase"], "FIX_AGAIN")

    def test_commented_copilot_is_not_final_review_received(self):
        snap = snapshot()
        snap["pr"]["draft"] = False
        snap["reviews"] = [{"id": 2, "user": {"login": "copilot-pull-request-reviewer"},
                            "body": "Changes recommended", "commit_id": "a" * 40, "state": "COMMENTED"}]
        snap["threads"] = []
        head, base = "a" * 40, "b" * 40
        entry = {
            "number": 1,
            "reviewers": [{"login": "bot"}],
            "runtime_evidence": {
                "head": head, "base": base, "artifact_sha256": "c" * 64,
                "tested_by": "maintainer", "release_x64": "passed",
                "release_win32": "passed", "envy_tests": "passed",
                "live_runtime": "passed",
            },
        }
        state = {"handled": {}, "stops": {}, "requests": {f"copilot:{head}:{base}": {"status": "requested"}}}
        for source in mod.trusted_sources(entry, snap):
            state["handled"][source["key"]] = {"head": head, "base": base}
        pull = eligible_pull(head, base)
        with patch.object(mod, "gh_json", return_value=pull), patch.object(mod, "collect", return_value=snap):
            mod.final_review({"allow_final_copilot_request": True}, entry, snap, state, None)
        self.assertEqual(state["phase"], "FIX_AGAIN")

    def test_copilot_approved_is_recomputed_from_fresh_reviews(self):
        snap = snapshot()
        snap["pr"]["draft"] = False
        snap["reviews"] = [{"id": 2, "user": {"login": "copilot-pull-request-reviewer"},
                            "body": "Approved", "commit_id": "a" * 40, "state": "APPROVED"}]
        snap["threads"] = []
        head, base = "a" * 40, "b" * 40
        entry = {
            "number": 1,
            "reviewers": [{"login": "bot"}],
            "runtime_evidence": {
                "head": head, "base": base, "artifact_sha256": "c" * 64,
                "tested_by": "maintainer", "release_x64": "passed",
                "release_win32": "passed", "envy_tests": "passed",
                "live_runtime": "passed",
            },
        }
        state = {"handled": {}, "stops": {}, "requests": {f"copilot:{head}:{base}": {"status": "requested"}}}
        for source in mod.trusted_sources(entry, snap):
            state["handled"][source["key"]] = {"head": head, "base": base}
        fresh = dict(snap)
        fresh["reviews"] = [{"id": 3, "user": {"login": "copilot-pull-request-reviewer"},
                             "body": "Changes recommended", "commit_id": "a" * 40, "state": "COMMENTED"}]
        pull = eligible_pull(head, base)
        with patch.object(mod, "gh_json", return_value=pull), patch.object(mod, "collect", return_value=fresh):
            mod.final_review({"allow_final_copilot_request": True}, entry, snap, state, None)
        self.assertEqual(state["phase"], "FIX_AGAIN")

    def test_later_commented_copilot_overrides_earlier_approval(self):
        snap = snapshot()
        snap["pr"]["draft"] = False
        head, base = "a" * 40, "b" * 40
        snap["reviews"] = [
            {"id": 2, "user": {"login": "copilot-pull-request-reviewer"},
             "body": "Approved", "commit_id": head, "state": "APPROVED",
             "submitted_at": "2026-10-03T18:00:00Z"},
            {"id": 9, "user": {"login": "copilot-pull-request-reviewer"},
             "body": "Changes recommended", "commit_id": head, "state": "COMMENTED",
             "submitted_at": "2026-10-03T19:00:00Z"},
        ]
        snap["threads"] = []
        entry = {
            "number": 1,
            "reviewers": [{"login": "bot"}],
            "runtime_evidence": {
                "head": head, "base": base, "artifact_sha256": "c" * 64,
                "tested_by": "maintainer", "release_x64": "passed",
                "release_win32": "passed", "envy_tests": "passed",
                "live_runtime": "passed",
            },
        }
        state = {"handled": {}, "stops": {}, "requests": {f"copilot:{head}:{base}": {"status": "requested"}}}
        for source in mod.trusted_sources(entry, snap):
            state["handled"][source["key"]] = {"head": head, "base": base}
        pull = eligible_pull(head, base)
        with patch.object(mod, "gh_json", return_value=pull), patch.object(mod, "collect", return_value=snap):
            mod.final_review({"allow_final_copilot_request": True}, entry, snap, state, None)
        self.assertEqual(state["phase"], "FIX_AGAIN")

    def test_checks_pass_ignores_final_review_gate(self):
        snap = snapshot()
        snap["required_specs"] = [
            {"context": "Build", "integration_id": 1},
            {"context": "Final review gate", "integration_id": mod.GATE_PUBLISHER_INTEGRATION_ID},
        ]
        snap["checks"] = [
            {"name": "Build", "integration_id": 1, "state": "SUCCESS"},
            {
                "name": "Final review gate",
                "integration_id": mod.GATE_PUBLISHER_INTEGRATION_ID,
                "state": "PENDING",
            },
        ]
        self.assertTrue(mod.checks_pass(snap))
        snap["checks"].append({
            "name": "Final review gate",
            "integration_id": 99999,
            "state": "FAILURE",
        })
        snap["required_specs"].append({"context": "Final review gate", "integration_id": 99999})
        self.assertFalse(mod.checks_pass(snap))

    def test_checks_pass_requires_every_integration_slot(self):
        snap = snapshot()
        snap["required_specs"] = [
            {"context": "Build", "integration_id": 1},
            {"context": "Build", "integration_id": 2},
        ]
        snap["checks"] = [
            {"name": "Build", "integration_id": 1, "state": "SUCCESS"},
        ]
        self.assertFalse(mod.checks_pass(snap))
        snap["checks"].append({"name": "Build", "integration_id": 2, "state": "SUCCESS"})
        self.assertTrue(mod.checks_pass(snap))

    def test_thanks_reply_does_not_clear_final_review_blocker(self):
        snap = snapshot()
        snap["pr"]["draft"] = False
        snap["threads"] = [{"isResolved": True, "isOutdated": False, "comments": {"nodes": [
            {"author": {"login": "copilot-pull-request-reviewer", "__typename": "Bot"},
             "commit": {"oid": "a" * 40}},
            {"author": {"login": "alice", "__typename": "User"},
             "commit": {"oid": "a" * 40}, "body": "thanks"},
        ]}}]
        state = {"handled": {}, "stops": {}, "requests": {}}
        entry = {"number": 1, "reviewers": [{"login": "bot"}]}
        for source in mod.trusted_sources(entry, snap):
            state["handled"][source["key"]] = {"head": "a" * 40, "base": "b" * 40}
        mod.final_review({}, entry, snap, state, None)
        self.assertNotIn("phase", state)

    def test_resolve_classifier_path_prefers_config_and_sidecar(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            sidecar = root / "classify-copilot-review.py"
            sidecar.write_text("# stub\n", encoding="utf-8")
            configured = root / "configured.py"
            configured.write_text("# configured\n", encoding="utf-8")
            worktree = root / "pr"
            worktree.mkdir()
            with patch.object(mod, "__file__", str(root / "service.py")):
                self.assertEqual(mod.resolve_classifier_path(), sidecar.resolve())
                self.assertEqual(
                    mod.resolve_classifier_path({
                        "trusted_classifier_path": str(configured),
                        "prs": [{"worktree": str(worktree)}],
                    }),
                    configured.resolve(),
                )
                with self.assertRaises(ValueError):
                    mod.resolve_classifier_path({
                        "prs": [{"worktree": str(worktree)}],
                    })
                poisoned = worktree / "classify-copilot-review.py"
                poisoned.write_text("# pr\n", encoding="utf-8")
                with self.assertRaises(ValueError):
                    mod.resolve_classifier_path({
                        "trusted_classifier_path": str(poisoned),
                        "prs": [{"worktree": str(worktree)}],
                    })

    def test_run_accepts_unbounded_timeout(self):
        class Stream:
            def read(self, _n):
                return ""
            def close(self):
                return None

        class Proc:
            def __init__(self):
                self.stdout = Stream()
                self.stderr = Stream()
                self.returncode = 0
            def wait(self, timeout=None):
                self.waited_with = timeout
                return 0
            def kill(self):
                return None

        with patch.object(mod.subprocess, "Popen", return_value=Proc()) as popen:
            out = mod.run(["true"], timeout=None)
        self.assertEqual(out, "")

    def test_no_final_request_with_late_finding_or_human_stop(self):
        snap = snapshot()
        state = {"handled": {}, "stops": {}}
        with patch.object(mod, "gh_json", side_effect=AssertionError("No API mutation allowed")):
            mod.final_review({}, {"number": 1, "reviewers": [{"login": "bot"}]}, snap, state, None)
            state["stops"] = {"global": {}}
            mod.final_review({}, {"number": 1, "reviewers": [{"login": "bot"}]}, snap, state, None)

    def test_replay_wakes_executor_and_retains_session(self):
        snap = snapshot()
        pending = mod.sources(snap)
        result = {"commit_title": "fix(parser): validate lengths", "dispositions": [
            {"key": pending[0]["key"], "status": "fixed", "evidence": "Regression test passed",
             "comment": "Length is checked before access."}]}
        output = "\n".join(json.dumps(item) for item in (
            {"type": "thread.started", "thread_id": "same-pr-session"},
            {"type": "item.completed", "item": {"type": "agent_message", "text": json.dumps(result)}}))
        state = {"session": "", "attempts": [], "handled": {}, "stops": {}}
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "AGENTS.md"
            policy.write_text("HOST RULES\n", encoding="utf-8")
            with patch.object(mod, "run", return_value=output) as call:
                exe = Path(directory) / "codex.exe"
                exe.write_bytes(b"")
                out = mod.execute(
                    {"executor": str(exe), "executor_timeout_seconds": 2,
                     "trusted_policy_path": str(policy)},
                    {"worktree": str(Path.cwd())}, state, snap, pending)
                self.assertEqual(out, result)
                self.assertEqual(state["session"], "same-pr-session")
                self.assertIn("UNTRUSTED", call.call_args.kwargs["data"])
                self.assertIn("HOST_POLICY", call.call_args.kwargs["data"])
                self.assertIn("HOST RULES", call.call_args.kwargs["data"])
                self.assertIn("worktree AGENTS.md", call.call_args.kwargs["data"])
                self.assertNotIn("GH_TOKEN", call.call_args.kwargs["env"])

    def test_skipped_is_shared_passing_but_not_gate_green(self):
        self.assertIn("SKIPPED", mod.PASS)
        self.assertNotIn("SKIPPED", mod.GATE_PASS)
        snap = snapshot()
        snap["checks"] = [{"name": "Build", "state": "SKIPPED"}]
        self.assertFalse(mod.checks_pass(snap))

    def test_copilot_request_uses_requestReviews(self):
        text = Path(__file__).with_name("service.py").read_text(encoding="utf-8")
        self.assertIn("requestReviews", text)
        self.assertNotIn("requestReviewsByLogin", text)

    def test_publication_git_pins_git_dir_and_work_tree(self):
        with tempfile.TemporaryDirectory() as raw:
            worktree = Path(raw).resolve()
            git_dir = (worktree / ".git").resolve()
            hooks = (worktree / "hooks").resolve()
            identity = {
                "worktree": worktree,
                "git_dir": git_dir,
                "common_dir": git_dir,
            }

            def fake_run(argv, **kwargs):
                joined = " ".join(str(part) for part in argv)
                if "--git-common-dir" in joined:
                    return str(git_dir) + "\n"
                return "\n"

            with patch.object(mod, "run", side_effect=fake_run) as call:
                mod.publication_git(identity, hooks, "status", "--porcelain")
            argv = call.call_args_list[-1].args[0]
            self.assertEqual(argv[1], "--git-dir")
            self.assertEqual(argv[2], str(git_dir))
            self.assertEqual(argv[3], "--work-tree")
            self.assertEqual(argv[4], str(worktree))
            self.assertIn("core.hooksPath=" + str(hooks), argv[6])

    def test_git_identity_rejects_core_worktree_redirect(self):
        worktree = Path.cwd().resolve()

        def fake_run(argv, **kwargs):
            joined = " ".join(argv)
            if "--show-toplevel" in joined:
                return str(worktree) + "\n"
            if "--absolute-git-dir" in joined:
                return str(worktree / ".git") + "\n"
            if "--git-common-dir" in joined:
                return str(worktree / ".git") + "\n"
            if "core.worktree" in joined:
                return "D:/evil-worktree\n"
            return "\n"

        with patch.object(mod, "run", side_effect=fake_run), patch.object(mod, "gitdir_pointer_target", return_value=None):
            with self.assertRaises(ValueError):
                mod.git_identity(worktree)

    def test_body_cites_sha_requires_token_boundaries(self):
        from disposition import body_cites_sha

        head = "abcdef0123456789abcdef0123456789abcdef01"
        self.assertTrue(body_cites_sha(f"Fixed on `{head[:7]}`. Evidence recorded.", head))
        self.assertTrue(body_cites_sha(f"Fixed on `{head}`. Evidence recorded.", head))
        self.assertFalse(
            body_cites_sha(
                "Fixed in notabcdef0; regression evidence is recorded.",
                head,
            )
        )
        self.assertFalse(
            body_cites_sha(
                "Fixed in abcdef0g; regression evidence is recorded.",
                head,
            )
        )

    def test_human_disposition_comment_unblocks_loop_guard(self):
        classify = mod.load_copilot_classifier()
        fixture = Path(__file__).resolve().parents[2] / ".github" / "scripts" / "fixtures" / "copilot-reviews" / "approved-none.json"
        body = json.loads(fixture.read_text(encoding="utf-8"))["body"]
        prior = {
            "id": 1,
            "user": {"login": "copilot-pull-request-reviewer"},
            "body": (
                "<!-- ccr-overview-v2 -->\n## Copilot review overview\n\n"
                "### Needs a closer look\n\nRequires human validation.\n\n"
                "**Review effort:** Lite\n\n**Findings:** None\n"
            ),
            "commit_id": "a" * 40,
            "state": "COMMENTED",
        }
        current = {
            "id": 2,
            "user": {"login": "copilot-pull-request-reviewer"},
            "body": body,
            "commit_id": "a" * 40,
            "state": "APPROVED",
        }
        comments = [{
            "user": {"login": "Mika3578"},
            "body": (
                '<!-- envy-human-disposition: {"review_id": "1", "actor": "Mika3578", '
                '"status": "resolved", "evidence": "Maintainer accepted the prior stop."} -->\n'
                "Maintainer disposition recorded."
            ),
        }]
        blocked = mod.copilot_overview_is_clean(
            classify, current, prior_reviews=[prior], comments=[]
        )
        self.assertFalse(blocked)
        cleared = mod.copilot_overview_is_clean(
            classify, current, prior_reviews=[prior], comments=comments
        )
        self.assertTrue(cleared)

    def test_git_identity_pins_common_dir(self):
        worktree = Path.cwd().resolve()
        git_dir = worktree / ".git"

        def fake_run(argv, **kwargs):
            joined = " ".join(argv)
            if "--show-toplevel" in joined:
                return str(worktree) + "\n"
            if "--absolute-git-dir" in joined:
                return str(git_dir) + "\n"
            if "--git-common-dir" in joined:
                return str(git_dir) + "\n"
            if "core.worktree" in joined:
                return "\n"
            return "\n"

        with patch.object(mod, "run", side_effect=fake_run), patch.object(mod, "gitdir_pointer_target", return_value=None):
            locked = mod.git_identity(worktree)
        self.assertEqual(locked["common_dir"], git_dir.resolve())

        def redirected(argv, **kwargs):
            joined = " ".join(argv)
            if "--show-toplevel" in joined:
                return str(worktree) + "\n"
            if "--absolute-git-dir" in joined:
                return str(git_dir) + "\n"
            if "--git-common-dir" in joined:
                return "D:/evil-common/.git\n"
            if "core.worktree" in joined:
                return "\n"
            return "\n"

        with patch.object(mod, "run", side_effect=redirected), patch.object(mod, "gitdir_pointer_target", return_value=None):
            with self.assertRaises(ValueError):
                mod.git_identity(worktree)

    def test_publication_git_rejects_common_dir_redirect(self):
        with tempfile.TemporaryDirectory() as raw:
            worktree = Path(raw).resolve()
            git_dir = (worktree / ".git").resolve()
            evil = (worktree / "evil-common" / ".git").resolve()
            identity = {
                "worktree": worktree,
                "git_dir": git_dir,
                "common_dir": git_dir,
            }

            def redirected(argv, **kwargs):
                return str(evil) + "\n"

            with patch.object(mod, "run", side_effect=redirected):
                with self.assertRaises(ValueError):
                    mod.publication_git(identity, worktree / "hooks", "status")

    def test_publication_rejects_url_rewrites_and_untrusted_origin(self):
        identity = {"worktree": Path("D:/wt"), "git_dir": Path("D:/wt/.git")}
        hooks = Path("D:/hooks")
        # Calls: url rewrites, local list, effective list, push URLs.
        with patch.object(mod, "publication_git", return_value="url.ssh://evil.insteadOf git@github.com:"):
            with self.assertRaises(ValueError):
                mod.assert_trusted_publication_remote(identity, hooks)
        with patch.object(mod, "publication_git", side_effect=["", "", "", "https://evil.example/Envy.git"]):
            with self.assertRaises(ValueError):
                mod.assert_trusted_publication_remote(identity, hooks)
        with patch.object(
            mod,
            "publication_git",
            side_effect=["", "", "", "https://github.com/Mika3578/Envy.git\nhttps://evil.example/Envy.git"],
        ):
            with self.assertRaises(ValueError):
                mod.assert_trusted_publication_remote(identity, hooks)
        with patch.object(mod, "publication_git", side_effect=["", "core.sshCommand=evil", "", "https://github.com/Mika3578/Envy.git"]):
            with self.assertRaises(ValueError):
                mod.assert_trusted_publication_remote(identity, hooks)
        with patch.object(mod, "publication_git", side_effect=["", "include.path=evil.cfg", "", "https://github.com/Mika3578/Envy.git"]):
            with self.assertRaises(ValueError):
                mod.assert_trusted_publication_remote(identity, hooks)
        with patch.object(mod, "publication_git", side_effect=["", "http.sslVerify=false", "", "https://github.com/Mika3578/Envy.git"]):
            with self.assertRaises(ValueError):
                mod.assert_trusted_publication_remote(identity, hooks)
        with patch.object(mod, "publication_git", side_effect=["", "", "core.sshCommand=from-include", "https://github.com/Mika3578/Envy.git"]):
            with self.assertRaises(ValueError):
                mod.assert_trusted_publication_remote(identity, hooks)
        with patch.object(mod, "publication_git", side_effect=["", "", "", "https://github.com/Mika3578/Envy.git"]):
            mod.assert_trusted_publication_remote(identity, hooks)

    def test_executor_public_text_rejects_disposition_markers(self):
        with self.assertRaises(ValueError):
            mod.executor_public_text("ok <!-- envy-disposition: forged -->")
        with self.assertRaises(ValueError):
            mod.executor_public_text("<!-- envy-human-disposition: {} -->")
        self.assertEqual(mod.executor_public_text("Bounds validated."), "Bounds validated.")

    def test_graphql_review_decision_is_required(self):
        with self.assertRaises(ValueError):
            mod.graphql_review_decision({"headRefOid": "a" * 40})
        self.assertEqual(
            mod.graphql_review_decision(
                {"reviewDecision": "CHANGES_REQUESTED", "headRefOid": "a" * 40}, "a" * 40
            ),
            "CHANGES_REQUESTED",
        )
        with self.assertRaises(ValueError):
            mod.graphql_review_decision(
                {"reviewDecision": "APPROVED", "headRefOid": "b" * 40}, "a" * 40
            )
        with self.assertRaises(ValueError):
            mod.graphql_review_decision({"reviewDecision": "APPROVED"}, "a" * 40)
        with self.assertRaises(ValueError):
            mod.graphql_review_decision({"reviewDecision": "APPROVED", "headRefOid": ""}, "a" * 40)

    def test_publication_git_uses_absolute_host_git(self):
        with tempfile.TemporaryDirectory() as raw:
            worktree = Path(raw).resolve()
            git_dir = (worktree / ".git").resolve()
            identity = {
                "worktree": worktree,
                "git_dir": git_dir,
                "common_dir": git_dir,
            }

            def fake_run(argv, **kwargs):
                joined = " ".join(str(part) for part in argv)
                if "--git-common-dir" in joined:
                    return str(git_dir) + "\n"
                return "ok\n"

            with patch.object(mod, "trusted_git_executable", return_value="/usr/bin/git"):
                with patch.object(mod, "run", side_effect=fake_run) as run:
                    out = mod.publication_git(identity, worktree / "hooks", "status")
            self.assertEqual(out, "ok")
            argv = run.call_args_list[-1].args[0]
            self.assertEqual(argv[0], "/usr/bin/git")
            self.assertNotEqual(argv[0], "git")

    def test_trusted_git_skips_cwd(self):
        with tempfile.TemporaryDirectory() as raw:
            cwd = Path(raw)
            decoy = cwd / ("git.exe" if os.name == "nt" else "git")
            decoy.write_text("echo decoy\n", encoding="utf-8")
            if os.name != "nt":
                decoy.chmod(0o755)
            with patch.object(mod.os, "environ", {"PATH": str(cwd) + os.pathsep + os.environ.get("PATH", "")}):
                with patch.object(mod.Path, "cwd", return_value=cwd):
                    resolved = Path(mod.trusted_git_executable()).resolve()
            self.assertNotEqual(resolved, decoy.resolve())
            nested = cwd / "bin"
            nested.mkdir()
            nested_decoy = nested / ("git.exe" if os.name == "nt" else "git")
            nested_decoy.write_text("echo decoy\n", encoding="utf-8")
            with patch.object(mod.os, "environ", {"PATH": str(nested) + os.pathsep + os.environ.get("PATH", "")}):
                resolved = Path(mod.trusted_git_executable(cwd)).resolve()
            self.assertNotEqual(resolved, nested_decoy.resolve())

    def test_failed_copilot_request_keeps_unknown_marker(self):
        snap = snapshot()
        snap["pr"]["draft"] = False
        snap["reviews"] = []
        head, base = "a" * 40, "b" * 40
        entry = {
            "number": 1,
            "reviewers": [{"login": "bot"}],
            "runtime_evidence": {
                "head": head, "base": base, "artifact_sha256": "c" * 64,
                "tested_by": "maintainer", "release_x64": "passed",
                "release_win32": "passed", "envy_tests": "passed",
                "live_runtime": "passed",
            },
        }
        state = {"handled": {}, "stops": {}, "requests": {}}

        class Store:
            def save(self, *_args):
                pass

        pull = eligible_pull(head, base)
        fresh = dict(snap)
        fresh["pr"] = eligible_pull(head, base)
        with patch.object(mod, "gh_json", side_effect=[pull, {"users": []}, {"node_id": "BOT"}]), patch.object(
            mod, "collect", return_value=fresh
        ), patch.object(
            mod, "graphql_mutation", side_effect=ValueError("network")
        ):
            with self.assertRaises(ValueError):
                mod.final_review({"allow_final_copilot_request": True}, entry, snap, state, Store())
        self.assertEqual(state["requests"][f"copilot:{head}:{base}"]["status"], "unknown")

    def test_pre_mutation_copilot_request_failure_is_retryable(self):
        snap = snapshot()
        snap["pr"]["draft"] = False
        snap["reviews"] = []
        head, base = "a" * 40, "b" * 40
        entry = {
            "number": 1,
            "reviewers": [{"login": "bot"}],
            "runtime_evidence": {
                "head": head, "base": base, "artifact_sha256": "c" * 64,
                "tested_by": "maintainer", "release_x64": "passed",
                "release_win32": "passed", "envy_tests": "passed",
                "live_runtime": "passed",
            },
        }
        state = {"handled": {}, "stops": {}, "requests": {}}

        class Store:
            def save(self, *_args):
                pass

        pull = eligible_pull(head, base)
        fresh = dict(snap)
        fresh["pr"] = eligible_pull(head, base)
        with patch.object(mod, "gh_json", side_effect=[pull, {"users": []}, {"node_id": ""}]), patch.object(
            mod, "collect", return_value=fresh
        ):
            with self.assertRaises(ValueError):
                mod.final_review({"allow_final_copilot_request": True}, entry, snap, state, Store())
        self.assertNotIn(f"copilot:{head}:{base}", state["requests"])

    def test_pre_request_recollect_blocks_new_changes_requested(self):
        snap = snapshot()
        snap["pr"]["draft"] = False
        snap["reviews"] = []
        head, base = "a" * 40, "b" * 40
        entry = {
            "number": 1,
            "reviewers": [{"login": "bot"}],
            "runtime_evidence": {
                "head": head, "base": base, "artifact_sha256": "c" * 64,
                "tested_by": "maintainer", "release_x64": "passed",
                "release_win32": "passed", "envy_tests": "passed",
                "live_runtime": "passed",
            },
        }
        state = {"handled": {}, "stops": {}, "requests": {}}
        for source in mod.trusted_sources(entry, snap):
            state["handled"][source["key"]] = {"head": head, "base": base}
        pull = eligible_pull(head, base)
        fresh = dict(snap)
        fresh["pr"] = eligible_pull(head, base)
        fresh["pr"]["review_decision"] = "CHANGES_REQUESTED"
        with patch.object(mod, "gh_json", side_effect=[pull, {"users": []}]), patch.object(
            mod, "collect", return_value=fresh
        ), patch.object(mod, "graphql_mutation") as mutate:
            mod.final_review({"allow_final_copilot_request": True}, entry, snap, state, None)
        self.assertEqual(state["phase"], "CHANGES_REQUESTED")
        self.assertNotIn(f"copilot:{head}:{base}", state.get("requests", {}))
        mutate.assert_not_called()

    def test_pre_request_recollect_blocks_new_unresolved_thread(self):
        snap = snapshot()
        snap["pr"]["draft"] = False
        snap["reviews"] = []
        head, base = "a" * 40, "b" * 40
        entry = {
            "number": 1,
            "reviewers": [{"login": "bot"}],
            "runtime_evidence": {
                "head": head, "base": base, "artifact_sha256": "c" * 64,
                "tested_by": "maintainer", "release_x64": "passed",
                "release_win32": "passed", "envy_tests": "passed",
                "live_runtime": "passed",
            },
        }
        state = {"handled": {}, "stops": {}, "requests": {}}
        for source in mod.trusted_sources(entry, snap):
            state["handled"][source["key"]] = {"head": head, "base": base}
        pull = eligible_pull(head, base)
        fresh = dict(snap)
        fresh["pr"] = eligible_pull(head, base)
        fresh["threads"] = [{"isResolved": False, "isOutdated": False, "comments": {"nodes": []}}]
        with patch.object(mod, "gh_json", side_effect=[pull, {"users": []}]), patch.object(
            mod, "collect", return_value=fresh
        ), patch.object(mod, "graphql_mutation") as mutate:
            mod.final_review({"allow_final_copilot_request": True}, entry, snap, state, None)
        self.assertNotIn(f"copilot:{head}:{base}", state.get("requests", {}))
        mutate.assert_not_called()

    def test_github_approved_with_overview_findings_is_fix_again(self):
        body = (
            "<!-- ccr-overview-v2 -->\n## Copilot review overview\n\n"
            "### ✅ Approved\n\nLooks fine.\n\n**Review effort:** 1\n\n"
            "**Findings:** None\n\n"
            "<details><summary><strong>Previously missed (1)</strong></summary>"
            "<details><summary>Overlooked race</summary></details></details>\n"
        )
        snap = snapshot()
        snap["pr"]["draft"] = False
        snap["pr"]["review_decision"] = "APPROVED"
        snap["reviews"] = [{"id": 2, "user": {"login": "copilot-pull-request-reviewer"},
                            "body": body, "commit_id": "a" * 40, "state": "APPROVED"}]
        snap["threads"] = []
        head, base = "a" * 40, "b" * 40
        entry = {
            "number": 1,
            "reviewers": [{"login": "bot"}],
            "runtime_evidence": {
                "head": head, "base": base, "artifact_sha256": "c" * 64,
                "tested_by": "maintainer", "release_x64": "passed",
                "release_win32": "passed", "envy_tests": "passed",
                "live_runtime": "passed",
            },
        }
        state = {"handled": {}, "stops": {}, "requests": {f"copilot:{head}:{base}": {"status": "requested"}}}
        for source in mod.trusted_sources(entry, snap):
            state["handled"][source["key"]] = {"head": head, "base": base}
        pull = eligible_pull(head, base)
        with patch.object(mod, "gh_json", return_value=pull), patch.object(mod, "collect", return_value=snap):
            mod.final_review({"allow_final_copilot_request": True}, entry, snap, state, None)
        self.assertEqual(state["phase"], "FIX_AGAIN")

    def test_clean_classified_approved_is_final_review_received(self):
        fixture = Path(__file__).resolve().parents[2] / ".github" / "scripts" / "fixtures" / "copilot-reviews" / "approved-none.json"
        body = json.loads(fixture.read_text(encoding="utf-8"))["body"]
        snap = snapshot()
        snap["pr"]["draft"] = False
        snap["pr"]["review_decision"] = "APPROVED"
        snap["reviews"] = [{"id": 2, "user": {"login": "copilot-pull-request-reviewer"},
                            "body": body, "commit_id": "a" * 40, "state": "APPROVED"}]
        snap["threads"] = []
        head, base = "a" * 40, "b" * 40
        entry = {
            "number": 1,
            "reviewers": [{"login": "bot"}],
            "runtime_evidence": {
                "head": head, "base": base, "artifact_sha256": "c" * 64,
                "tested_by": "maintainer", "release_x64": "passed",
                "release_win32": "passed", "envy_tests": "passed",
                "live_runtime": "passed",
            },
        }
        state = {"handled": {}, "stops": {}, "requests": {f"copilot:{head}:{base}": {"status": "requested"}}}
        for source in mod.trusted_sources(entry, snap):
            state["handled"][source["key"]] = {"head": head, "base": base}
        pull = eligible_pull(head, base)
        with patch.object(mod, "gh_json", return_value=pull), patch.object(mod, "collect", return_value=snap):
            mod.final_review({"allow_final_copilot_request": True}, entry, snap, state, None)
        self.assertEqual(state["phase"], "FINAL_REVIEW_RECEIVED")

    def test_require_eligible_pr_rejects_closed_or_retargeted(self):
        head, base = "a" * 40, "b" * 40
        good = eligible_pull(head, base)
        mod.require_eligible_pr(good)
        closed = eligible_pull(head, base, state="closed")
        with self.assertRaises(ValueError):
            mod.require_eligible_pr(closed)
        retargeted = eligible_pull(head, base)
        retargeted["base"]["ref"] = "main"
        with self.assertRaises(ValueError):
            mod.require_eligible_pr(retargeted)
        tool_branch = eligible_pull(head, base)
        tool_branch["head"]["ref"] = "cursor/fix-foo"
        with self.assertRaises(ValueError):
            mod.require_eligible_pr(tool_branch)

    def test_final_review_rejects_closed_pr_matching_identity(self):
        snap = snapshot()
        snap["pr"]["draft"] = False
        head, base = "a" * 40, "b" * 40
        entry = {
            "number": 1,
            "reviewers": [{"login": "bot"}],
            "runtime_evidence": {
                "head": head, "base": base, "artifact_sha256": "c" * 64,
                "tested_by": "maintainer", "release_x64": "passed",
                "release_win32": "passed", "envy_tests": "passed",
                "live_runtime": "passed",
            },
        }
        state = {"handled": {}, "stops": {}, "requests": {}}
        for source in mod.trusted_sources(entry, snap):
            state["handled"][source["key"]] = {"head": head, "base": base}
        closed = eligible_pull(head, base, state="closed")
        with patch.object(mod, "gh_json", return_value=closed):
            with self.assertRaises(ValueError):
                mod.final_review({"allow_final_copilot_request": True}, entry, snap, state, None)

    def test_final_review_waits_when_merge_state_not_ready(self):
        snap = snapshot()
        snap["pr"]["draft"] = False
        head, base = "a" * 40, "b" * 40
        entry = {
            "number": 1,
            "reviewers": [{"login": "bot"}],
            "runtime_evidence": {
                "head": head, "base": base, "artifact_sha256": "c" * 64,
                "tested_by": "maintainer", "release_x64": "passed",
                "release_win32": "passed", "envy_tests": "passed",
                "live_runtime": "passed",
            },
        }
        state = {"handled": {}, "stops": {}, "requests": {}}
        for source in mod.trusted_sources(entry, snap):
            state["handled"][source["key"]] = {"head": head, "base": base}
        behind = eligible_pull(head, base, mergeable_state="behind")
        with patch.object(mod, "gh_json", return_value=behind):
            mod.final_review({"allow_final_copilot_request": True}, entry, snap, state, None)
        self.assertEqual(state["phase"], "AWAITING_MERGEABLE")
        self.assertNotIn(f"copilot:{head}:{base}", state.get("requests", {}))


if __name__ == "__main__":
    unittest.main()
