#!/usr/bin/env python3
"""Regression tests for CI phase transitions and the transitional gate policy."""

import importlib.util
import itertools
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("pr_phase", SCRIPTS / "pr-phase.py")
PHASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PHASE)
BASH = os.environ.get("BASH_EXE", "bash")


def payload(draft, labels=(), action="synchronize"):
    return {
        "action": action,
        "pull_request": {"draft": draft, "labels": [{"name": x} for x in labels]},
    }


class PhaseTests(unittest.TestCase):
    def test_phase_transitions(self):
        # The label collection, not the last label action, is authoritative.
        for action, draft, labeled in itertools.product(
            ("opened", "synchronize", "reopened", "ready_for_review",
             "converted_to_draft", "labeled", "unlabeled"), (True, False), (True, False)
        ):
            with self.subTest(action=action, draft=draft, labeled=labeled):
                labels = ["unrelated"] + (["stage:live-test"] if labeled else [])
                expected = "ready" if not draft else "live-test" if labeled else "draft"
                self.assertEqual(PHASE.classify_phase("pull_request", payload(draft, labels, action)), expected)

    def test_unrelated_or_similar_label_cannot_promote_draft(self):
        for label in ("stage:live-test-extra", "Stage:live-test", "ready-for-review", "needs-human"):
            self.assertEqual(PHASE.classify_phase("pull_request", payload(True, [label])), "draft")

    def test_missing_or_invalid_input_fails_closed(self):
        for event in ({}, {"pull_request": {}}, payload("false"),
                      {"pull_request": {"draft": True, "labels": "stage:live-test"}},
                      {"pull_request": {"draft": False, "labels": [{}]}}):
            with self.subTest(event=event), self.assertRaises((KeyError, ValueError)):
                PHASE.classify_phase("pull_request", event)

    def test_non_pr_events_preserve_full_validation(self):
        for name in ("push", "schedule", "workflow_dispatch"):
            self.assertEqual(PHASE.classify_phase(name, {}), "full")

    def test_real_event_file_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            event = Path(directory) / "event.json"
            output = Path(directory) / "output.txt"
            event.write_text(json.dumps(payload(True)), encoding="utf-8")
            result = subprocess.run(
                [os.sys.executable, str(SCRIPTS / "pr-phase.py")],
                env={**os.environ, "GITHUB_EVENT_NAME": "pull_request",
                     "GITHUB_EVENT_PATH": str(event), "GITHUB_OUTPUT": str(output)},
                capture_output=True, text=True, check=True,
            )
            self.assertEqual(output.read_text(), "phase=draft\nfull_validation=false\n")
            self.assertEqual(result.stdout, output.read_text())


class GateTests(unittest.TestCase):
    def policy(self, phase, remote="false", deps="false"):
        result = subprocess.run(
            [BASH, "-c", 'set -euo pipefail; add_must() { printf "%s\\n" "$1"; }; source ./pr-gate-policy.sh; pr_gate_policy'],
            cwd=SCRIPTS, env={**os.environ, "CI_PHASE": phase,
                              "RUN_REMOTE_JS": remote, "RUN_DEP_REVIEW": deps},
            capture_output=True, text=True,
        )
        return result

    def test_draft_excludes_only_deferred_windows_checks(self):
        draft = set(self.policy("draft", "true", "true").stdout.splitlines())
        full = set(self.policy("ready", "true", "true").stdout.splitlines())
        self.assertEqual(full - draft, {"Analyze (csharp)", "Build x64 Release", "Build Win32 Release"})
        self.assertEqual(draft - full, set())
        self.assertTrue({"Analyze (c-cpp)", "Analyze (javascript-typescript)", "secret-scan",
                         "Format Check", "Documentation Check", "Lint build files",
                         "Vcpkg manifest sanity", "Remote JS Security Tests", "Dependency review"} <= draft)

    def test_full_policy_does_not_skip_builds_for_docs(self):
        for phase in ("ready", "live-test", "full"):
            result = self.policy(phase)
            self.assertEqual(result.returncode, 0)
            self.assertIn("Build x64 Release", result.stdout)
            self.assertIn("Build Win32 Release", result.stdout)
            self.assertNotIn("Dependency review", result.stdout)
            self.assertNotIn("Remote JS Security Tests", result.stdout)

    def test_invalid_phase_fails(self):
        self.assertNotEqual(self.policy("unknown").returncode, 0)


if __name__ == "__main__":
    unittest.main()
