#!/usr/bin/env python3
"""Offline tests for audit-ruleset drift detection."""

import copy
import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("audit_ruleset", SCRIPTS / "audit-ruleset.py")
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)
DESIRED = json.loads((SCRIPTS.parent / "rulesets" / "protect-develop.desired.json").read_text(encoding="utf-8"))


def desired_ruleset() -> dict:
    return {
        "name": DESIRED["name"],
        "target": DESIRED["target"],
        "enforcement": DESIRED["enforcement"],
        "conditions": DESIRED["conditions"],
        "rules": copy.deepcopy(DESIRED["rules"]),
        "bypass_actors": DESIRED.get("bypass_actors", []),
    }


class AuditRulesetTests(unittest.TestCase):
    def test_migration_refuses_changed_ref_coverage(self):
        live = copy.deepcopy(desired_ruleset())
        live["conditions"]["ref_name"]["include"].append("refs/heads/security/*")
        command = AUDIT.migration_command("Mika3578/Envy", 1, desired_ruleset(), live)
        self.assertIn("Migration refused", command)
        self.assertNotIn("--method PUT", command)

    def test_migration_refuses_changed_bypass_actors(self):
        live = copy.deepcopy(desired_ruleset())
        live["bypass_actors"].append({"actor_id": 1, "actor_type": "Integration", "bypass_mode": "always"})
        command = AUDIT.migration_command("Mika3578/Envy", 1, desired_ruleset(), live)
        self.assertIn("Migration refused", command)
        self.assertNotIn("--method PUT", command)

    def test_migration_refuses_changed_target_or_enforcement(self):
        for key, value in (("target", "tag"), ("enforcement", "evaluate")):
            with self.subTest(key=key):
                live = copy.deepcopy(desired_ruleset())
                live[key] = value
                command = AUDIT.migration_command("Mika3578/Envy", 1, desired_ruleset(), live)
                self.assertIn("Migration refused", command)
                self.assertNotIn("--method PUT", command)

    def test_migration_refuses_extra_live_protection(self):
        live = desired_ruleset()
        live["rules"].append({"type": "future_protection", "parameters": {}})
        command = AUDIT.migration_command("Mika3578/Envy", 1, desired_ruleset(), live)
        self.assertIn("Migration refused", command)
        self.assertNotIn("--method PUT", command)

    def test_migration_refuses_extra_required_context(self):
        live = desired_ruleset()
        gate = next(rule for rule in live["rules"] if rule["type"] == "required_status_checks")
        gate["parameters"]["required_status_checks"].append({"context": "Extra security gate"})
        command = AUDIT.migration_command("Mika3578/Envy", 1, desired_ruleset(), live)
        self.assertIn("Migration refused", command)

    def test_matching_live_has_no_drift(self):
        live = desired_ruleset()
        drift = AUDIT.compare(desired_ruleset(), live)
        self.assertEqual(drift, [])

    def test_sonar_extra_is_drift(self):
        live = desired_ruleset()
        for rule in live["rules"]:
            if rule["type"] == "required_status_checks":
                rule["parameters"]["required_status_checks"].append(
                    {"context": "SonarCloud Code Analysis", "integration_id": 12526}
                )
        drift = AUDIT.compare(desired_ruleset(), live)
        self.assertTrue(any("SonarCloud" in line for line in drift))

    def test_approval_count_drift(self):
        live = desired_ruleset()
        for rule in live["rules"]:
            if rule["type"] == "pull_request":
                rule["parameters"]["required_approving_review_count"] = 0
        drift = AUDIT.compare(desired_ruleset(), live)
        self.assertTrue(any("required_approving_review_count" in line for line in drift))

    @patch.object(AUDIT.subprocess, "run")
    def test_malformed_gh_json_has_diagnostic(self, run):
        run.return_value = type("Result", (), {
            "returncode": 0,
            "stdout": "{invalid",
            "stderr": "",
        })()
        with self.assertRaisesRegex(RuntimeError, "malformed JSON"):
            AUDIT.fetch_live_ruleset("Mika3578/Envy", 16457466)

    @patch.object(AUDIT.subprocess, "run")
    def test_failed_gh_request_has_diagnostic(self, run):
        run.return_value = type("Result", (), {
            "returncode": 1,
            "stdout": "",
            "stderr": "authentication failed",
        })()
        with self.assertRaisesRegex(RuntimeError, "GitHub CLI request failed"):
            AUDIT.fetch_live_ruleset("Mika3578/Envy", 16457466)

    def test_repo_argument_rejects_path_injection(self):
        with self.assertRaisesRegex(ValueError, "OWNER/REPOSITORY"):
            AUDIT.fetch_live_ruleset("../../etc/passwd", 16457466)

    def test_repo_argument_rejects_dot_segments(self):
        with self.assertRaises(ValueError):
            AUDIT.validate_repo("Mika3578/..")
        with self.assertRaises(ValueError):
            AUDIT.validate_repo("../Envy")
        self.assertEqual(AUDIT.validate_repo("Mika3578/Envy"), "Mika3578/Envy")

    def test_json_path_rejects_escape(self):
        with self.assertRaisesRegex(ValueError, "inside the repository"):
            AUDIT.load_json(Path("..") / ".." / "outside.json")

    def test_integration_id_drift(self):
        live = desired_ruleset()
        for rule in live["rules"]:
            if rule["type"] == "required_status_checks":
                for check in rule["parameters"]["required_status_checks"]:
                    check["integration_id"] = 99999
        drift = AUDIT.compare(desired_ruleset(), live)
        self.assertTrue(any("integration_id" in line or "missing on live" in line for line in drift))

    def test_missing_rule_type_is_drift(self):
        live = desired_ruleset()
        live["rules"] = [rule for rule in live["rules"] if rule["type"] != "deletion"]
        drift = AUDIT.compare(desired_ruleset(), live)
        self.assertTrue(any("deletion" in line for line in drift))


    def test_missing_context_is_preserved_as_drift(self):
        live = desired_ruleset()
        for rule in live["rules"]:
            if rule["type"] == "required_status_checks":
                rule["parameters"]["required_status_checks"].append(
                    {"context": "", "integration_id": 1}
                )
        drift = AUDIT.compare(desired_ruleset(), live)
        self.assertTrue(any("missing-context" in line or "required_status_checks" in line for line in drift))

    def test_migration_preserves_live_code_quality_rule(self):
        live = desired_ruleset()
        desired = desired_ruleset()
        desired["rules"] = [rule for rule in desired["rules"] if rule["type"] != "code_quality"]
        command = AUDIT.migration_command("Mika3578/Envy", 1, desired, live)
        self.assertIn("code_quality", command)
        self.assertNotIn("code_quality", AUDIT.migration_command("Mika3578/Envy", 1, desired))

    def test_missing_code_quality_gate_is_drift(self):
        live = desired_ruleset()
        live["rules"] = [rule for rule in live["rules"] if rule["type"] != "code_quality"]
        self.assertTrue(any("code_quality" in line for line in AUDIT.compare(desired_ruleset(), live)))

    def test_code_quality_severity_is_drift(self):
        live = desired_ruleset()
        AUDIT.rule_by_type(live, "code_quality")["parameters"]["severity"] = "errors"
        self.assertTrue(any("code_quality.parameters" in line for line in AUDIT.compare(desired_ruleset(), live)))


if __name__ == "__main__":
    unittest.main()
