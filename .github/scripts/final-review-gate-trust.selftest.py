#!/usr/bin/env python3
"""Offline tests: PR-controlled YAML cannot publish Final review gate."""

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
PROBE = WORKFLOWS / "final-review-gate.yml"
PUBLISHER = WORKFLOWS / "publish-final-review-gate.yml"
CHECKOUT_PIN = "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09"


def _on_block(text: str) -> str:
    lines = text.replace("\r\n", "\n").splitlines()
    start = None
    for i, line in enumerate(lines):
        if line == "on:" or line.startswith("on:"):
            start = i
            break
    if start is None:
        return ""
    collected = []
    for line in lines[start + 1 :]:
        if line and not line.startswith(" ") and not line.startswith("\t") and not line.startswith("#"):
            break
        collected.append(line)
    return "\n".join(collected)


def _on_pull_request_merge_commit(text: str) -> bool:
    """True when GitHub will load this workflow from the PR merge commit."""
    on_block = _on_block(text)
    if "pull_request_target:" in on_block:
        return False
    return "pull_request:" in on_block or "pull_request_review:" in on_block


class FinalReviewGateTrustTests(unittest.TestCase):
    def test_pr_controlled_probe_cannot_publish_authoritative_success(self):
        probe = PROBE.read_text(encoding="utf-8")
        self.assertIn("name: Final review gate probe", probe)
        self.assertIn("permissions: {}", probe)
        self.assertNotIn("statuses: write", probe)
        self.assertNotIn("checks: write", probe)
        self.assertNotIn("contents: write", probe)
        self.assertNotIn("pull-requests: write", probe)
        self.assertNotIn("publish-final-review-gate.py", probe)
        self.assertNotIn("gh api", probe)
        self.assertNotIn("check-runs", probe)
        self.assertNotIn('context="Final review gate"', probe)
        self.assertIn("permissions: {}", probe)
        self.assertGreaterEqual(probe.count("permissions: {}"), 2)
        self.assertNotIn("repos/${REPOSITORY}/statuses/", probe)
        self.assertTrue(_on_pull_request_merge_commit(probe))

    def test_trusted_publisher_definition_is_default_branch_owned(self):
        pub = PUBLISHER.read_text(encoding="utf-8")
        self.assertIn("name: Publish final review gate", pub)
        self.assertIn("pull_request_target:", pub)
        self.assertIn("workflow_run:", pub)
        self.assertIn("checks: write", pub)
        self.assertNotIn("statuses: write", pub)
        self.assertNotIn("\n  pull_request:\n", pub.replace("\r\n", "\n"))
        self.assertNotIn("pull_request_review:", pub)
        self.assertIn("github.event.repository.default_branch", pub)
        self.assertIn(CHECKOUT_PIN, pub)
        self.assertIn("persist-credentials: false", pub)
        self.assertNotIn("pull_request.head.sha", pub)
        self.assertNotIn("github.head_ref", pub)
        self.assertNotIn("allow-unsafe-pr-checkout", pub)
        self.assertIn(".github/scripts/classify-copilot-review.py", pub)
        self.assertIn("pull_request_review_comment:", PROBE.read_text(encoding="utf-8"))
        self.assertIn("edited", PROBE.read_text(encoding="utf-8"))
        self.assertIn("Final review gate probe", pub)
        self.assertIn("contents: read", pub)
        self.assertNotIn("contents: write", pub)
        self.assertNotIn("pull-requests: write", pub)
        self.assertNotIn("statuses: write", pub)
        self.assertIn("github.event.check_run.name != 'Final review gate'", pub)
        self.assertIn('status:-0}" -eq 2', pub)
        self.assertNotIn('status:-0}" -eq 2 || -z "${pr:-}"', pub)

    def test_publisher_token_can_read_commit_statuses(self):
        pub = PUBLISHER.read_text(encoding="utf-8")
        perms = pub.split("permissions:", 1)[1].split("concurrency:", 1)[0]
        self.assertIn("statuses: read", perms)
        self.assertIn("checks: write", perms)

    def test_pr_modifying_evaluator_does_not_change_publisher_checkout(self):
        pub = PUBLISHER.read_text(encoding="utf-8")
        self.assertIn("ref: ${{ github.event.repository.default_branch }}", pub)
        self.assertIn(".github/scripts/final-review-gate.py", pub)
        self.assertIn(".github/scripts/publish-final-review-gate.py", pub)
        self.assertIn(".github/scripts/classify-copilot-review.py", pub)
        self.assertIn(".github/scripts/finding-ledger.py", pub)
        sparse = pub.split("sparse-checkout:", 1)[1].split("sparse-checkout-cone-mode", 1)[0]
        self.assertIn(".github/scripts/finding-ledger.py", sparse)
        require = pub.split("Require trusted scripts on the default branch", 1)[1]
        self.assertIn(".github/scripts/finding-ledger.py", require)
        outcome = (WORKFLOWS / "copilot-review-outcome.yml").read_text(encoding="utf-8")
        self.assertIn("GraphQL reviewDecision query returned errors", outcome)

    def test_coderabbit_does_not_review_drafts(self):
        text = (ROOT / ".coderabbit.yaml").read_text(encoding="utf-8")
        self.assertIn("drafts: false", text)
        self.assertNotIn("drafts: true", text)
        self.assertRegex(text, r"(?m)^finishing_touches:")

    def test_final_review_gate_fragment_binds_actions_integration(self):
        text = (
            ROOT / ".github" / "rulesets" / "protect-develop.final-review-gate.desired.json"
        ).read_text(encoding="utf-8")
        self.assertIn('"integration_id": 15368', text)
        self.assertNotIn('"integration_id": 0', text)

    def test_outcome_collector_fails_closed_on_graphql_errors(self):
        text = (WORKFLOWS / "copilot-review-outcome.yml").read_text(encoding="utf-8")
        self.assertIn("untreated_threads", text)
        self.assertIn("thread_disposition", text)
        self.assertIn("GraphQL reviewThreads query returned errors", (ROOT / ".github" / "scripts" / "collect-final-review-snapshot.py").read_text(encoding="utf-8"))

    def test_changing_probe_and_scripts_cannot_self_green(self):
        probe = PROBE.read_text(encoding="utf-8")
        pub = PUBLISHER.read_text(encoding="utf-8")
        mutated = probe.replace("permissions: {}", "permissions:\n  statuses: write")
        self.assertIn("statuses: write", mutated)
        self.assertNotIn("publish-final-review-gate.py", mutated)
        self.assertIn("pull_request_target:", pub)
        self.assertIn("checks: write", pub)
        self.assertNotEqual(PROBE.name, PUBLISHER.name)

    def test_no_other_pr_merge_commit_workflow_publishes_the_gate_context(self):
        for path in list(WORKFLOWS.glob("*.yml")) + list(WORKFLOWS.glob("*.yaml")):
            text = path.read_text(encoding="utf-8")
            if path.name == PUBLISHER.name:
                continue
            if not _on_pull_request_merge_commit(text):
                continue
            self.assertNotIn(
                'context="Final review gate"',
                text,
                msg=f"{path.name} must not post Final review gate from a PR-controlled workflow",
            )
            self.assertNotIn("context: Final review gate", text)

    def test_publisher_paginates_commit_pulls(self):
        text = PUBLISHER.read_text(encoding="utf-8")
        self.assertIn("--paginate", text)
        self.assertIn("--slurp", text)
        self.assertIn("commits/{sha}/pulls", text)
        self.assertIn("len(set(eligible)) != 1", text)
        self.assertNotIn("pr = numbers[0]", text)
        self.assertIn("steps.scripts.outputs.missing != '1'", text)
        self.assertIn("Publish pending gate when default-branch scripts are missing", text)
        self.assertIn("Convert-HostOwnedPath", (ROOT / "scripts" / "review" / "register-task.ps1").read_text(encoding="utf-8"))

    def test_final_copilot_request_is_non_destructive_union(self):
        text = (ROOT / ".github" / "scripts" / "request-final-copilot-review.sh").read_text(encoding="utf-8")
        self.assertIn("union:true", text)
        self.assertNotIn("userIds:[]", text)
        self.assertNotIn("REVIEWERS_CLEARED", text)
        outcome = (WORKFLOWS / "copilot-review-outcome.yml").read_text(encoding="utf-8")
        self.assertIn("GraphQL reviewDecision query returned errors", outcome)
        self.assertNotIn("param(\n    [Parameter(Mandatory)][string]$Service,\n    [Parameter(Mandatory)][string]$Config,\n    [Parameter(Mandatory)][string]$Python,\n    [switch]$EnableCorrections\n)\nparam(", (ROOT / "scripts" / "review" / "register-task.ps1").read_text(encoding="utf-8").replace("\r\n", "\n"))
        self.assertIn('"review_decision_source": "graphql"', outcome)
        self.assertIn("Resolve-Path -LiteralPath $root", (ROOT / "scripts" / "review" / "register-task.ps1").read_text(encoding="utf-8"))

    def test_review_history_file_survives_until_check_history(self):
        text = (WORKFLOWS / "copilot-review-outcome.yml").read_text(encoding="utf-8")
        before, after = text.split("finding-ledger.py check-history", 1)
        self.assertNotIn('rm -f "$REVIEWS_FILE"', before)
        self.assertIn('rm -f "$REVIEWS_FILE"', after)

    def test_trusted_success_still_requires_exact_current_sha(self):
        import importlib.util
        import sys

        spec = importlib.util.spec_from_file_location(
            "final_review_gate_mod",
            ROOT / ".github" / "scripts" / "final-review-gate.py",
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)
        head = "a" * 40
        old = "b" * 40
        copilot = "copilot-pull-request-reviewer[bot]"
        snapshot = {
            "pr_number": 397,
            "head_sha": head,
            "current_head_sha": head,
            "is_draft": False,
            "review_decision": "APPROVED",
            "unresolved_threads": 0,
            "untreated_threads": 0,
            "untreated_pr_level_findings": [],
            "previously_missed_titles": [],
            "suppressed_comment_titles": [],
            "open_finding_titles": [],
            "changed_files": ["Envy/Buffer.cpp"],
            "required_checks": [{"name": "Format Check", "state": "SUCCESS"}],
            "reviews": [
                {"id": 1, "user": {"login": copilot, "type": "Bot"}, "commit_id": head, "state": "APPROVED"}
            ],
            "finding_ledger": [],
            "copilot_request_pending": False,
            "review_decision_source": "graphql",
            "review_decision_unavailable": False,
            "merge_state_status": "CLEAN",
            "pr_author_login": "alice",
            "copilot_classification": "APPROVED",
        }
        ok = mod.evaluate_final_review_gate(snapshot)
        self.assertEqual(ok["state"], mod.STATE_SUCCESS)
        moved = dict(snapshot, current_head_sha=old, head_sha=old, reviews=[])
        out = mod.revalidate_gate_before_success(ok, moved)
        self.assertNotEqual(out["state"], mod.STATE_SUCCESS)
        self.assertFalse(out["allow_publish"])


if __name__ == "__main__":
    unittest.main()
