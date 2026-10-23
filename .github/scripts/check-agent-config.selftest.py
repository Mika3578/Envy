#!/usr/bin/env python3
"""Regression tests for check-agent-config.py (offline, no network)."""

from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("check_agent_config", HERE / "check-agent-config.py")
cac = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cac)

COPIED = [
    "AGENTS.md",
    "CLAUDE.md",
    ".aider.conf.yml",
    ".clinerules",
    ".windsurfrules",
    ".continue/rules/envy.md",
    ".github/copilot-instructions.md",
    ".github/rulesets/protect-develop.desired.json",
    ".agents",
    ".cursor/rules",
]


class RepoState(unittest.TestCase):
    def test_repository_passes(self):
        self.assertEqual(cac.run(cac.REPO_ROOT), [])


    def skill_text(self, name):
        return (cac.REPO_ROOT / ".agents/skills" / name / "SKILL.md").read_text(encoding="utf-8")

    def test_finish_verdict_phrases(self):
        text = self.skill_text("envy-pr-workflow")
        self.assertIn("Technically ready for human validation", text)
        self.assertIn("Blocked: <precise reason>", text)

    def test_skills_keep_no_blocked_or_unsafe_advice(self):
        for path in (cac.REPO_ROOT / ".agents/skills").rglob("*.md"):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("gh pr checks --", text, path)
            self.assertNotIn("force-with-lease", text, path)

    def test_review_skill_uses_ccr_route(self):
        self.assertIn("/ccr/review_threads", self.skill_text("envy-review-requests"))

    def test_live_ruleset_path_must_stay_in_repository(self):
        for source in ("../outside.json", "/etc/passwd"):
            with self.assertRaises(SystemExit):
                cac.load_live_ruleset(source)


class Mutations(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        for rel in COPIED:
            src, dst = cac.REPO_ROOT / rel, self.tmp / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            if src.is_dir():
                shutil.copytree(src, dst)
            else:
                shutil.copy2(src, dst)
        # Each mutation test asserts its own error; the fixture tree lacks the
        # product files, so unrelated glob/path errors are expected here.

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def errors(self, live=None):
        return "\n".join(cac.run(self.tmp, live))

    def edit(self, rel, old, new):
        path = self.tmp / rel
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text, f"fixture drift in {rel}")
        path.write_text(text.replace(old, new, 1), encoding="utf-8")

    def test_agents_size_budget(self):
        with (self.tmp / "AGENTS.md").open("a", encoding="utf-8") as fh:
            fh.write("filler line\n" * 2000)
        self.assertIn("AGENTS.md is", self.errors())

    def test_claude_must_import_agents(self):
        self.edit("CLAUDE.md", "@AGENTS.md", "Read AGENTS.md")
        self.assertIn("must start with '@AGENTS.md'", self.errors())

    def test_adapter_must_point_to_agents(self):
        (self.tmp / ".clinerules").write_text("# Cline\nUse tabs.\n", encoding="utf-8")
        self.assertIn(".clinerules must point to AGENTS.md", self.errors())

    def test_copilot_review_budget(self):
        with (self.tmp / ".github/copilot-instructions.md").open("a", encoding="utf-8") as fh:
            fh.write("x" * 4000)
        self.assertIn("Copilot code review reads 4000", self.errors())

    def test_aider_preloads_only_agents(self):
        self.edit(".aider.conf.yml", "  - AGENTS.md\n", "  - AGENTS.md\n  - docs/DEVELOPMENT_PLAN.md\n")
        self.assertIn("must preload only AGENTS.md", self.errors())

    def test_legacy_cursorrules(self):
        (self.tmp / ".cursorrules").write_text("x\n", encoding="utf-8")
        self.assertIn(".cursorrules is legacy", self.errors())

    def test_skill_name_must_match_directory(self):
        self.edit(".agents/skills/envy-pr-workflow/SKILL.md", "name: envy-pr-workflow", "name: pr")
        self.assertIn("must equal the directory name", self.errors())

    def test_unlisted_skill(self):
        skill = self.tmp / ".agents/skills/envy-extra/SKILL.md"
        skill.parent.mkdir(parents=True)
        skill.write_text("---\nname: envy-extra\ndescription: Extra.\n---\n", encoding="utf-8")
        self.assertIn("'envy-extra' is not listed", self.errors())

    def test_skill_outside_shared_directory(self):
        skill = self.tmp / ".github/skills/old/SKILL.md"
        skill.parent.mkdir(parents=True)
        skill.write_text("---\nname: old\ndescription: Old.\n---\n", encoding="utf-8")
        self.assertIn("skills must live only in .agents/skills/", self.errors())

    def test_cursor_rule_always_apply(self):
        self.edit(".cursor/rules/01-cpp.mdc", "alwaysApply: false", "alwaysApply: true")
        self.assertIn("alwaysApply must be false", self.errors())

    def test_cursor_rule_quoted_array_globs(self):
        self.edit(".cursor/rules/07-documentation.mdc", "globs: docs/**", 'globs: ["docs/**"')
        self.assertIn("unquoted, comma-separated", self.errors())

    def test_cursor_rule_dead_glob(self):
        self.edit(".cursor/rules/01-cpp.mdc", "**/*.inl", "**/*.inl,**/*.cxx")
        self.assertIn("glob '**/*.cxx' matches no file", self.errors())

    def test_cursor_rule_read_only_tree(self):
        (self.tmp / "Services/zlib/zlib.h").parent.mkdir(parents=True)
        (self.tmp / "Services/zlib/zlib.h").write_text("x\n", encoding="utf-8")
        self.edit(".cursor/rules/06-p2p-protocols.mdc", "Remote/**", "Remote/**,**/Services/**")
        self.assertIn("read-only third-party tree", self.errors())

    def test_dead_path_reference(self):
        with (self.tmp / ".agents/skills/envy-code-review/SKILL.md").open("a", encoding="utf-8") as fh:
            fh.write("\nSee `docs/10_dev/does-not-exist.md`.\n")
        self.assertIn("'docs/10_dev/does-not-exist.md' does not exist", self.errors())

    def test_retired_draft_review_ban(self):
        with (self.tmp / ".github/copilot-instructions.md").open("a", encoding="utf-8") as fh:
            fh.write("\nAgents must not request any review product while the PR is a Draft.\n")
        self.assertIn("retired rule", self.errors())

    def test_duplicated_core_rules(self):
        core = (self.tmp / "AGENTS.md").read_text(encoding="utf-8")
        with (self.tmp / ".windsurfrules").open("a", encoding="utf-8") as fh:
            fh.write("\n".join(l for l in core.splitlines() if len(l.strip()) >= 60)[:3000])
        self.assertIn("copies", self.errors())

    def test_missing_required_check(self):
        self.edit("AGENTS.md", "SonarCloud Code Analysis", "Sonar")
        self.assertIn("required check 'SonarCloud Code Analysis'", self.errors())

    def test_live_approval_count_mismatch(self):
        live = json.loads((self.tmp / ".github/rulesets/protect-develop.desired.json").read_text(encoding="utf-8"))
        for rule in live["rules"]:
            if rule["type"] == "pull_request":
                rule["parameters"]["required_approving_review_count"] = 2
        self.assertIn("differs from the live ruleset (2)", self.errors(live))

    def test_documented_check_not_enforced(self):
        self.edit("AGENTS.md", "SonarCloud Code Analysis;", "SonarCloud Code Analysis, Docs Check;")
        self.assertIn("lists 'Docs Check' but the committed ruleset does not require it", self.errors())

    def test_committed_approval_target_mismatch(self):
        path = self.tmp / ".github/rulesets/protect-develop.desired.json"
        desired = json.loads(path.read_text(encoding="utf-8"))
        for rule in desired["rules"]:
            if rule["type"] == "pull_request":
                rule["parameters"]["required_approving_review_count"] = 2
        path.write_text(json.dumps(desired), encoding="utf-8")
        self.assertIn("committed approval target differs from protect-develop.desired.json (2)", self.errors())

    def test_live_ruleset_without_approval_count(self):
        live = {"rules": [{"type": "pull_request", "parameters": {}}]}
        self.assertIn("has no required_approving_review_count", self.errors(live))

    def test_unterminated_skill_frontmatter(self):
        path = self.tmp / ".agents/skills/envy-code-review/SKILL.md"
        text = path.read_text(encoding="utf-8").split("\n")
        closing = text.index("---", 1)
        path.write_text("\n".join(text[:closing] + text[closing + 1:]), encoding="utf-8")
        self.assertIn("missing or unterminated YAML frontmatter", self.errors())

    def test_live_automatic_copilot_review(self):
        live = {"rules": [{"type": "copilot_code_review", "parameters": {"review_on_push": True}}]}
        self.assertIn("enables automatic Copilot review", self.errors(live))


if __name__ == "__main__":
    unittest.main(verbosity=1)
