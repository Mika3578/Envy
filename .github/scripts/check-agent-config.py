#!/usr/bin/env python3
"""Consistency checks for AI-agent instruction files.

Keeps AGENTS.md the single, compact source of truth and every tool adapter
thin, loadable and in sync with the committed ruleset. Offline by default;
pipe `gh api repos/<o>/<r>/rulesets/<id>` into `--live-ruleset -` to also
check the documented approval count against the live ruleset.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Codex stops reading project docs at 32 KiB; keep a wide margin so the core
# rules never get truncated and stay cheap to load in every session.
AGENTS_MAX_BYTES = 16 * 1024
AGENTS_MAX_LINES = 200
CLAUDE_MAX_LINES = 30
ADAPTER_MAX_LINES = 20
# Copilot code review ignores instruction text past 4,000 characters.
COPILOT_MAX_CHARS = 4000
SKILL_NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SKILL_DESCRIPTION_MAX = 1024

ADAPTERS = (".clinerules", ".windsurfrules", ".continue/rules/envy.md")
SKILLS_DIR = ".agents/skills"
RETIRED_SKILL_DIRS = (".github/skills", ".claude/skills", ".cursor/skills", ".codex/skills")
CURSOR_RULES_DIR = ".cursor/rules"
READ_ONLY_PREFIXES = (
    "Services/",
    "HashLib/HashLib/",
    "Plugins/RatDVDPlugin/",
    "Plugins/SWFPlugin/",
    "Plugins/PluginWizard/",
)
SKIP_DIRS = {".git", "vcpkg", "vcpkg_installed", "node_modules", "Builds", ".vs"}

# Rules removed on purpose; reintroducing them in instruction files would
# bring back artificial stops. Historical docs may still quote them.
RETIRED_RULES = (
    (re.compile(r"must not request (?:any )?(?:Copilot|review)[^.]*Draft", re.I),
     "blanket ban on Draft review requests (see envy-review-requests)"),
    (re.compile(r"do not request any review product while the PR is Draft", re.I),
     "blanket ban on Draft review requests (see envy-review-requests)"),
    (re.compile(r"at most (?:three|two|\d) automatic correction batches", re.I),
     "fixed correction-batch budget (escalate on lack of progress instead)"),
    (re.compile(r"Surface the problem and wait for guidance", re.I),
     "stop-and-wait escalation (record the blocker and continue)"),
)

PATH_TOKEN_RE = re.compile(r"`([^`\s]+)`")
PATH_SUFFIXES = (".md", ".mdc", ".py", ".sh", ".yml", ".yaml", ".json", ".ps1", ".sln")


def read(root: Path, rel: str) -> str:
    return (root / rel).read_text(encoding="utf-8")


def repo_files(root: Path) -> list[str]:
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        for name in filenames:
            out.append(name if rel_dir == "." else f"{rel_dir}/{name}")
    return out


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    i, parts = 0, []
    while i < len(pattern):
        if pattern.startswith("**/", i):
            parts.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            parts.append(".*")
            i += 2
        elif pattern[i] == "*":
            parts.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            parts.append("[^/]")
            i += 1
        else:
            parts.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(parts) + "$")


def frontmatter(text: str) -> dict[str, str] | None:
    """Line-based parser: Cursor writes unquoted globs YAML cannot load."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None
    fields: dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            return fields
        key, sep, value = line.partition(":")
        if sep and not line.startswith((" ", "\t")):
            fields[key.strip()] = value.strip()
    return None


def instruction_files(root: Path) -> list[str]:
    files = ["AGENTS.md", "CLAUDE.md", ".github/copilot-instructions.md", *ADAPTERS]
    files += sorted(p.relative_to(root).as_posix() for p in (root / SKILLS_DIR).glob("*/SKILL.md"))
    files += sorted(p.relative_to(root).as_posix() for p in (root / CURSOR_RULES_DIR).glob("*.mdc"))
    return [f for f in files if (root / f).is_file()]


def check_sizes(root: Path) -> list[str]:
    errors = []
    agents = (root / "AGENTS.md").read_bytes()
    if len(agents) > AGENTS_MAX_BYTES:
        errors.append(f"AGENTS.md is {len(agents)} bytes (limit {AGENTS_MAX_BYTES}); move procedures to skills")
    if agents.count(b"\n") > AGENTS_MAX_LINES:
        errors.append(f"AGENTS.md has more than {AGENTS_MAX_LINES} lines")
    claude = read(root, "CLAUDE.md")
    first = next((line.strip() for line in claude.splitlines() if line.strip()), "")
    if first != "@AGENTS.md":
        errors.append("CLAUDE.md must start with '@AGENTS.md' so Claude Code loads the canonical rules")
    if len(claude.splitlines()) > CLAUDE_MAX_LINES:
        errors.append(f"CLAUDE.md exceeds {CLAUDE_MAX_LINES} lines; keep it a thin adapter")
    for rel in ADAPTERS:
        if not (root / rel).is_file():
            continue
        text = read(root, rel)
        if "AGENTS.md" not in text:
            errors.append(f"{rel} must point to AGENTS.md")
        if len(text.splitlines()) > ADAPTER_MAX_LINES:
            errors.append(f"{rel} exceeds {ADAPTER_MAX_LINES} lines; keep it a thin adapter")
    copilot = read(root, ".github/copilot-instructions.md")
    if len(copilot) > COPILOT_MAX_CHARS:
        errors.append(f".github/copilot-instructions.md is {len(copilot)} chars; Copilot code review reads {COPILOT_MAX_CHARS}")
    if (root / ".cursorrules").exists():
        errors.append(".cursorrules is legacy; use AGENTS.md and .cursor/rules/*.mdc")
    return errors


def check_aider(root: Path) -> list[str]:
    path = root / ".aider.conf.yml"
    if not path.is_file():
        return []
    reads, in_read = [], False
    for line in path.read_text(encoding="utf-8").splitlines():
        if re.match(r"^read:\s*$", line):
            in_read = True
            continue
        if in_read:
            item = re.match(r"^\s+-\s+(\S+)", line)
            if item:
                reads.append(item.group(1))
            elif line.strip() and not line.startswith((" ", "#")):
                in_read = False
    if reads != ["AGENTS.md"]:
        return [f".aider.conf.yml must preload only AGENTS.md, found {reads}"]
    return []


def check_skills(root: Path) -> list[str]:
    errors = []
    for rel in RETIRED_SKILL_DIRS:
        if (root / rel).is_dir() and any((root / rel).glob("*/SKILL.md")):
            errors.append(f"skills must live only in {SKILLS_DIR}/ (found {rel}/)")
    names = set()
    for skill in sorted((root / SKILLS_DIR).glob("*/SKILL.md")):
        rel = skill.relative_to(root).as_posix()
        meta = frontmatter(skill.read_text(encoding="utf-8"))
        if meta is None:
            errors.append(f"{rel}: missing or unterminated YAML frontmatter")
            continue
        name, description = meta.get("name", ""), meta.get("description", "")
        if name != skill.parent.name or not SKILL_NAME_RE.match(name):
            errors.append(f"{rel}: name '{name}' must equal the directory name in kebab-case")
        if not description or len(description) > SKILL_DESCRIPTION_MAX:
            errors.append(f"{rel}: description must be 1..{SKILL_DESCRIPTION_MAX} characters")
        names.add(name)
    listed = set(re.findall(r"^\|\s*`([a-z0-9-]+)`\s*\|", read(root, "AGENTS.md"), re.M))
    for missing in sorted(names - listed):
        errors.append(f"skill '{missing}' is not listed in the AGENTS.md skills table")
    for stale in sorted(listed - names):
        errors.append(f"AGENTS.md lists skill '{stale}' but {SKILLS_DIR}/{stale}/SKILL.md is missing")
    return errors


def check_cursor_rules(root: Path, files: list[str]) -> list[str]:
    errors = []
    for rule in sorted((root / CURSOR_RULES_DIR).glob("*.mdc")):
        rel = rule.relative_to(root).as_posix()
        meta = frontmatter(rule.read_text(encoding="utf-8"))
        if meta is None:
            errors.append(f"{rel}: missing or unterminated frontmatter")
            continue
        if meta.get("alwaysApply", "").lower() != "false":
            errors.append(f"{rel}: alwaysApply must be false (global rules belong in AGENTS.md)")
        if meta.get("description", ""):
            errors.append(f"{rel}: leave description empty so the rule attaches by glob only")
        globs = meta.get("globs", "")
        if not globs or globs[0] in "[\"'":
            errors.append(f"{rel}: globs must be a non-empty, unquoted, comma-separated list")
            continue
        for pattern in (g.strip() for g in globs.split(",")):
            regex = glob_to_regex(pattern)
            if not any(regex.match(f) for f in files):
                errors.append(f"{rel}: glob '{pattern}' matches no file")
            literal = pattern.lstrip("*/")
            if any(literal.startswith(p) or f"/{p}" in pattern for p in READ_ONLY_PREFIXES):
                errors.append(f"{rel}: glob '{pattern}' targets a read-only third-party tree")
    return errors


def check_paths(root: Path, docs: list[str]) -> list[str]:
    errors = []
    for rel in docs:
        for token in PATH_TOKEN_RE.findall(read(root, rel)):
            token = token.rstrip(".,;:)")
            if any(c in token for c in "*{}<>$") or token.startswith(("-", "@", "http")):
                continue
            # Only multi-segment paths: bare names and `prefix/` tokens are
            # usually branch prefixes or generic file names.
            if "/" not in token.rstrip("/"):
                continue
            if token.endswith("/") or token.endswith(PATH_SUFFIXES):
                if not (root / token).exists():
                    errors.append(f"{rel}: referenced path '{token}' does not exist")
    return errors


def check_retired_rules(root: Path, docs: list[str]) -> list[str]:
    errors = []
    for rel in docs:
        text = " ".join(read(root, rel).split())
        for regex, why in RETIRED_RULES:
            if regex.search(text):
                errors.append(f"{rel}: reintroduces a retired rule: {why}")
    return errors


def check_duplication(root: Path, docs: list[str]) -> list[str]:
    def long_lines(text: str) -> set[str]:
        return {" ".join(l.split()) for l in text.splitlines() if len(l.strip()) >= 60}

    core = long_lines(read(root, "AGENTS.md"))
    errors = []
    for rel in docs:
        if rel == "AGENTS.md":
            continue
        shared = core & long_lines(read(root, rel))
        if len(shared) > 3:
            errors.append(f"{rel}: copies {len(shared)} lines of AGENTS.md; link to it instead")
    return errors


def check_ruleset(root: Path, live: dict | None) -> list[str]:
    errors = []
    agents = " ".join(read(root, "AGENTS.md").split())
    desired = json.loads(read(root, ".github/rulesets/protect-develop.desired.json"))
    for source, ruleset in (("committed", desired), ("live", live)):
        if ruleset is None:
            continue
        rules = {r["type"]: r.get("parameters", {}) for r in ruleset.get("rules", [])}
        for check in rules.get("required_status_checks", {}).get("required_status_checks", []):
            if check["context"] not in agents:
                errors.append(f"AGENTS.md does not list {source} required check '{check['context']}'")
        review = rules.get("copilot_code_review", {})
        if review.get("review_on_push") or review.get("review_draft_pull_requests"):
            errors.append(f"{source} ruleset enables automatic Copilot review; AGENTS.md says reviews are on request")
        if source == "committed":
            target = rules.get("pull_request", {}).get("required_approving_review_count")
            match = re.search(r"committed target \(`[^`]+`\) is (\d+)", agents)
            if not match or int(match.group(1)) != target:
                errors.append(f"AGENTS.md committed approval target differs from protect-develop.desired.json ({target})")
        if source == "live":
            count = rules.get("pull_request", {}).get("required_approving_review_count")
            match = re.search(r"Required approving reviews: \*\*(\d+)\*\*", agents)
            if count is None:
                errors.append("live ruleset has no required_approving_review_count; pass the full rulesets API response")
            elif not match or int(match.group(1)) != count:
                errors.append(f"AGENTS.md approval count differs from the live ruleset ({count})")
    return errors


def run(root: Path, live: dict | None = None) -> list[str]:
    docs = instruction_files(root)
    errors = []
    errors += check_sizes(root)
    errors += check_aider(root)
    errors += check_skills(root)
    errors += check_cursor_rules(root, repo_files(root))
    errors += check_paths(root, docs)
    errors += check_retired_rules(root, docs)
    errors += check_duplication(root, docs)
    errors += check_ruleset(root, live)
    return errors


def load_live_ruleset(source: str | None) -> dict | None:
    """Read the live ruleset from stdin ('-') or a JSON file inside the repository."""
    if source is None:
        return None
    if source == "-":
        return json.load(sys.stdin)
    path = (REPO_ROOT / source).resolve()
    if not path.is_relative_to(REPO_ROOT):
        raise SystemExit(f"--live-ruleset must be '-' or a path inside the repository: {source}")
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--live-ruleset", metavar="JSON", help="'-' for stdin, or a repo-relative file")
    args = parser.parse_args()
    errors = run(REPO_ROOT, load_live_ruleset(args.live_ruleset))
    for error in errors:
        print(f"::error::{error}")
    if not errors:
        print(f"Agent configuration OK ({len(instruction_files(REPO_ROOT))} instruction files).")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
