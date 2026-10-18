# AI coding guide

Status: active
Last updated: 2026-10-18
Scope: Entry point for AI-assisted development on Envy.
Source of truth: `AGENTS.md`, live GitHub state, and the canonical docs linked below.

## Canonical rules

Root [`AGENTS.md`](../../AGENTS.md) is the single, compact source of truth
for repository-wide rules (about 160 lines, always loaded). Procedures are
skills in `.agents/skills/<name>/SKILL.md`, loaded only when a task needs
them. When policy changes, update `AGENTS.md` or the owning skill first.

## Tool adapters and loading

| Tool | Always loaded | On demand |
| --- | --- | --- |
| Claude Code | `CLAUDE.md` (imports `AGENTS.md`) | skills read via the `AGENTS.md` table; `.cursor/rules` pointers |
| Codex | `AGENTS.md` (32 KiB read limit) | `.agents/skills/` |
| Cursor | `AGENTS.md` | `.cursor/rules/*.mdc` by glob; `.agents/skills/` |
| GitHub Copilot | agents: `AGENTS.md`; code review: `.github/copilot-instructions.md` (first 4,000 chars) | `.agents/skills/` |
| Aider | `AGENTS.md` via `.aider.conf.yml` | - |
| Cline / Windsurf / Continue | pointer files | - |

`.github/scripts/check-agent-config.py` (run in *Lint build files*) keeps
these files small, consistent and pointing at existing paths. The legacy root
`.cursorrules` and `.github/agents/my-agent.md` stay removed.

## Working sequence

Check open PRs and issues touching the same area, make the smallest
compatible change, and validate it with the cheapest relevant checks.
Network/file input is untrusted; protocol changes follow
`.agents/skills/envy-protocol-change/SKILL.md`.

## Canonical context

- [Development plan](../DEVELOPMENT_PLAN.md)
- [Current implementation status](status.md)
- [Architecture](../20_arch/architecture.md)
- [Protocol references](../30_protocols/REFERENCE_IMPLEMENTATIONS.md)
- [Agents and automation](agents-and-automation.md)
- [DevSecOps map](devsecops-envy.md)
