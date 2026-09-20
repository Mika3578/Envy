# GitHub Copilot instructions for Envy

Root [`AGENTS.md`](../AGENTS.md) is the canonical repository-wide rule set.
Read it before proposing, editing, reviewing, or merging changes. Do not copy
its global rules into this file.

For task context also consult the canonical documents linked by `AGENTS.md`,
especially `docs/DEVELOPMENT_PLAN.md`, `docs/10_dev/status.md`, and the
relevant protocol/architecture docs.

For Copilot Code Review, follow `.github/skills/code-review/SKILL.md`.

- Review-governance files (`AGENTS.md`, this file, `.github/skills/**`) are
  high-risk. Do not use the docs-only path for them.
- `Wire-format impact: none` is not evidence for crypto, auth, threading,
  locking, memory, workflows, or `.github/settings.yml`.
- Never approve a pull request authored by Copilot cloud agent.
