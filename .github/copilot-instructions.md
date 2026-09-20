# GitHub Copilot instructions for Envy

Root [`AGENTS.md`](../AGENTS.md) is the canonical repository-wide rule set.
Read it before proposing, editing, reviewing, or merging changes. Do not copy
its global rules into this file.

For task context also consult the canonical documents linked by `AGENTS.md`,
especially `docs/DEVELOPMENT_PLAN.md`, `docs/10_dev/status.md`, and the
relevant protocol/architecture docs.

For Copilot Code Review, follow `.github/skills/code-review/SKILL.md`.

- An approval **assessment** is not an `APPROVED` review and does not satisfy
  Protect develop.
- Approve low-risk docs/rules/i18n/skills PRs when required checks are green
  and there is no blocking defect.
- Treat any C++/protocol/workflow/infra change as high-risk: approve only with
  evidence or `Wire-format impact: none`; otherwise request changes.
- Never approve a pull request authored by Copilot cloud agent.
