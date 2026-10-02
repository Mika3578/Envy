# GitHub Copilot instructions for Envy

Root [`AGENTS.md`](../AGENTS.md) is the canonical repository-wide rule set.
Read it before proposing, editing, reviewing, or merging changes. Do not copy
its global rules into this file.

For task context also consult the canonical documents linked by `AGENTS.md`,
especially `docs/DEVELOPMENT_PLAN.md`, `docs/10_dev/status.md`, and the
relevant protocol/architecture docs.

For Copilot Code Review, follow `.github/skills/code-review/SKILL.md`.

- Do **not** request Copilot Code Review until every review thread on the
  current head is **treated** (`AGENTS.md` §5): fix in code or reply with
  technical justification, then resolve on GitHub. One Copilot request per
  stable treated head — no re-requests while threads are open or between
  partial batches.
- When the review finds **no blocking defects** on that head, submit
  **`APPROVED`** on GitHub — not comment-only. If you find blocking issues,
  request changes; after fixes, re-review and **`APPROVED`** when clean.
- Review-governance files (`AGENTS.md`, this file, `.github/skills/**`) are
  high-risk. Do not use the docs-only path for them. You may submit
  `APPROVED` when `.github/skills/code-review/SKILL.md` gates hold and the
  diff does not weaken merge protections, even when these paths change.
- `Wire-format impact: none` is not evidence for crypto, auth, threading,
  locking, memory, workflows, or `.github/settings.yml`.
- Never approve a pull request authored by Copilot cloud agent.
- A Copilot `APPROVED` review is not proof of correctness; required CI and
  security checks stay independent.
- Minimize cost: see **Model and token economy** in root `AGENTS.md` §8.
- **Review economy:** do not request Copilot to poll status. Treat and resolve
  all threads first; one Copilot review per stable head when
  `AGENTS.md` §5 *Review and Copilot economy* checklist is complete.
