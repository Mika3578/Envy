# GitHub Copilot instructions for Envy

Root [`AGENTS.md`](../AGENTS.md) is the canonical repository-wide rule set.
Read it before proposing, editing, reviewing, or merging changes. Do not copy
its global rules into this file.

For task context also consult the canonical documents linked by `AGENTS.md`,
especially `docs/DEVELOPMENT_PLAN.md`, `docs/10_dev/status.md`, and the
relevant protocol/architecture docs.

For Copilot Code Review, follow `.github/skills/code-review/SKILL.md`.

- Request Copilot when the pull request is **mergeable** toward `develop`
  (required checks green, up to date, not draft, threads resolved). Re-request
  after each new head once mergeable again.
- When the review finds **no blocking defects** on that head and no
  changed path is review-governance, submit **`APPROVED`** on GitHub —
  not comment-only. If you find blocking issues, request changes; after
  fixes, re-review and **`APPROVED`** when clean and still outside
  review-governance paths.
- Review-governance files (`AGENTS.md`, this file, `.github/skills/**`) are
  high-risk. Do not use the docs-only path for them. Do **not** submit
  `APPROVED` when any of these paths change; require an independent human
  reviewer (`AGENTS.md` hard rule 12). Copilot counting excludes those
  paths.
- `Wire-format impact: none` is not evidence for crypto, auth, threading,
  locking, memory, workflows, or `.github/settings.yml`.
- Never approve a pull request authored by Copilot cloud agent.
- A Copilot `APPROVED` review is not proof of correctness; required CI and
  security checks stay independent.
