# GitHub Copilot instructions for Envy

Root [`AGENTS.md`](../AGENTS.md) is the canonical repository-wide rule set.
Read it before proposing, editing, reviewing, or merging changes. Do not copy
its global rules into this file.

For task context also consult the canonical documents linked by `AGENTS.md`,
especially `docs/DEVELOPMENT_PLAN.md`, `docs/10_dev/status.md`, and the
relevant protocol/architecture docs.

For Copilot Code Review, apply the same safety, interoperability, testing, and
evidence requirements. When the pull request is ready — required checks green,
no unresolved threads, no `CHANGES_REQUESTED`, no weakened quality gates, and
high-risk protocol/crypto/auth/threading/locking/memory changes have evidence
or an explicit `Wire-format impact: none` — submit a GitHub `APPROVED` review
if repository Copilot approval settings allow it. An approval assessment or
comment alone is not sufficient and does not satisfy Protect develop.
