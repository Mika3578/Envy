---
name: envy-code-review
description: Review Envy pull requests against AGENTS.md. Use when reviewing a PR, deciding APPROVED versus CHANGES_REQUESTED, or checking merge-readiness for develop.
---

# Envy pull-request review

Read root `AGENTS.md` before commenting or submitting a review. Do not
duplicate those global rules here.

Copilot Code Review is the **final reviewer**. Other AI comments are
pre-review only. An **approval assessment** ("ready to approve") is not an
`APPROVED` review and does not satisfy Protect develop or the Review
Lifecycle Gate. Submit `APPROVED` only when the gates below hold and
repository Copilot approval settings allow Copilot to approve.

## Risk class

**Low-risk (docs/i18n/adapters):** `docs/**`, `*.mdc`,
`.github/ISSUE_TEMPLATE/**`, `.github/CONTRIBUTING.md`,
`.cursor/**`, `.continue/**`, `.clinerules`, `.windsurfrules`,
`.cursorrules`, `Languages/**`, `CHANGELOG.md`, `MODERNIZATION.md`.

**High-risk review-governance:** `AGENTS.md`,
`.github/copilot-instructions.md`, `.github/skills/**`.

**Default — high-risk code/infra:** every other path, including
`Envy/**`, `HashLib/**`, `Plugins/**`, `Services/**`, `TorrentEnvy/**`,
`Visual Studio/**`, `scripts/**`, `Remote/**`, `Unpacker/**`,
`SkinBuilder/**`, `Repository/**`, `.github/workflows/**`,
`.github/settings.yml`, installer, protocol, crypto, auth, networking,
packet parse, threading, locking, memory, and root build/version files.
Unclassified paths use this class; do not treat them as low-risk.

If **any** changed file is high-risk, treat the whole pull request as
high-risk, **except** comment-only diffs on code/infra paths (not on
review-governance files). Copilot cloud-agent authored PRs: comment and
request a human; do not `APPROVED`.

## Evidence by risk

- **Protocol / packet parse / networking:** a regression or protocol
  comparison, **or** `Wire-format impact: none` when the change cannot
  affect the wire.
- **Crypto, authentication, threading, locking, memory lifetime:**
  targeted tests or an explicit validation of that risk.
  `Wire-format impact: none` is **not** enough.
- **Workflows / `.github/settings.yml` / installer / other code/infra:**
  targeted CI or security validation (required checks green; no secrets,
  permissions, or protection weakening). Wire-format text is not enough.
- **Review-governance:** required CI green, and the diff must not reduce
  required approvals, required checks, Copilot self-approval bans, or
  quality gates. Tightening/clarifying is OK. Weakening is
  `CHANGES_REQUESTED`. Recommended path allowlist excludes these files,
  so Copilot's `APPROVED` does not count unless the allowlist is blank.

## Submit `APPROVED` when all of the following hold

- The pull request is not a draft and is not Copilot-authored.
- Required Protect develop checks are green. If CI is still running, wait.
- No unresolved review threads and no outstanding `CHANGES_REQUESTED`.
- The current HEAD has a completed **final** Copilot cycle: GitHub
  records `copilot-pull-request-reviewer` `APPROVED` on this exact SHA.
  A Copilot, CodeRabbit, Amazon Q, Sourcery, Cubic, or Cursor *comment*
  is not an `APPROVED` review. The
  `copilot-pull-request-reviewer` check success is supporting evidence,
  not a substitute. The `Review Lifecycle Gate` CI check encodes this on
  ready PRs (drafts are skipped). Unresolved threads are enforced by
  Protect develop, not by this CI check. The gate is not a Protect
  develop required context until a maintainer adds it.
- The change does not disable, skip, relabel, or weaken a required
  build/test/static-analysis/security/quality gate.
- Low-risk PRs: docs match the live Protect develop ruleset.
- High-risk PRs: the matching evidence class above is present, and no
  blocking defect exists.
- Do not treat CodeRabbit, Amazon Q, Sourcery, or an approval *assessment*
  as an approval. A Copilot `APPROVED` review is not proof of correctness;
  required CI and security checks stay independent.

## Submit `CHANGES_REQUESTED` when

- A required gate is missing, skipped, or bypassed.
- A blocking defect, unsafe parse, or undocumented wire-format change exists.
- Protocol high-risk change lacks protocol evidence or a justified
  `Wire-format impact: none`.
- Crypto/auth/threading/locking/memory change lacks targeted validation.
- Workflow/infra/settings.yml or other unclassified code/infra change
  lacks targeted CI/security validation.
- Review-governance change weakens merge gates or self-approval bans.
- Branch naming uses a tool/agent prefix (`cursor/`, `claude/`, …).
