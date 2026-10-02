---
name: envy-code-review
description: Review Envy pull requests against AGENTS.md. Use when reviewing a PR, deciding APPROVED versus CHANGES_REQUESTED, or checking merge-readiness for develop.
---

# Envy pull-request review

Read root `AGENTS.md` before commenting or submitting a review. Do not
duplicate those global rules here.

An **approval assessment** ("ready to approve") is not an `APPROVED` review
and does not satisfy Protect develop. Submit `APPROVED` only when the
gates below hold and repository Copilot approval settings allow it.

## When to run (request timing)

Maintainers and agents request Copilot Code Review only when the pull
request is **mergeable** toward `develop` (**not a draft** — no agent or
maintainer review request in Draft; cheap CI and thread treatment only,
required Protect
develop checks green, branch up to date with `develop`, no outstanding
`CHANGES_REQUESTED` that still applies) **and every review comment thread
on the current head is treated** (`AGENTS.md` §5 *Review comment
handling*: fix or justified reply, then resolve on GitHub). Request **one**
Copilot review on that stable head — not while untreated threads remain and
not after every partial fix batch (Copilot review-on-push stays off in
Protect develop by design). Re-request only when a **new head** requires it
and treatment is complete again.

## Correction agents (must not request reviews in Draft)

Repository correction/stabilizer agents treat review threads and push fix
batches; they **do not** request Copilot Code Review, other review products,
or human reviewers while the pull request is a **draft**, and they do not
approve or merge. Request Copilot only from a maintainer (or one explicit
final step after **Ready**) when `AGENTS.md` §5 *Review and Copilot economy*
pre-request checklist is satisfied.

## Review outcome (must use GitHub review state)

- **No blocking findings** on the current head and the gates in
  **Submit `APPROVED` when** below all hold: submit **`APPROVED`**. Do not
  stop at overview comments, nit-only threads, or a verbal "looks good" when
  nothing blocking remains. GitHub’s default review type is **Comment**; with
  repository **Auto-approval** enabled, Copilot must leave an **`Approve`**
  review event on GitHub, not only the overview **approval assessment** (see
  [GitHub Docs — Pull request approvals from Copilot](https://docs.github.com/en/copilot/how-tos/agents/copilot-code-review/using-copilot-code-review#pull-request-approvals-from-copilot)).
- **Blocking findings:** submit **`CHANGES_REQUESTED`** and/or actionable
  inline comments. Do not **`APPROVED`** until they are fixed or explicitly
  withdrawn and mergeability returns; then re-review and **`APPROVED`** when
  clean.

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
  `CHANGES_REQUESTED`. Copilot may submit `APPROVED` when these gates hold
  and repository Copilot settings allow counting on the changed paths.

## Submit `APPROVED` when all of the following hold

- The pull request is not a draft and is not Copilot-authored.
- Required Protect develop checks are green. If CI is still running, wait.
- No unresolved review threads and no outstanding `CHANGES_REQUESTED`.
- Squash Commit Summary in the PR body matches the final head and satisfies
  `AGENTS.md` rule 16 (issue reference + concise bullets; no process-only text).
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
