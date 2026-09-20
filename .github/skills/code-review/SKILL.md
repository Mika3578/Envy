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

## Risk class

**Low-risk (docs/rules/i18n/skills):** `docs/**`, `*.md`, `*.mdc`,
`.github/ISSUE_TEMPLATE/**`, `.github/skills/**`, `.github/settings.yml`,
`.github/copilot-instructions.md`, `.github/CONTRIBUTING.md`,
`.cursor/**`, `.continue/**`, `.clinerules`, `.windsurfrules`,
`.cursorrules`, `Languages/**`, `AGENTS.md`, `CLAUDE.md`.

**High-risk:** `Envy/**`, `HashLib/**`, `Plugins/**`, `Services/**`,
`TorrentEnvy/**`, `.github/workflows/**`, installer/infra, protocol,
crypto, auth, networking, packet parse, threading, locking, memory.

If **any** changed file is high-risk, treat the whole pull request as
high-risk. Copilot cloud-agent authored PRs: comment and request a human;
do not `APPROVED` (no self-approval).

## Submit `APPROVED` when all of the following hold

- The pull request is not a draft and is not Copilot-authored.
- Required Protect develop checks are green. If CI is still running, wait.
- No unresolved review threads and no outstanding `CHANGES_REQUESTED`.
- The change does not disable, skip, relabel, or weaken a required
  build/test/static-analysis/security/quality gate.
- Low-risk PRs: docs match the live Protect develop ruleset.
- High-risk PRs: a regression/protocol comparison **or** an explicit
  `Wire-format impact: none` is in the PR, and no blocking defect exists.
- Do not treat CodeRabbit, Amazon Q, Sourcery, or an approval *assessment*
  as an approval.

## Submit `CHANGES_REQUESTED` when

- A required gate is missing, skipped, or bypassed.
- A blocking defect, unsafe parse, or undocumented wire-format change exists.
- High-risk change lacks evidence / `Wire-format impact: none`.
- Branch naming uses a tool/agent prefix (`cursor/`, `claude/`, …).
