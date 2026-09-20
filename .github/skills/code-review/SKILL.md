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
`.github/ISSUE_TEMPLATE/**`, `.github/skills/**`,
`.github/copilot-instructions.md`, `.github/CONTRIBUTING.md`,
`.cursor/**`, `.continue/**`, `.clinerules`, `.windsurfrules`,
`.cursorrules`, `Languages/**`, `AGENTS.md`, `CLAUDE.md`.

**High-risk:** `Envy/**`, `HashLib/**`, `Plugins/**`, `Services/**`,
`TorrentEnvy/**`, `.github/workflows/**`, `.github/settings.yml`,
installer/infra, protocol, crypto, auth, networking, packet parse,
threading, locking, memory.

If **any** changed file is high-risk, treat the whole pull request as
high-risk, **except** when the high-risk file's actual diff is comments
or documentation only (assess that file on the diff, not the path).
Copilot cloud-agent authored PRs: comment and request a human; do not
`APPROVED` (no self-approval).

## Evidence by risk

- **Protocol / C++ / crypto / networking:** a regression or protocol
  comparison, **or** an explicit `Wire-format impact: none`.
- **Workflows / `.github/settings.yml` / installer / infra:** targeted
  CI or security validation for that change (required checks still
  green; no secrets, permissions, or protection weakening).
  `Wire-format impact: none` does **not** satisfy this class.

## Submit `APPROVED` when all of the following hold

- The pull request is not a draft and is not Copilot-authored.
- Required Protect develop checks are green. If CI is still running, wait.
- No unresolved review threads and no outstanding `CHANGES_REQUESTED`.
- The change does not disable, skip, relabel, or weaken a required
  build/test/static-analysis/security/quality gate.
- Low-risk PRs: docs match the live Protect develop ruleset.
- High-risk PRs: the matching evidence class above is present, and no
  blocking defect exists.
- Do not treat CodeRabbit, Amazon Q, Sourcery, or an approval *assessment*
  as an approval.

## Submit `CHANGES_REQUESTED` when

- A required gate is missing, skipped, or bypassed.
- A blocking defect, unsafe parse, or undocumented wire-format change exists.
- Protocol/C++ high-risk change lacks protocol evidence or
  `Wire-format impact: none`.
- Workflow/infra/settings.yml high-risk change lacks targeted CI/security
  validation (wire-format text is not enough).
- Branch naming uses a tool/agent prefix (`cursor/`, `claude/`, …).
