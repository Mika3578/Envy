---
name: envy-code-review
description: Review Envy pull requests against AGENTS.md. Use when reviewing a PR, deciding APPROVED versus CHANGES_REQUESTED, or checking merge-readiness for develop.
---

# Envy pull-request review

Read root `AGENTS.md` before commenting or submitting a review. Do not
duplicate those global rules here.

## Submit `APPROVED` when all of the following hold

- The pull request is not a draft.
- Required Protect develop checks are green (or this review is only an
  assessment and CI is still running — then wait, do not approve early).
- No unresolved review threads and no outstanding `CHANGES_REQUESTED`.
- The change does not disable, skip, relabel, or weaken a required
  build/test/static-analysis/security/quality gate.
- High-risk protocol, crypto, auth, threading, locking, or memory changes
  include a regression/protocol comparison **or** an explicit
  `Wire-format impact: none` in the PR.
- Docs match the live Protect develop ruleset; do not treat CodeRabbit,
  Amazon Q, Sourcery, or an approval *assessment* as an approval.

## Submit `CHANGES_REQUESTED` when

- A required gate is missing, skipped, or bypassed.
- A blocking defect, unsafe parse, or undocumented wire-format change exists.
- Branch naming uses a tool/agent prefix (`cursor/`, `claude/`, …).

If repository Copilot settings allow approvals, an `APPROVED` review is the
required merge-gate signal. An overview assessment without `APPROVED` does
not count.
