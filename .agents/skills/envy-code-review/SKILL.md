---
name: envy-code-review
description: Review an Envy pull request as a reviewer and choose the GitHub review state (APPROVED, COMMENTED or CHANGES_REQUESTED). Use when asked to review a PR or judge its merge readiness for develop.
---

# Envy pull-request review

Judge the diff against root `AGENTS.md`. Report blocking defects first;
mark nits as optional. Do not repeat findings already answered on the PR.

## Risk class

- **Governance (never bot-only approval):** `AGENTS.md`, `CLAUDE.md`,
  `.agents/**`, `.claude/**`, `.cursor/**`, `.github/copilot-instructions.md`,
  `.github/workflows/**`, `.github/scripts/**`, `.github/rulesets/**`,
  `.github/settings.yml`, review-app configs. Instructions and this skill are
  read from the PR head, so a bot approving a change to them would authorize
  its own rules. Leave `COMMENTED` or `CHANGES_REQUESTED`; a human approves.
- **Low risk:** other `docs/**`, `Languages/**`, `CHANGELOG.md`,
  `.github/ISSUE_TEMPLATE/**`.
- **High risk (default):** everything else, notably `Envy/**`, `HashLib/**`,
  `Plugins/**`, `Services/**`, `Remote/**`, `Installer/**`, build files,
  protocol, packet parsing, crypto, auth, threading, locking, memory.
  One high-risk file makes the PR high-risk; comment-only code diffs do not.

## Evidence required

- Protocol / packet parsing / networking: regression test or protocol
  comparison, or `Wire-format impact: none` when the wire cannot change.
- Crypto, auth, threading, locking, memory lifetime: targeted tests or an
  explicit validation of that risk; `Wire-format impact: none` is not enough.
- Workflows, settings, installer: targeted CI or security validation; no
  secret exposure, permission growth or protection weakening.
- Governance: must not reduce required checks, approvals, self-approval bans
  or quality gates. Tightening or clarifying is fine.

## Review state

- `CHANGES_REQUESTED` when: a required gate is missing, skipped or weakened;
  a blocking defect, unsafe parse or undocumented wire-format change exists;
  required evidence above is missing; a governance change weakens gates; the
  branch uses a tool/agent prefix.
- `APPROVED` only when all hold: not a draft; not authored by a Copilot cloud
  agent; no governance path in the diff; required checks green; no
  unresolved threads; evidence present; Squash Commit Summary matches the
  final head. An approval is not proof of correctness; CI stays independent.
- Otherwise `COMMENTED`.

The live ruleset currently requires zero approvals, so an `APPROVED` from a
bot does not by itself permit a merge; the maintainer still merges. AI
summaries and approval "assessments" are not approvals.
