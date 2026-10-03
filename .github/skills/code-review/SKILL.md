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

Maintainers and agents request Copilot Code Review **once** when HEAD is
stable: not a draft, no planned push, required Protect develop checks
green, every current finding treated (inline, overview, Previously missed,
Suppressed, PR-level bodies), review threads resolved, and no outstanding
`CHANGES_REQUESTED`. Do not request Copilot during Draft, while CI is red or
running, or while a correction batch is in progress. Re-request on a **new**
HEAD only after that HEAD is stable again. Copilot review-on-push stays
**off**. Draft Copilot review stays **off**.

The check named `copilot-pull-request-reviewer` is not an approval. Read the
GitHub review: login must be the Copilot reviewer bot, `commit_id` must equal
the current PR HEAD, and `state` must be `APPROVED`.

## Correction agents (must not request reviews in Draft)

Repository correction/stabilizer agents treat review threads and push fix
batches; they **do not** request Copilot Code Review, other review products,
or human reviewers while the pull request is a **draft**, and they do not
approve or merge. Request Copilot only from a maintainer (or one explicit
final step after **Ready**) when `AGENTS.md` §5 is satisfied.

## Review outcome (must use GitHub review state)

- **No blocking findings** on the current head **and** every condition in
  **Submit `APPROVED` when** below is satisfied: submit a real GitHub
  **`APPROVED`** review. Do not stop at overview comments, nit-only threads,
  or a verbal "looks good". GitHub’s default review type is **Comment**; with
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

**Privileged governance (never Copilot-only approval):** `AGENTS.md`,
`.github/copilot-instructions.md`, `.github/skills/**`,
`.github/settings.yml`, `.github/workflows/**`, `.github/rulesets/**`,
and `.github/scripts/` files that classify changes, audit rulesets, or
otherwise define merge/review/CI gate policy. Copilot loads instructions
and this skill from the **PR head**; an `APPROVED` from Copilot on a PR
that edits those files is a self-authorization loop. When **any** such
path changes: do **not** submit `APPROVED` — use `COMMENTED` or
`CHANGES_REQUESTED` and require an independent human (non-Copilot)
approval. Repository Copilot path allowlists must exclude these paths
(`docs/10_dev/devsecops-envy.md`).

**Default — high-risk code/infra:** every other path, including
`Envy/**`, `HashLib/**`, `Plugins/**`, `Services/**`, `TorrentEnvy/**`,
`Visual Studio/**`, `scripts/**`, `Remote/**`, `Unpacker/**`,
`SkinBuilder/**`, `Repository/**`, installer, protocol, crypto, auth,
networking, packet parse, threading, locking, memory, and root
build/version files. Unclassified paths use this class; do not treat
them as low-risk.

If **any** changed file is high-risk, treat the whole pull request as
high-risk, **except** comment-only diffs on code/infra paths (not on
privileged governance files). Copilot cloud-agent authored PRs: comment
and request a human; do not `APPROVED`.

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
- **Privileged governance:** required CI green, and the diff must not
  reduce required approvals, required checks, Copilot self-approval bans,
  or quality gates. Tightening/clarifying is OK. Weakening is
  `CHANGES_REQUESTED`. Copilot must **not** submit `APPROVED` when any
  privileged governance path changes — even if the UI allowlist would
  allow counting — because the skill and instructions are PR-controlled.
  Those PRs need an independent human `APPROVED`. Manual squash merge stays
  required (`AGENTS.md` rule 16).

## Submit `APPROVED` when all of the following hold

- The pull request is not a draft and is not Copilot-authored.
- **No privileged governance path** is in the diff (see Risk class). If any
  is present, stop at `COMMENTED` / `CHANGES_REQUESTED` and require a human.
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
- Privileged governance paths additionally require an independent human
  `APPROVED` on the current HEAD. Copilot must not be the sole counted
  approval on those changes.

## Submit `CHANGES_REQUESTED` when

- A required gate is missing, skipped, or bypassed.
- A blocking defect, unsafe parse, or undocumented wire-format change exists.
- Protocol high-risk change lacks protocol evidence or a justified
  `Wire-format impact: none`.
- Crypto/auth/threading/locking/memory change lacks targeted validation.
- Workflow/infra/settings.yml or other unclassified code/infra change
  lacks targeted CI/security validation.
- Privileged governance change weakens merge gates or self-approval bans.
- Any privileged governance path is in the diff and the only proposed
  counted approval would be Copilot (leave `COMMENTED`; human required).
- Branch naming uses a tool/agent prefix (`cursor/`, `claude/`, …).
