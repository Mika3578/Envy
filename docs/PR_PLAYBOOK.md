# PR Playbook

Use this playbook to keep PRs small, reviewable, and operationally safe.

## Global Expectations (All PR Types)

- One logical change area per PR.
- Report:
  - testing performed
  - testing not performed
  - environment limitations
- Never silently remove tests, coverage, workflows, docs, artifacts, or legacy files.
- Update `CHANGELOG.md` under `[Unreleased]` for release/user-visible
  behavior. Docs/rules/CI-only PRs may skip it when the PR states why
  and still updates `docs/DEVELOPMENT_PLAN.md` for strategic scope.
- Update `docs/DEVELOPMENT_PLAN.md` for strategic/scope decisions.
- Record session notes in `.local/DEV_TRACKER.md` (gitignored).

## Git sync

Use `.github/CONTRIBUTING.md` as the canonical source for the linear-history workflow and exact `git fetch` / `git rebase origin/develop` / `git push --force-with-lease` commands.

## PR finalization (before squash merge to `develop`)

Canonical policy: [`docs/10_dev/pr-workflow.md`](10_dev/pr-workflow.md) and
[`AGENTS.md`](../AGENTS.md). Use the PR title as the squash title; keep the PR
description current (audit record). Required CI green, threads resolved, no
active changes requested. A real non-author approval remains mandatory.
The maintainer performs a manual squash merge with the curated Squash Commit
Summary; do not enable auto-merge while that body must be supplied manually.

## Documentation PR Checklist

### Testing expectations
- Verify Markdown renders cleanly in GitHub preview.
- Run link validation tooling if available.

### Documentation expectations
- Ensure canonical doc references are updated.
- Avoid duplicate status blocks; link to canonical source.

### Risk review expectations
- Confirm no workflow/runtime behavior changes were introduced accidentally.

## CI PR Checklist

### Testing expectations
- Validate changed workflows/jobs with at least one representative run.
- Capture required vs advisory check impact.
- Draft PRs without `stage:live-test` stay on the cheap lane (Windows product
  builds deferred by `pr-phase` / classify — intentional, not missing CI).
  That deferral is not build evidence. Every live-test or Ready PR runs actual
  x64 and Win32 Release builds and EnvyTests, including docs-only PRs.
  See `docs/10_dev/pr-workflow.md`.

### Documentation expectations
- Update build/CI sections in relevant docs (`README.md`, `docs/DEVELOPMENT_PLAN.md`).

### Risk review expectations
- Preserve validation capability unless intentionally moved and documented.
- Call out branch protection and merge-gate implications.

## Security PR Checklist

### Testing expectations
- Add/adjust regression tests where feasible.
- Validate both positive and malformed input cases.

### Documentation expectations
- Update security audit/tracker references.
- Record remaining risk and follow-up actions.

### Risk review expectations
- Explicitly list compatibility and performance implications.
- Prefer audit-first approach for high-risk areas.

## Protocol PR Checklist

### Testing expectations
- Run protocol-specific unit/integration checks available in scope.
- Document wire-level verification strategy.

### Documentation expectations
- Update protocol status and roadmap docs.
- Add compatibility notes for any behavior-facing changes.

### Risk review expectations
- Preserve wire compatibility unless explicitly documented.
- Identify interop risk with reference clients.

## Refactor PR Checklist

### Testing expectations
- Run nearest test/build suite for touched components.
- Report unchanged behavior intent and verification depth.

### Documentation expectations
- Update plan/tracker/changelog if scope or sequencing changes.

### Risk review expectations
- Avoid broad refactors without explicit approved scope.
- Highlight rollback strategy for risky changes.
