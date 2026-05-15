# Repository Cleanup Audit

_Date: 2026-05-15_

## 1) Files/Directories to Keep

- `docs/DEVELOPMENT_PLAN.md` (strategic decisions and long-horizon sequencing)
- `docs/DEV_TRACKER.md` (operational dashboard)
- `docs/10_dev/status.md` (deep protocol comparison and evidence)
- `docs/10_dev/roadmap.md` (technical modernization roadmap)
- `docs/audit/*` (security/architecture/performance/dependency quality history)
- `AGENTS.md`, `CLAUDE.md`, `.cursor/rules/*` (agent and workflow guidance)

## 2) Files/Directories to Consolidate

- Status and tracker duplication between `docs/10_dev/dev-tracker.md`, `docs/STATUS.md`, and plan docs should be redirected toward `docs/DEV_TRACKER.md`.
- Decision-log duplication between legacy index docs and active governance docs should point to `docs/DECISIONS.md`.

## 3) Possibly Obsolete Files

- `docs/10_dev/dev-tracker.md` appears stale and HTML-heavy for current operational use.
- Legacy index variants (for example historical `README_old.md`) may be archival-only.

## 4) Files That Must Not Yet Be Deleted

- Any legacy roadmap/status doc with protocol matrices or implementation evidence.
- Existing audit reports in `docs/audit/`.
- Legacy build/config docs that still describe authoritative VS workflows.

## 5) Suggested Follow-up Cleanup PRs

1. Add redirect banners to stale tracker/status docs.
2. Normalize doc index and remove duplicate navigation paths after validation.
3. Perform dependency register pass with owners/versions.
4. Add protocol parser smoke tests tied to documented risk list.

## 6) Documentation Duplication Analysis

- Current duplication centers on status reporting across multiple docs with inconsistent freshness.
- Canonical split should be:
  - strategy: `docs/DEVELOPMENT_PLAN.md`
  - operations: `docs/DEV_TRACKER.md`
  - deep protocol evidence: `docs/10_dev/status.md`

## 7) Legacy Build/Configuration Analysis

- Visual Studio solution and MSVC `v145` remain authoritative.
- CMake is useful for partial/test workflows but does not yet replace solution builds.
- CI should continue to report these boundaries clearly to avoid false confidence.

## 8) AI-Rules Consistency Analysis

- Core intent aligns across `AGENTS.md`, `CLAUDE.md`, and Cursor rules.
- Gaps addressed in this PR:
  - explicit no-silent-removal rule
  - mandatory changelog/plan/tracker updates for meaningful PRs
  - explicit build-authority/toolchain statements
  - stronger testing/reporting expectations
