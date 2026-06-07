# Envy Development Tracker (Operational)

_Last Updated: 2026-06-07_

This is the **operational dashboard** for day-to-day execution.

- Strategic decisions and long-horizon priorities: `docs/DEVELOPMENT_PLAN.md`
- Deep protocol comparison and evidence: `docs/10_dev/status.md`
- Technical modernization sequencing: `docs/10_dev/roadmap.md`

## 1) Repository Overview

| Item | Current State |
|---|---|
| Default branch | `develop` |
| Authoritative build path | `Visual Studio/Envy.sln` |
| Toolchain requirement | MSVC `v145` required for authoritative Windows builds |
| CMake status | Partial/non-authoritative (HashLib + selected tests) |
| CI state | v145 matrix **GREEN** on `windows-2025-vs2026` (verified PR #51, #53) |
| Modernization posture | Incremental modernization; compatibility-first |

## 2) Progress Dashboard

- Project modernization: `█████░░░░░` 50%
- Security hardening: `█████░░░░░` 50%
- CI reliability: `█████░░░░░` 50%
- Protocol tests: `██░░░░░░░░` 20%
- Documentation quality: `████████░░` 80%

## 3) Current Status

### Done
- **Phase 0 / PR #35** — Visual Studio 2026 (`v145`) toolset migration, hosted CI on `windows-2025-vs2026`, build-log artifacts, AI governance rules. Merged to `develop`.
- **fix/startup-skin-toolbar-icons** — Removed startup `Toolbar Lookup` / `Failed to load icon` debug-log noise. Added `CSkin::EnsureLoaded()`, deduplicated per-session debug emissions, added debug-only `CSkin::ValidateLoaded()` post-apply sanity check. Added missing `<toolbar name="CLibraryTree.Physical"/>` to `Envy/Res/Default.xml`.
- Canonical strategy baseline established in `docs/DEVELOPMENT_PLAN.md`.
- Protocol gap analysis and comparative audits (`docs/10_dev/status.md`, `docs/audit/*`).
- Core governance docs (README, setup/testing/deployment, contributing).
- CodeQL C# analysis hardening: dedicated manual-build workflow for `SkinUpdater`; legacy FictionBookReader blockers documented in `docs/maintenance/codeql-csharp.md`.
- Documentation consolidation: single source of truth established, stale duplicates removed, all references repointed.

### In Progress
- Dependency ownership visibility and risk classification.
- CI signal quality improvements and clearer required-vs-advisory checks.

### Next
- Build an actionable dependency ownership pass from `docs/DEPENDENCIES.md`.
- Expand protocol parser-focused tests where refactoring boundaries permit.
- Split large modernization efforts into smaller reviewable PR slices.
- Re-enable strict `/permissive-` conformance on hash policy templates.

### Blocked
- No stable hosted GitHub Actions runner guarantees full VS + v145 parity for every scenario.
- Full protocol integration tests remain constrained by legacy coupling.

### Later
- CMake parity expansion once Visual Studio baseline remains stable.
- Broader IPv6 and protocol modernization phases after high-risk gaps close.
- BitTorrent v2 / transport gaps (see `docs/10_dev/roadmap.md`).
- ED2K/Kad opcode and capability gaps with wire-compat tests.

## 4) Protocol Modernization Status

| Protocol Area | Status | Notes |
|---|---|---|
| BitTorrent | Partial | v1 core present; transport/v2 gaps remain |
| ED2K/eMule | Partial | Core interoperability improved; some opcode/feature gaps |
| Kad/Kademlia | Partial | Bootstrap + key flows present; routing hardening gaps |
| Gnutella | Legacy/maintenance | Requires focused validation pass |
| G2 | Legacy/maintenance | Functional but needs refreshed test evidence |
| DC++ | Legacy/maintenance | Limited current validation coverage |
| IPv6 | Partial | Utilities exist; not end-to-end dual-stack |

## 5) Security Status

### Completed hardening
- Security audits and issue logs in `docs/audit/SECURITY_AUDIT.md` and related reports.
- Multiple protocol and remote-surface hardening passes documented in changelog/audit docs.

### Remaining risks
- Parser robustness and malformed packet handling still need deeper automated coverage.
- Legacy components require recurring audit-first reviews before refactors.

### Audit coverage
- Baseline coverage in `docs/audit/*`; not yet a full continuously maintained register.

## 6) CI / Build Status

### Current (2026-06-07)

| Check | Status | Notes |
|---|---|---|
| Build matrix (Win32/x64 × Debug/Release) | **GREEN** | v145 on `windows-2025-vs2026`; `/m:1` for Win32 PCH safety |
| CodeQL C# manual build | PASS | Dedicated workflow for `SkinUpdater` |
| Lint build files | PASS | No legacy `v141_xp` / `v142` outside `Plugins/PluginWizard` |
| Format check (`clang-format`) | PASS | |
| clang-tidy (advisory) | PASS | |
| Dependency review / vcpkg sanity | PASS | Real `builtin-baseline` in manifest |
| YAML / workflow validation | PASS | |

### General

- Current build strategy: Visual Studio solution is authoritative; CMake is supplementary.
- `v145` remains required for authoritative release confidence.
- Hosted runner: `windows-2025-vs2026` (VS 2026 / MSVC 14.5x); build logs uploaded as `build-logs-<platform>-<configuration>` artifacts.
- Checks posture:
  - Advisory: clang-tidy, partial CMake.
  - Required: lint + format + v145 solution build matrix + dependency review.

## 7) Documentation Status

### Canonical docs
- Strategy: `docs/DEVELOPMENT_PLAN.md`
- Operations: `docs/DEV_TRACKER.md` (this file)
- Protocol deep status: `docs/10_dev/status.md`
- Technical roadmap: `docs/10_dev/roadmap.md`

### Missing or weak areas
- Centralized dependency ownership map (seeded in `docs/DEPENDENCIES.md`, needs iteration).
- Centralized known limitations summary (now in `docs/KNOWN_LIMITATIONS.md`).

### Audit completeness
- Good initial coverage in `docs/audit/*`; requires periodic refresh cadence.

## 8) Dependency Status

- Dependency register state: **initial seed only**; not complete.
- Ownership gaps: multiple vendored components lack explicit owner/update cadence.
- Vendored risks: drift, stale patch level, and implicit transitive risk without a full BOM process.

## 9) Next PR Queue

| Order | Branch | Goal | Risk | Status |
|---|---|---|---|---|
| 1 | `docs/dependency-owners-pass-1` | Fill owner/status and update strategy for top vendored libs | Medium | Proposed |
| 2 | `test/protocol-parser-smoke` | Add parser smoke tests for high-risk packet paths | High | Proposed |
| 3 | `ci/v145-signal-clarity` | Clarify required/advisory checks without changing runtime behavior | Medium | Proposed |
| 4 | `docs/protocol-compat-contracts` | Document wire-compat expectations per protocol area | Low | Proposed |
| 5 | `chore/cmake-scope-inventory` | Document CMake parity gaps and boundaries | Low | Proposed |

## 10) Risks / Blockers

- v145 GitHub runner/toolchain availability and parity constraints.
- Incomplete CMake coverage relative to authoritative VS solution.
- Weak automated protocol parser test depth.
- Legacy MFC/UI/core coupling limits isolation and testability.
- Incomplete IPv6 integration across end-to-end networking paths.
