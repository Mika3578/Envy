# Envy Development Tracker (Operational)

_Last Updated: 2026-05-17_

This is the **operational dashboard** for day-to-day execution.

- Strategic decisions and long-horizon priorities: `docs/DEVELOPMENT_PLAN.md`
- Deep protocol comparison and evidence: `docs/10_dev/status.md`
- Technical modernization sequencing: `docs/10_dev/roadmap.md`

## 1) Repository Overview

| Item | Current State |
|---|---|
| Default branch | `develop` _(repository settings are authoritative; if `.github/settings.yml` still specifies `master`, treat that file as stale until it is updated)_ |
| Authoritative build path | `Visual Studio/Envy.sln` |
| Toolchain requirement | MSVC `v145` required for authoritative Windows builds |
| CMake status | Partial/non-authoritative (HashLib + selected tests) |
| CI state | PR #35 (`claude/code-audit-modernization-nJcTT`) rebased on `develop`; v145 matrix on `windows-2025-vs2026` pending green run |
| Modernization posture | Incremental modernization; compatibility-first |

## 2) Progress Dashboard

- Project modernization: `████░░░░░░` 40%
- Security hardening: `█████░░░░░` 50%
- CI reliability: `███░░░░░░░` 30%
- Protocol tests: `██░░░░░░░░` 20%
- Documentation quality: `███████░░░` 70%

## 3) Current Status

### Done
- Canonical strategy baseline established in `docs/DEVELOPMENT_PLAN.md`.
- Protocol gap analysis and comparative audits exist (`docs/10_dev/status.md`, `docs/audit/*`).
- Core governance docs exist (README, setup/testing/deployment, contributing).

### In Progress
- **Phase 0 / PR #35** — Visual Studio 2026 (`v145`) toolset migration, hosted CI on `windows-2025-vs2026`, build-log artifacts, AI rules (target base: `develop`).
- Consolidating duplicated status/tracker information into this operational dashboard.
- CI signal quality improvements and clearer required-vs-advisory checks.
- CodeQL C# analysis quality hardening: moved from `build-mode: none` to dedicated manual-build workflow and documented legacy C# blockers.
- Dependency ownership visibility and risk classification.

### Next
- Build an actionable dependency ownership pass from `docs/DEPENDENCIES.md`.
- Expand protocol parser-focused tests where refactoring boundaries permit.
- Split large modernization efforts into smaller reviewable PR slices.

### Blocked
- No stable hosted GitHub Actions runner guarantees full VS + v145 parity for every scenario.
- Full protocol integration tests remain constrained by legacy coupling.

### Later
- CMake parity expansion once Visual Studio baseline remains stable.
- Broader IPv6 and protocol modernization phases after high-risk gaps close.

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
- Security audits and issue logs exist in `docs/audit/SECURITY_AUDIT.md` and related reports.
- Multiple protocol and remote-surface hardening passes are documented in changelog/audit docs.

### Remaining risks
- Parser robustness and malformed packet handling still need deeper automated coverage.
- Legacy components require recurring audit-first reviews before refactors.

### Audit coverage
- Baseline coverage exists (`docs/audit/security*`, `docs/audit/SECURITY_AUDIT.md`) but is not yet a full continuously maintained register.

## 6) CI / Build Status

### PR #35 (`claude/code-audit-modernization-nJcTT`) — 2026-05-17

| Check | Last known result (pre-rebase push) | Notes |
|---|---|---|
| CodeQL C# manual build | **Updated** | Dedicated `.github/workflows/codeql-csharp.yml` now uses manual build for `SkinUpdater`; legacy FictionBookReader blockers documented in `docs/maintenance/codeql-csharp.md`. |
| Lint build files | PASS | No legacy `v141_xp` / `v142` outside `Plugins/PluginWizard` |
| Format check (`clang-format`) | PASS | |
| clang-tidy (advisory) | PASS | |
| Dependency review / vcpkg sanity | PASS | Real `builtin-baseline` in manifest |
| Build matrix (Win32/x64 × Debug/Release) | **Partial** | x64 Debug/Release green on run `25993019518`; Win32 hit PCH lock (`C1083`); CI uses `/m:1` for Win32 |
| YAML / workflow validation | PASS | Workflows lint clean |

**Compile errors fixed in this session (C++20 / v145 blockers):**

- `Envy/CoolInterface.h` — `TOOLBAR_RES`: named `struct` (fixes C7626 anonymous struct with member function).
- `Envy/Connection.h` — `TCPBandwidthMeter`: named nested `struct` (same C7626).
- `Envy/HostCache.h`, `Envy/FragmentedFile.h`, `Envy/DownloadSource.h`, `Envy/CtrlLibraryTileView.h` — removed deprecated `std::binary_function` / `std::unary_function` bases; `throw()` → `noexcept` where touched.
- `Envy/HostCache.h` / `Envy/FragmentedFile.h` — restored `first_argument_type` / `second_argument_type` / `result_type` for `std::bind2nd` predicates.
- `Envy/Buffer.h` — `Read()` declaration aligned to `noexcept` definition.
- `Envy/Envy.cpp` — disabled taskbar block that referenced missing `CJumpList` wrapper (local **Release x64** build verified).
- Prior PR commits (already on branch): `HashLib/Utility.hpp` semicolon; `Envy/Strings.h` / `Envy/StdAfx.h` comparators; `CTimeAverage` range-for; `GetFileSize` ternary; `/permissive` on first-party projects for `Envy/Hashes/*` two-phase lookup.

**Remaining blockers (post-fix):**

- Win32 matrix jobs: verify green after `/m:1` PCH workaround in `build.yml`.
- Phase 2 follow-up: add `this->` in `Envy/Hashes/*` policy templates and re-enable strict `/permissive-` on first-party projects.
- Plugin projects still on `stdcpp17`; main app on `stdcpp20` — intentional Phase 0 split.

**Next Phase 1 tasks (after Phase 0 merge):**

- BitTorrent v2 / transport gaps (see `docs/10_dev/roadmap.md`).
- ED2K/Kad opcode and capability gaps with wire-compat tests.
- Re-enable strict conformance on hash policy templates.
- Dependency ownership pass (`docs/DEPENDENCIES.md`).

### General

- Current build strategy: Visual Studio solution is authoritative; CMake is supplementary.
- `v145` remains required for authoritative release confidence.
- Hosted runner: `windows-2025-vs2026` (VS 2026 / MSVC 14.5x); build logs uploaded as `build-logs-<platform>-<configuration>` artifacts.
- Checks posture:
  - Advisory: clang-tidy, partial CMake.
  - Required (Phase 0 target): lint + format + v145 solution build matrix + dependency review.

## 7) Documentation Status

### Canonical docs
- Strategy: `docs/DEVELOPMENT_PLAN.md`
- Operations: `docs/DEV_TRACKER.md`
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
| 2 | `tests/protocol-parser-smoke` | Add parser smoke tests for high-risk packet paths | High | Proposed |
| 3 | `ci/v145-signal-clarity` | Clarify required/advisory checks without changing runtime behavior | Medium | Proposed |
| 4 | `docs/protocol-compat-contracts` | Document wire-compat expectations per protocol area | Low | Proposed |
| 5 | `build/cmake-scope-inventory` | Document CMake parity gaps and boundaries | Low | Proposed |

## 10) Risks / Blockers

- v145 GitHub runner/toolchain availability and parity constraints.
- Incomplete CMake coverage relative to authoritative VS solution.
- Weak automated protocol parser test depth.
- Legacy MFC/UI/core coupling limits isolation and testability.
- Incomplete IPv6 integration across end-to-end networking paths.
