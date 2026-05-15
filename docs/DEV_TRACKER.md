# Envy Development Tracker (Operational)

_Last Updated: 2026-05-15_

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
| CI state | Useful but limited by toolchain/runtime matrix constraints |
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
- Consolidating duplicated status/tracker information into this operational dashboard.
- CI signal quality improvements and clearer required-vs-advisory checks.
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

- Current build strategy: Visual Studio solution is authoritative; CMake is supplementary.
- `v145` remains required for authoritative release confidence.
- CI limitations: matrix cannot fully represent all legacy runtime and toolchain conditions.
- Checks posture:
  - Advisory: partial CMake and selected static checks.
  - Required (target state): stable solution build + key tests + security scanning.

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
