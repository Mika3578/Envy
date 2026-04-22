# DEVELOPMENT PLAN (LIVING)

> **LIVING DOCUMENT** — Must be updated after every meaningful change (feature, architectural decision, scope change, blocker resolution).

- **Last Updated:** 2026-04-22
- **Changelog Entry:** 2026-04-22 — Initial comprehensive planning baseline established during documentation and audit pass.

## Update Protocol
1. Update **Last Updated** date on every meaningful change.
2. Add a one-line entry to the changelog section above.
3. Reflect status changes in **Current Status** and **Roadmap**.
4. Record consequential technical decisions in **Decisions Log**.
5. Close or refresh **Open Questions** explicitly.

## Vision & Goals
- Maintain Envy as a stable multi-network P2P client for Windows.
- Reduce modernization risk by improving testability and dependency hygiene.
- Increase release confidence through clearer architecture boundaries and measurable quality gates.

## Current Status
### Done
- CI workflows for build/quality/security exist.
- Hash-focused unit tests integrated in repo and workflows.
- Audit and core documentation baseline established.

### In Progress
- C++ modernization across legacy modules.
- Incremental protocol compatibility and robustness improvements.

### Blocked / At Risk
- Full CMake parity with Visual Studio build graph.
- Dependency refresh for older vendored components without regressions.

## Roadmap

### Phase 1 — Stability & Visibility (P0)
- [ ] Create dependency register + ownership map (2d)
- [ ] Add threat model and secure-coding checklist (2d)
- [ ] Expand tests for protocol parser/state-machine paths (5d)
- [ ] Establish baseline metrics (startup, memory, throughput) (3d)

### Phase 2 — Build/Quality Convergence (P1)
- [ ] Define CMake migration boundary and milestones (3d)
- [ ] Reduce duplicated CI workflow logic (2d)
- [ ] Promote selected static-analysis checks to required gates (2d)

### Phase 3 — Architecture Hardening (P2)
- [ ] Isolate core transfer engine interfaces from UI classes (10d)
- [ ] Version plugin-facing APIs and compatibility policy (5d)
- [ ] Create automated dependency/SBOM release artifact (3d)

## Backlog
- Replace unsafe string operations in first-party code
- Consolidate duplicate roadmap/status markdown into canonical set
- Document remote API implementation status endpoint-by-endpoint
- Add long-running memory/regression test scenario
- Archive legacy `.vcproj` files once migration is complete

## Decisions Log
- **2026-04-22:** Keep Visual Studio solution as authoritative full-build path while CMake remains partial.
- **2026-04-22:** Standardize new audit reports under `docs/audit/`.
- **2026-04-22:** Treat this plan as a required living artifact for project management continuity.

## Open Questions
1. Should this project explicitly remain Windows-only, or is cross-platform parity still a target?
2. What is the acceptable backward-compatibility policy for legacy protocols/features?
3. Which dependency update cadence (monthly/quarterly) is realistic for maintainers?
4. Should remote API documentation be strict contract-first or implementation-first?
