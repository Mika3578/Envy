# Decisions (ADR-lite)

Canonical table: [`docs/DECISIONS.md`](../DECISIONS.md).

Use this file to record decisions that affect architecture, protocol compatibility, security posture, or developer workflow.

### Decision: Reference implementation policy
- **Date:** 2026-09-11
- **Status:** accepted
- **ID:** D-008 in `docs/DECISIONS.md`
- **Context:** Several maintained P2P clients are useful for Envy (eMule Community, aMule, eMule Qt, eMule AI, aria2-next, Ember, Rucio, eMule eSE), but they are not equivalent: some are de-facto ED2K/Kad wire references, others are architecture or experimental overlays.
- **Decision:** Specification / BEP / RFC first; live interoperability second; established implementations third; newer implementations fourth; experimental extensions last. Ember/eSE features are never documented as eMule/Kad2. Envy remains multi-network.
- **Consequences:** ED2K/Kad P0 targets eMule Community and aMule. Kad6 and Ember crypto stay P3/P2 research. BitTorrent/G1/G2/DC are preserved.
- **References:** `docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md`, `docs/DEVELOPMENT_PLAN.md`, `docs/10_dev/status.md`.

### Decision: Cross-platform foundations
- **Date:** 2026-09-18
- **Status:** accepted
- **ID:** D-012…D-015 in `docs/DECISIONS.md`
- **Context:** Envy is a Windows MFC monolith; future multi-OS work must not start as a rewrite or claim unsupported platforms.
- **Decision:** Target EnvyCore + platform abstraction + retained MFC Windows frontend. Linux/macOS are **planned** not supported. New EnvyCore APIs avoid MFC/Win32 types. Win32 stays in CI (Stage A). CMake portable slice is foundational; full-app CMake stays low priority.
- **Consequences:** #91/#161/#89 proceed Windows-first under the portability plan; no required Linux/macOS CI until portable code exists; no Win32 removal without evidence.
- **References:** `docs/20_arch/PORTABILITY_PLAN.md`, `docs/ARCHITECTURE.md`.

### Decision: Crash capture engine (BugTrap replacement)
- **Date:** 2026-09-19
- **Status:** accepted (evaluation in progress)
- **ID:** D-017 in `docs/DECISIONS.md`
- **Context:** Issue #90 must replace obsolete BugTrap without a mandatory SaaS. PR #243 prototyped in-process `MiniDumpWriteDump`; that is not strong enough for heap-corruption / stack-overflow / fast-fail.
- **Decision:** Crashpad is the capture engine (local DB, upload off). Sentry Native is Option B only. Isolated `tools/crash-probe` must produce Win32/x64 size and crash-class evidence before root `vcpkg.json` or `Envy.sln` change.
- **Consequences:** Do not merge #243 as the product dumper. Salvage BugTrap deletion and next-launch UX later. No silent telemetry.
- **References:** `docs/10_dev/crashpad-vs-sentry-native.md`, `docs/10_dev/crash-reporting.md`.

## Template

### Decision: <short title>
- **Date:** YYYY-MM-DD
- **Status:** proposed | accepted | superseded
- **Context:** What problem are we solving?
- **Decision:** What did we decide?
- **Consequences:** Trade-offs, risks, follow-ups.
- **References:** Links to docs, issues, code paths.
