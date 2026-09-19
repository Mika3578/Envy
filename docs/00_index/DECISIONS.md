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

## Template

### Decision: <short title>
- **Date:** YYYY-MM-DD
- **Status:** proposed | accepted | superseded
- **Context:** What problem are we solving?
- **Decision:** What did we decide?
- **Consequences:** Trade-offs, risks, follow-ups.
- **References:** Links to docs, issues, code paths.
