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

## Template

### Decision: <short title>
- **Date:** YYYY-MM-DD
- **Status:** proposed | accepted | superseded
- **Context:** What problem are we solving?
- **Decision:** What did we decide?
- **Consequences:** Trade-offs, risks, follow-ups.
- **References:** Links to docs, issues, code paths.
