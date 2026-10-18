---
name: envy-protocol-change
description: Change or review Envy network, protocol, packet parsing, crypto, auth, threading or memory-lifetime code (ED2K/Kad, Gnutella/G2, BitTorrent, DC, Remote, UPnP). Use before editing such code or when choosing the evidence a fix needs.
---

# Envy protocol and security-sensitive changes

## Before editing

1. Find the owning code, its tests (`tests/`, EnvyTests) and `Envy/*Validate*`
   helpers, and open PRs or issues on the same area.
2. Consult sources in this order: specification / RFC / BEP, official docs,
   maintained implementation, reference clients. Envy priorities after the
   specs: eMule Community / aMule (ED2K, Kad), Shareaza lineage (G1/G2),
   BEPs then libtorrent / qBittorrent / Transmission (BitTorrent), DC++ for
   NMDC/ADC only when Envy's DC path is in scope. List:
   `docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md`; per-protocol notes in
   `docs/30_protocols/<protocol>/` (read the relevant section only).
3. Separate what a reference client does from what Envy supports; do not add
   a network or capability because a reference client has it.

## Implementation rules

- Treat every byte from the network, files and Remote as hostile: check
  lengths before reads, use overflow-safe arithmetic for sizes and offsets,
  cap counts, strings, nesting and allocations, and reject malformed input as
  a protocol error without crashing or leaking state.
- Bound queues, buffers, per-peer maps, retries and timeouts; handle partial
  send/recv and transient socket errors; never block the UI thread.
- Never trust remote paths or names: prevent traversal and invalid
  characters.
- Gate new behaviour on capability or version detection; ignore unknown
  fields safely; never assume a fixed layout.
- Keep locking consistent with the surrounding code (`CSingleLock`,
  `CQuickLock`); document ownership for raw pointers.

## Evidence in the PR

- Regression test with boundary and malformed cases for every parser or
  validation fix.
- Protocol or reference comparison for behaviour changes, with divergences
  recorded; otherwise state `Wire-format impact: none` and why.
- Crypto, auth, threading, locking and lifetime changes need targeted tests
  or an explicit validation of that risk; wire-format text does not cover
  them.
- Interoperability claims need a runtime or harness result (for ED2K see
  `.github/workflows/ed2k-interop-harness.yml`); otherwise say it is untested.
