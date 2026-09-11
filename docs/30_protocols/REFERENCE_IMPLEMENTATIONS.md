# Reference implementations

Status: active
Last updated: 2026-09-11
Scope: External P2P projects used as interoperability, architecture, and research references for Envy.
Source of truth: protocol specifications first; this document lists complementary implementations. Canonical Envy status is `docs/10_dev/status.md`.

Active reference projects as of 2026. Do not pin Envy documentation to a specific upstream release unless a wire incompatibility requires it.

## Policy

**Specification first, interoperability implementation second.**

Envy remains a **Windows-native multi-network** client. No external project listed here is a replacement for Envy. The goal is to take well-understood behaviour and architecture ideas from each project and adapt them to Envy’s licence, MFC codebase, and existing networks.

Target coverage (descriptive, not a claim of current parity):

- ED2K/Kad behaviour aligned with eMule Community and aMule
- incremental core/UI separation inspired by eMule Qt
- modern reachability ideas from eMule AI
- transfer-engine / API / headless patterns from aria2-next
- DHT/security research ideas from Ember (Envy-specific, never presented as Kad2)
- IPv6/Kad6 experiments from eMule eSE (research only)

Order of trust when sources disagree:

1. Protocol specification / BEP / RFC / ADC
2. Live interoperability evidence (Envy ↔ reference client)
3. Established reference implementation (eMule Community, aMule)
4. Newer maintained implementations (eMule Qt, eMule AI, aria2-next)
5. Experimental extensions (Ember, eMule eSE, proprietary overlays)

Never copy code blindly. Compare behaviour and adapt it to Envy’s architecture and AGPL-3.0-or-later licence. Never treat experimental extensions as part of the eMule/Kad2 standard.

Presence of a feature in a reference project does **not** mean Envy implements it. Envy claims must be backed by Envy code, tests, or an explicitly planned roadmap item.

## Summary

| Project | Role for Envy | Priority | Domains | Status class |
| --- | --- | ---: | --- | --- |
| [eMule Community](https://github.com/irwir/eMule) | De-facto ED2K/Kad wire reference | P0 | ED2K, Kad2, SecureIdent, AICH, credits | normative/reference |
| [aMule](https://github.com/amule-project/amule) | Interop + daemon architecture | P0 | ED2K, Kad, headless, multi-OS | interoperability |
| [eMule Qt](https://github.com/ModderMule/emule-qt) | Modern core/UI split | P1 | daemon, IPC, REST, Web UI | architecture |
| [eMule AI](https://github.com/eMuleAI/eMuleAI) | Modern connectivity | P1 | IPv6, NAT, firewalled peers | architecture |
| [aria2-next](https://github.com/AnInsomniacy/aria2-next) | Multi-protocol engine/API | P1 | ED2K, BitTorrent, RPC, headless | architecture |
| [Ember](https://github.com/untaimed18/Ember-P2P) | Modern DHT/security research | P2 | Noise, Ed25519, BLAKE3, DHT hardening | experimental/R&D |
| [Rucio](https://github.com/ogarcia/rucio) | Modern P2P client architecture | P2 | libp2p, Kademlia, daemon/Web | architecture |
| [eMule eSE](https://github.com/diad87/eMule-eSE-LiveTV) | IPv6/Kad6 research | P3 | IPv6, Kad6, modern NAT | experimental/R&D |

**Rucio** here is [ogarcia/rucio](https://github.com/ogarcia/rucio) (P2P client), not the CERN scientific-data project of the same name.

---

## Official specifications (always preferred)

Code references complement these documents; they do not replace them.

### ED2K

- eDonkey / eMule protocol description: Kulbak & Bickson, *The eMule Protocol Specification* (commonly cited from the aMule protocol wiki)
- aMule ED2K protocol wiki: <https://wiki.amule.org/wiki/Ed2k_protocol>
- aMule ED2K overview: <https://amule-org.github.io/docs/p2p-networks/ed2k>
- ED2K URI / link specification: <https://wiki.amule.org/wiki/Ed2k_link>
- Historical behaviours not fully specified (credits, SecureIdent RSA, Source Exchange edge cases, HighID/LowID) may require eMule Community / aMule source as de-facto clarification

### Kad

- Maymounkov & Mazières, *Kademlia: A Peer-to-peer Information System Based on the XOR Metric*: <https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf>
- Kad2 opcodes, contacts, publish/search, firewall check, and Buddy behaviour: eMule Community / aMule Kad sources, used only to fill gaps in written Kad documentation
- NAT traversal: document and compare historically; do not assume later experimental NAT schemes are Kad2

### BitTorrent

- BEP index: <https://www.bittorrent.org/beps/bep_0000.html>
- Especially: BEP 3 (v1), BEP 5 (DHT), BEP 6 (Fast Extension), BEP 9 (magnet), BEP 10 (LTEP), BEP 11 (PEX), BEP 15 (UDP tracker), BEP 29 (uTP), BEP 32 (IPv6 DHT), BEP 52 (v2)

### Gnutella / Gnutella2

- Historical Gnutella 0.6 draft: <http://rfc-gnutella.sourceforge.net/src/rfc-0_6-draft.html>
- Gnutella2 / Shareaza protocol notes and Shareaza-lineage code (Envy’s G1/G2 stack is Shareaza-derived)
- Preserve G1 and G2; they are not deprecated by ED2K work

### Direct Connect

- NMDC: <https://nmdc.sourceforge.net/NMDC.html>
- ADC: <https://adc.sourceforge.io/ADC.html>
- ADC-EXT: <https://adc.sourceforge.io/ADC-EXT.html>

---

## Project notes

### eMule Community — P0, normative/reference

- **URL:** <https://github.com/irwir/eMule>
- **Role:** Primary wire-compatibility reference for ED2K and Kad2.
- **Reuse as ideas:** Hello/MuleInfo, userhash, ClientID, HighID/LowID, callbacks, capability bits, compression, multipacket, search, Source Exchange, AICH, credits, Kad2 bootstrap/routing/search/publish, firewall check, Buddy, historical NAT traversal, and the real RSA SecureIdent protocol.
- **Do not copy blindly:** Windows/MFC structure, credit-system policy, UI, and any local mods. Adapt packet semantics to Envy’s existing engines.
- **Status class:** normative/reference for ED2K/Kad2 behaviour. Still second to written specs where those exist.

### aMule — P0, interoperability

- **URL:** <https://github.com/amule-project/amule>
- **Role:** Second live interop target and a daemon/GUI/Web/CLI architecture reference.
- **Reuse as ideas:** ED2K/Kad interop tests (Envy ↔ aMule), HighID/LowID, callbacks, source exchange, headless `amuled` + remote GUI/Web/CLI split, cross-platform behaviour notes.
- **Do not copy blindly:** wxWidgets/GTK specifics, aMule External Connections protocol as a drop-in Envy API, or Linux-only assumptions.
- **Status class:** interoperability (and architecture for headless).

Expected live interop (planned, not currently claimed): Envy ↔ eMule Community, Envy ↔ aMule, and ideally eMule ↔ Envy ↔ aMule.

### eMule Qt — P1, architecture

- **URL:** <https://github.com/ModderMule/emule-qt>
- **Role:** Incremental engine/GUI decoupling: daemon, IPC, Web UI, REST.
- **Reuse as ideas:** `EnvyCore` → protocol engines → transfer engine → library/search → stable internal API/IPC → MFC frontend, with later Web/CLI frontends. Incremental migration only; no rewrite.
- **Do not copy blindly:** Qt, a new IPC schema, or a big-bang extraction of Envy into a separate process.
- **Status class:** architecture.

### eMule AI — P1, architecture (prospective connectivity)

- **URL:** <https://github.com/eMuleAI/eMuleAI>
- **Role:** Secondary/prospective technical reference for modern reachability on an eMule-derived base.
- **Reuse as ideas:** IPv6, dual-stack, NAT traversal, firewalled/LowID behaviour. Evaluate any mature modern transports only if they are actually present and proven; do not assume QUIC or uTP.
- **Do not copy blindly:** Experimental transports, AI-related branding, or protocol changes that would break eMule Community/aMule interop. This is not a normative ED2K source.
- **Status class:** architecture / prospective.

### aria2-next — P1, architecture

- **URL:** <https://github.com/AnInsomniacy/aria2-next>
- **Role:** Modern download engine with BitTorrent, ED2K, session persistence, CLI, and JSON-RPC.
- **Reuse as ideas:** transfer-engine modernization, RPC/headless API, automated transfer tests, Kad bootstrap notes, session persistence.
- **Do not copy blindly:** aria2 option names, JSON-RPC as a mandatory Envy surface, or dropping Envy’s multi-network UI/library.
- **Status class:** architecture (useful for ED2K *and* BitTorrent validation).

### Ember — P2, experimental/R&D

- **URL:** <https://github.com/untaimed18/Ember-P2P>
- **Role:** Modern Rust ED2K/Kad *experiment*: Noise, Ed25519, BLAKE3, anti-amplification, DHT hardening, firewalled-node handling.
- **Reuse as ideas:** routing-table diversity, subnet limits, anti-amplification, stronger node verification — only as Envy-specific optional research, versioned and backward compatible.
- **Do not copy blindly:** Proprietary overlay crypto or record formats. **Ember extensions are not part of the eMule/Kad2 standard** and must never be documented as such.
- **Status class:** experimental/R&D.

### Rucio (ogarcia/rucio) — P2, architecture

- **URL:** <https://github.com/ogarcia/rucio>
- **Role:** Modern Rust P2P client: daemon + CLI + Web panel, libp2p Kademlia, distributed search, optional eMule/Kad2 bridge.
- **Reuse as ideas:** daemon/CLI/Web layout, search UX over a protocol engine, how a Kad2 bridge can sit beside a modern overlay.
- **Do not copy blindly:** libp2p as a replacement for Kad2, or treating the Kad2 bridge as the ED2K spec.
- **Status class:** architecture. Not an ED2K normative source.

### eMule eSE — P3, experimental/R&D

- **URL:** <https://github.com/diad87/eMule-eSE-LiveTV>
- **Role:** R&D on IPv6, experimental Kad6, modern NAT (PCP / NAT-PMP if present). Not a P0 target.
- **Reuse as ideas:** strict separation of Kad2 from IPv6 extensions; dual-stack lessons after Envy IPv6 is stable.
- **Do not copy blindly:** Kad6, LiveTV, or any overlay that would mix with Kad2 contacts. Kad6 must stay distinct from Kad2.
- **Status class:** experimental/R&D.

---

## Related Envy documents

- Strategic sequence: `docs/DEVELOPMENT_PLAN.md`
- Feature status matrix: `docs/10_dev/status.md`
- Technical roadmap: `docs/10_dev/roadmap.md`
- Decision: `docs/DECISIONS.md` (D-008)
- ED2K: `docs/30_protocols/ed2k/`
- Kad: `docs/30_protocols/kad/`
- BitTorrent: `docs/30_protocols/bittorrent/`
- IPv6 plan: `docs/ipv6/PLAN.md`
