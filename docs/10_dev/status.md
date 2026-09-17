# Envy implementation status

Status: active
Last updated: 2026-09-15
Scope: Evidence-based protocol and architecture status for Envy on `develop`.
Source of truth: Envy source under `Envy/`, tests under `tests/`, and the documents linked below. External projects are references only.

This is the canonical **status matrix**. Roadmap sequencing lives in `docs/DEVELOPMENT_PLAN.md` and `docs/10_dev/roadmap.md`. External references live in `docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md`.

Envy is a **Windows-native multi-network** client (BitTorrent, Gnutella, Gnutella2, ED2K, Kad, Direct Connect, Remote/Web, library and multi-network search). ED2K/Kad interop work must not turn Envy into an eMule-only client.

## Status vocabulary

Use these terms only:

| Term | Meaning |
| --- | --- |
| implemented | Present in Envy code and believed to function for the stated scope |
| partial | Some of the feature exists; important pieces are missing or IPv4-only / library-only |
| unverified | Code or opcodes exist, but live interoperability is not demonstrated |
| planned | Explicitly on the roadmap; not implemented |
| not implemented | Absent, or deliberately disabled |
| experimental | Research-only; not a compatibility target |

Avoid “complete” / “fully compatible” unless live interop evidence exists. Opcode or struct matching is **not** live interoperability. A Hello capability bit is **not** proof of implementation.

## Feature matrix

| Function | Envy current | Reference | Target |
| --- | --- | --- | --- |
| ED2K basic interop | partial / unverified live | eMule Community, aMule | implemented (full baseline) |
| Kad2 | partial / unverified live | eMule Community, aMule | interoperable |
| SecureIdent RSA | not implemented | eMule Community (secondary: aMule) | implemented |
| IPv6 | partial | eMule AI, eMule Qt, eMule eSE | dual-stack |
| Headless daemon | not implemented | aMule, eMule Qt, aria2-next | planned |
| REST / JSON-RPC | partial (Remote web UI) | eMule Qt, aria2-next | planned |
| BitTorrent v1 | implemented | BEPs, aria2-next, libtorrent | preserve / extend |
| BitTorrent v2 | partial | BEP 52, aria2-next | implemented |
| Gnutella (G1) | implemented | Envy / Shareaza lineage | preserve |
| Gnutella2 (G2) | implemented | Envy / Shareaza lineage | preserve |
| Direct Connect (NMDC) | implemented | NMDC, Shareaza, DC++ | preserve |
| Direct Connect (ADC/ADCS) | not implemented | ADC / ADC-EXT, EiskaltDC++ | planned (separate layer) |
| uTP (BEP 29) | not implemented | BEP 29, aria2-next | planned |
| Kad6 / next overlay | not implemented | eMule eSE (R&D only) | experimental (P3) |

## Evidence notes

### ED2K

- Handshake, transfer, Source Exchange v1/v2, large-file I64 packets, and many eMule opcodes are present in `Envy/EDClient.cpp` / `Envy/EDPacket.h`.
- Source Exchange remains **IPv4-only on-wire** (`docs/30_protocols/ed2k/SOURCE_EXCHANGE_INTEROP_NOTES.md`).
- Capability advertisement rule: Envy must advertise an eMule capability only when it is implemented and tested (`docs/DEVELOPMENT_PLAN.md`). Helpers live in `Envy/Ed2kHelloCapabilities.h` / `Envy/SecureIdentPolicy.h`.
- Honest-by-default Hello bits (advertise 0 until wired): AICH, SecureIdent, CryptLayer MiscOptions2 (TCP obfuscation unimplemented — `#121`; Hello bits must not start PUBLICKEY packet crypto), and Ext Multipacket (MiscOptions2 bit 5, `#129`, `Ed2kExtMultipacketAdvertised()`). Legacy MultiPacket (`0x92`/`0x93`) and Ext Multipacket (`0xA4`) C2C handlers are absent; Ext2 handlers are stubs that never `Send`. Compression is still advertised while compressed **upload** is missing — decide advertise-vs-implement after golden Hello vectors / interop harness. Envy self-golden Hello/HelloAnswer TCP vectors live in `tests/test_ed2k_hello_golden.cpp` (`Ed2kHelloWire.h`); eMule/aMule capture slots are still empty.
- Live Envy ↔ eMule Community / aMule transfers are **unverified** in-repo. Treat historical “fully operational” wording in older reports as outdated.
- P0 baseline before new ED2K extensions: Hello/HelloAnswer, MuleInfo, userhash, ClientID, HighID/LowID, callbacks, capability negotiation, compression, multipacket (only if implemented), search, Source Exchange, publish-as-source, upload/download, large files, and clean handling of unsupported extensions.

### Kad2

- **Active path:** `Envy/Kademlia.cpp` / `Envy/Kademlia.h` (UDP via `Datagrams` / `EDPacket` `ED2K_PROTOCOL_KAD`). Started when `Settings.eDonkey.EnableKad` is true (`CEnvyApp::InitKademlia`).
- **Legacy path (inactive):** `Envy/KadProtocol.cpp`, `KBucket.cpp`, `KadStorage.cpp` are compiled only under `ENVY_LEGACY_KADEMLIA`, which is **never defined**. Do not treat them as the live Kad2 stack. Header-only stubs (`KadFirewall.h`, `KadUDPKeys.h`, `KadIndex.h`) have no implementations.
- Wire handlers present for bootstrap, HELLO, PING/PONG, REQ/RES (FIND_NODE), SEARCH_KEY/SOURCE/RES, PUBLISH_KEY/SOURCE/RES — **partial**: search results are not delivered to downloads/UI (`TODO` in `Kademlia.cpp`); `StoreEntry` is a no-op stub; outbound `SearchKeyword` / `Publish*` / `SendHelloRequest` have no app callers; HELLO uses hard-coded ports in places; `EnableKadHello` / `KadFindValue` settings are **not read** by `Kademlia.cpp`.
- **Absent:** FIREWALLED_*, Buddy, Kad callback, UDP keys, notes search/publish, bucket split/LRU/refresh, eclipse /24 limits.
- ED2K Hello Kad version nibble is advertised as **0** (`CEDClient::SendHello`) even when Kad is enabled — honest until Kad is app-integrated and tested.
- `docs/30_protocols/kad/kad2-compatibility-report.md` records **opcode/format matching**, not live DHT interop.
- Status: **partial / unverified**. Target: interoperable Kad2 with eMule/aMule without mixing in Kad6 or Ember overlays.

### SecureIdent RSA

- **Not implemented.** `ED2K_VERSION_SECUREID` is `0` (`Envy/EDPacket.h`).
- Issue #75: do not advertise SecureIdent; never mark a peer verified; ignore inbound SecureIdent packets; keep ED2K transfer independent of SecureIdent.
- Policy helpers: `Envy/SecureIdentPolicy.h`; smoke tests: `tests/test_secureident_policy_smoke.cpp`.
- Real eMule RSA SecureIdent is a **P0/P1** workstream *after* the ED2K baseline. See `docs/DEVELOPMENT_PLAN.md`.

Older documents that say SecureIdent is “active” or “complete” are **wrong**. Canonical correction is this file plus `docs/KNOWN_LIMITATIONS.md`.

### IPv6 / reachability

- Helpers and some settings exist (`Envy/IPv6Support.*`); core sockets/host cache remain IPv4-centric (`docs/ipv6/SCOPE.md`).
- Dual-stack phases 1+ are still `todo` (`docs/ipv6/PLAN.md`).
- Do not start Kad6 before a clean IPv4/IPv6 address type, sockets, DNS A/AAAA, connect/listen, source exchange, host cache, bans, dedup, UI/logging, and UPnP / NAT-PMP / PCP / CGNAT behaviour.
- Status: **partial**. Target: dual-stack.

### Headless / API / core-UI

- Envy is an MFC desktop monolith (`docs/ARCHITECTURE.md`). There is no Envy daemon/CLI.
- Remote/Web exists (`Remote/`) with a design-level API note (`docs/API.md`); endpoint-by-endpoint live verification is incomplete.
- Headless daemon, CLI, and REST/JSON-RPC are **planned** (P1), inspired by aMule, eMule Qt, aria2-next, and Rucio. Migration must be incremental.

### BitTorrent

- v1: DHT, magnet, PEX, LTEP, web seeds, trackers, MSE/PE (`Envy/BTCrypto.*`) are present per `docs/10_dev/roadmap.md` / CHANGELOG.
- v2 / BEP 52: HashLib SHA-256 exists; `CBTInfo::IsBitTorrentV2()` currently returns false and `m_oBTHv2` remains commented (`Envy/BTInfo.h`). Magnet `btmh:` parsing is not a complete v2 download path (`docs/30_protocols/bittorrent/BITTORRENT_V2_PLAN.md`).
- uTP: `Services/LibUTP` is vendored; Envy code does not call it. Status: **not implemented**.
- Do not sacrifice BitTorrent work to make Envy an eMule-only client.

### G1 / G2 / Direct Connect

- G1: `Envy/G1Packet.*`, `Envy/G1Neighbour.*`, `Envy/NeighboursWithG1.*`.
- G2: `Envy/G2Packet.*`, `Envy/G2Neighbour.*`, `Envy/NeighboursWithG2.*`.
- **NMDC (preserve):** `Envy/DCClient.*`, `Envy/DCNeighbour.*`, `Envy/DCPacket.*`, transfer classes. Client `$Supports` includes NMDC-side `ADCGet`/`ADCSND` file-transfer extensions — these are **not** an ADC hub protocol.
- **ADC/ADCS hub protocol: not implemented.** `adc://` / `adcs://` are skipped in hublist import (`HostCache`); no ADC `CSUP`/`CINF`/`CID`/`PID` hub session. Future ADC support must be a **separate layer**, not a graft onto the NMDC parser.
- G1/G2 depth versus gtk-gnutella / latest G2 extras remains **unverified**; that is not an invitation to remove them.

## Historical documents (do not treat as live status)

These remain useful for opcodes and archaeology; they over-claim completeness:

- `docs/30_protocols/ed2k/ED2K_PROTOCOL_VERIFICATION.md`
- `docs/30_protocols/ed2k/ED2K_KAD_GAP_ANALYSIS.md`
- `docs/30_protocols/kad/kad2-compatibility-report.md` (wire match ≠ live interop)
- `docs/10_dev/modernization-summary.md` (January 2026 snapshot)
- `docs/40_quality/security/security-improvements-summary.md` (SecureIdent section obsolete)

## Related

- `docs/DEVELOPMENT_PLAN.md` — P0–P3 sequence
- `docs/10_dev/roadmap.md` — technical itemization
- `docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md` — external projects
- `docs/KNOWN_LIMITATIONS.md`
- `docs/DECISIONS.md` (D-008)
