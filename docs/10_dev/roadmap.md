# Envy Development Roadmap

Status: active
Last updated: 2026-09-11
Scope: Technical itemization of Envy modernization. Strategic sequence is `docs/DEVELOPMENT_PLAN.md`.
Source of truth: `docs/10_dev/status.md` for current vs planned; `docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md` for external projects.

**Based on:** Envy code plus reference clients (eMule Community, aMule, and others listed below). Older Examples/ notes for libtorrent, qBittorrent, and Transmission remain valid for BitTorrent.

Canonical context: strategic plan in `docs/DEVELOPMENT_PLAN.md`; status matrix in `docs/10_dev/status.md`. Session notes: `.local/DEV_TRACKER.md` (gitignored).

Priorities here must match DEVELOPMENT_PLAN: **P0 ED2K/Kad interop → P0/P1 RSA SecureIdent → P1 IPv6 and core/UI/headless → P1/P2 BitTorrent → P2 DHT research → P3 Kad6**. Envy stays multi-network.

---

## Current State Summary

- **Build System:** Visual Studio solution builds (MSVC toolset `v145`), CMake partial (HashLib only)
- **UI Framework:** MFC/Unicode complete
- **G2 / G1 / DC:** implemented and in scope to preserve (feature depth vs latest ADC-EXT unverified)
- **BitTorrent v1:** Solid (DHT, ut_metadata, ut_pex, lt_tex, web seeds, trackers)
- **BitTorrent v2:** Library-only (Merkle tree + SHA-256); no wire protocol
- **ED2K:** Core transfers + CryptLayer + SourceEx2 (0x83/0x84) present; compressed upload send path, AICH C2C, callbacks/buddy, and live eMule/aMule interop still open. **SecureIdent RSA is not implemented** (#75; do not advertise).
- **Kademlia:** Bootstrap, ping, find_node, FIND_VALUE (search key/source), PUBLISH (key/source), and DHT store implemented; bucket splitting, LRU, refresh, firewalled handling TODO. Live Kad2 interop **unverified**.
- **IPv6:** Utilities exist, core connections IPv4-only (`docs/ipv6/PLAN.md`)
- **Headless / RPC:** not implemented (MFC GUI + limited Remote web UI)
- **Testing:** HashLib unit tests plus parser/policy smokes; protocol integration tests require core refactoring

---

## Phase 0: Build & Infrastructure (COMPLETE)

- Visual Studio 2026 (v145) migration
- GitHub Actions CI/CD pipeline (Debug + Release, Win32 + x64)
- Google Test / custom test framework integration
- Code formatting (.clang-format), static analysis
- CMake for HashLib + tests
- OpenCppCoverage in CI

---

## Phase 1: Performance & Stability (COMPLETE)

- UI thread blocking fixes (file I/O moved to background)
- UI update batching (250ms timer, 50ms data caching)
- List processing O(n^2) elimination
- Memory management improvements (buffer reuse, smart pointers)
- CryptLayer implementation fixes (decryption ordering, state machine, RSA encryption)

---

## Phase 2: ED2K Protocol Fixes (PARTIALLY COMPLETE)

**Goal:** Fix incorrect advertisements and finish partially implemented features.

### Done
- CryptLayer RSA+RC4 handshake
- Large file support (64-bit request/send/compressed)
- HASHSETREQUEST2 / HASHSETANSWER2
- FileIdentifier support
- AICH hash tree building and verification (C2C recovery protocol still TODO)
- Concatenated UDP packet parsing fix
- SourceEx2 — REQUESTSOURCES2 (0x83) / ANSWERSOURCES2 (0x84) in `EDClient.cpp`; advertised via nOpt2 bit 10; IPv4-only tuples (`SOURCE_EXCHANGE_INTEROP_NOTES.md`)
- SecureIdent **safe disable** (#75): `ED2K_VERSION_SECUREID = 0`; peers never marked verified; inbound SecureIdent packets ignored

### Not implemented (do not list as done)
- **eMule RSA SecureIdent** — not implemented. Historical MD5/non-zero “verification” was invalid and is disabled. Do not advertise SecureIdent until a dedicated RSA workstream lands.

### TODO: Bugs / verification

| Item | Detail | Priority |
|------|--------|----------|
| **AICH hash algorithm** | Envy uses SHA-1 for AICH blocks; eMule uses MD4 — verify actual wire compatibility | Medium |

### TODO: Missing features

| Item | Detail | Priority |
|------|--------|----------|
| **Compressed upload** | Can receive COMPRESSEDPART but never sends it; implement zlib deflate in `UploadTransferED2K::DispatchNextChunk()` | Medium |
| **Live ED2K interop** | Envy ↔ eMule Community / aMule (Hello, HighID/LowID, search, SourceEx, transfer) | P0 |
| **RSA SecureIdent** | Real eMule challenge-response after ED2K baseline (`docs/DEVELOPMENT_PLAN.md`) | P0/P1 |
| **AICH C2C protocol** | AICHFILEHASHREQ (0x9E) / AICHFILEHASHANS (0x9D) handlers — required for AICH corruption recovery from peers | Medium |
| **MULTIPACKET_EXT2 full batching** | Current handler treats each entry as separate FILEREQUEST; implement proper batched processing | Low |
| **PUBLICIP_REQ / PUBLICIP_ANSWER** (0x97/0x98) | Public IP discovery from peers | Low |
| **CALLBACK / REASKCALLBACKTCP** (0x99/0x9A) | Callback mechanism for firewalled clients | P0 baseline |
| **BUDDYPING / BUDDYPONG** (0x9F/0xA0) | Buddy system for low-ID clients | P0 Kad/ED2K |
| **FWCHECKUDPREQ** (0xA7) | Firewall check for Kad integration | P0 Kad |

---

## Phase 3: Kademlia DHT Completion (PARTIALLY COMPLETE)

**Goal:** Move from "wire-compatible for bootstrap" to "fully functional DHT participant."

### Done
- BOOTSTRAP_REQ/RES, PING/PONG, FIND_NODE, HELLO
- Routing table (XOR distance, K=10)
- nodes.dat import (v0-3)
- Rate limiting, blacklist integration
- Request tracking, IP endianness

### Done (Kad2 search/publish)
- **FIND_VALUE** — SEARCH_KEY_REQ, SEARCH_SOURCE_REQ, SEARCH_RES implemented in `Kademlia.cpp`.
- **PUBLISH (KEY/SOURCE)** — PUBLISH_KEY_REQ, PUBLISH_SOURCE_REQ, PUBLISH_RES implemented; DHT store (`KadStore`) for keyword/source entries.

### TODO

| Item | Detail | Priority |
|------|--------|----------|
| **Bucket splitting** | Split buckets when full (if bucket contains own ID); current implementation uses simple add | High |
| **LRU replacement** | Replace least-recently-used contact when bucket is full; currently rejects new contacts | Medium |
| **Bucket refresh** | Periodic refresh of stale buckets (eMule uses 15-minute intervals) | Medium |
| **Eclipse protection** | Limit contacts from same /24 subnet to prevent eclipse attacks | Medium |
| **FIREWALLED_REQ/RES** | Handle firewalled node detection and relay | P0 |
| **FINDBUDDY_REQ/RES** | Buddy system for NAT traversal | P0 |
| **CALLBACK_REQ/RES** | Kad callback mechanism | P0 |
| **UDP hole punching** | NAT traversal for firewalled nodes (historical Kad2; not Ember/eSE overlays) | P0 |
| **Firewall self-check** | Detect own firewall status via Kademlia | P0 |
| **Kad6** | Experimental IPv6 overlay (eMule eSE). Distinct from Kad2. | P3 |

---

## Phase 4: BitTorrent Upgrades (TODO)

**Goal:** Close the gap with modern BT clients (libtorrent, qBittorrent, Transmission).

### 4.1 Transport & Security (no v2 dependency)

| Item | Detail | Priority |
|------|--------|----------|
| ~~Protocol encryption (MSE/PE)~~ | Done: `BTCrypto.h/cpp` with DH+RC4, integrated into `CBTClient`; `Settings.BitTorrent.Encryption` | Done |
| **uTP (BEP-29)** | UDP-based congestion-controlled transport; required by many modern peers | High |
| **HTTPS tracker support** | Accept `https://` tracker URLs | Medium |
| **HTTP scrape** | Uncomment and fix `ScrapeTracker()` in `BTInfo.cpp` | Medium |
| **Fast peers (BEP-6)** | Have/Allowed-Fast/Suggest-Piece/Reject — flag defined but never set | Low |
| **Local peer discovery (BEP-14)** | mDNS/LPD for LAN peers | Low |

### 4.2 BitTorrent v2 / BEP-52

| Item | Detail | Priority |
|------|--------|----------|
| **32-byte SHA-256 infohash** | Uncomment `m_oBTHv2`, implement `IsBitTorrentV2()` properly | High |
| **v2 .torrent parsing** | Parse `file tree`, per-file Merkle roots, `meta version` | High |
| **Hash request/response** (BEP-52 msg 21-23) | Wire protocol for Merkle piece verification | High |
| **Hybrid mode** (v1+v2 in one torrent) | Dual infohash, shared piece data | Medium |
| **v2 magnet download path** | Connect `btmh:` parsing to actual v2 metadata fetch | Medium |

### 4.3 Peer Exchange & Connectivity

| Item | Detail | Priority |
|------|--------|----------|
| **IPv6 peers in PEX** | Currently 6-byte compact (IPv4 only) | Medium |
| **NAT traversal (BEP-10)** | Flag defined but not set; implement holepunch | Low |

---

## Phase 5: IPv6 Integration (TODO) — P1

**Goal:** Dual-stack networking before any Kad6 work. References: eMule AI, eMule Qt, eMule eSE, `docs/ipv6/PLAN.md`.

| Item | Detail | Priority |
|------|--------|----------|
| **Core connection layer** | Change `CConnection` from `AF_INET` to dual-stack (`AF_INET6` with `IPV6_V6ONLY=0`) | High |
| **IPv6 in BT PEX** | 18-byte compact format for IPv6 peers | Medium |
| **IPv6 UPnP** | Port mapping for IPv6 | Medium |
| **UPnP GetExternalIP** | Currently returns empty; implement | Medium |
| **IPv6 in Kad DHT** | DHT already has IPv6 paths; integrate with core | Medium |
| **IPv6 in G2/G1** | Hub/ultrapeer connections over IPv6 | Low |

---

## Phase 6: Testing & Quality (IN PROGRESS)

**Goal:** Expand test coverage beyond HashLib.

### Done
- 13 HashLib unit tests (MD4, MD5, SHA-1, SHA-256, ED2K) — all passing
- CI/CD test execution (Release + Debug, Win32 + x64)
- OpenCppCoverage code coverage in CI
- Code analysis, formatting checks, markdown link checking

### TODO

| Item | Detail | Priority |
|------|--------|----------|
| **Envy core static library** | Refactor core into a static lib to enable protocol unit tests | High |
| **ED2K packet parsing tests** | Test handshake, concatenated UDP, compressed parts | High |
| **BT protocol tests** | Test bencode, magnet parsing, DHT messages | Medium |
| **Kad routing table tests** | XOR distance, bucket operations, node eviction | Medium |
| **Integration tests** | Live Envy ↔ eMule Community / aMule (and BT vs aria2-next where useful) | P0 |
| **Performance benchmarks** | Baseline metrics for download throughput, UI responsiveness, memory | Low |

---

## Phase 7: Core/UI, headless, Modern C++ (FUTURE / P1 architecture)

Incremental only. References: eMule Qt, aMule, aria2-next, Rucio. No rewrite.

| Item | Detail | Priority |
|------|--------|----------|
| **EnvyCore extraction** | Protocol/transfer/library behind a stable internal API; keep MFC as first frontend | P1 |
| **Headless / CLI / RPC** | Evaluate daemon + REST or JSON-RPC; Remote/Web is not that API yet | P1 |
| **C++20 adoption** | Concepts, ranges, coroutines where beneficial | Low |
| **Smart pointer migration** | Replace raw `new`/`delete` with `unique_ptr`/`shared_ptr` | Low |
| **CMake for full project** | Extend CMake to main app, services, plugins | Low |

---

## Priority Summary

Aligned with `docs/DEVELOPMENT_PLAN.md`.

### P0 — ED2K / Kad interop baseline
1. Live Envy ↔ eMule Community / aMule validation (Hello, HighID/LowID, search, SourceEx, transfer, Kad bootstrap/search/publish).
2. Firewalled / callback / Buddy / firewall-check behaviour.
3. Kad bucket splitting + LRU + refresh (needed for a real routing table).
4. ~~SourceEx2 / Kad FIND_VALUE + PUBLISH (code present; live interop still unverified).~~
5. ~~BT protocol encryption~~ — Done (MSE/PE in `CBTClient` via `BTCrypto.h/cpp`).

### P0/P1 — SecureIdent RSA
6. Real eMule RSA SecureIdent **after** the ED2K baseline. Not advertised today (`ED2K_VERSION_SECUREID = 0`).

### P1 — IPv6, core/UI, headless
7. IPv6 address/socket/DNS/host-cache foundation (`docs/ipv6/PLAN.md`). No Kad6 yet.
8. Incremental `EnvyCore` / MFC split (eMule Qt, aMule, aria2-next).
9. Evaluate daemon / CLI / REST or JSON-RPC.

### P1/P2 — BitTorrent (do not drop)
10. Compressed ED2K upload (send COMPRESSEDPART) — ED2K quality, can proceed beside BT.
11. AICH C2C protocol.
12. BT uTP (BEP 29) — not wired; `Services/LibUTP` is unused by Envy code.
13. BT v2 infohash + .torrent parsing + wire (BEP 52).

### P2 / P3
14. DHT/security research (Ember/Rucio ideas, Envy-specific, not Kad2).
15. Kad6 / eSE-style overlay only after IPv6 + Kad2 interop.
16. HTTPS trackers, LPD, remaining low-priority opcodes.

---

## Development Principles

- **Evidence-based:** Priorities from Envy code plus specs; reference clients second
- **Fix bugs before features:** Mis-advertised capabilities can cause interop failures
- **Incremental delivery:** Each phase delivers working functionality; no full rewrite
- **Multi-network:** Keep BitTorrent, G1, G2, and Direct Connect while improving ED2K/Kad
- **Profile before optimizing:** Performance changes guided by profiling

---

## Reference implementations

Canonical list, trust order, and “do not copy” notes: `docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md`.

| Priority | Project | Role |
| ---: | --- | --- |
| P0 | [eMule Community](https://github.com/irwir/eMule) | ED2K/Kad2 wire reference |
| P0 | [aMule](https://github.com/amule-project/amule) | Interop + daemon architecture |
| P1 | [eMule Qt](https://github.com/ModderMule/emule-qt) | core/UI, IPC, REST |
| P1 | [eMule AI](https://github.com/eMuleAI/eMuleAI) | IPv6 / reachability (not ED2K-normative) |
| P1 | [aria2-next](https://github.com/AnInsomniacy/aria2-next) | engine, RPC, BT + ED2K tests |
| P2 | [Ember](https://github.com/untaimed18/Ember-P2P) | DHT/security research; **not Kad2** |
| P2 | [Rucio](https://github.com/ogarcia/rucio) | daemon/Web/libp2p architecture (not CERN Rucio) |
| P3 | [eMule eSE](https://github.com/diad87/eMule-eSE-LiveTV) | IPv6/Kad6 R&D |

Local `Examples/` trees (if present, often gitignored) remain useful for libtorrent / qBittorrent / Transmission / historical eMule/aMule checkouts. Prefer the GitHub roots above over a pinned tag.
