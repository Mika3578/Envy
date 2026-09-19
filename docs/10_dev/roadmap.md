# Envy Development Roadmap

Status: active
Last updated: 2026-09-19
Scope: Technical itemization of Envy modernization. Strategic sequence is `docs/DEVELOPMENT_PLAN.md`.
Source of truth: `docs/10_dev/status.md` for current vs planned; `docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md` for external projects.
Portability foundations: `docs/20_arch/PORTABILITY_PLAN.md` (Linux/macOS = **planned**, not supported).

**Based on:** Envy code plus reference clients (eMule Community, aMule, and others listed below). Older Examples/ notes for libtorrent, qBittorrent, and Transmission remain valid for BitTorrent.

Canonical context: strategic plan in `docs/DEVELOPMENT_PLAN.md`; status matrix in `docs/10_dev/status.md`. Session notes: `.local/DEV_TRACKER.md` (gitignored).

Priorities here must match DEVELOPMENT_PLAN: **P0 ED2K/Kad interop → P0/P1 RSA SecureIdent → P1 IPv6 and core/UI/headless → P1/P2 BitTorrent → P2 DHT research → P3 Kad6**. Envy stays multi-network. Cross-OS work rides on the core/headless track and must not claim support early.

---

## Current State Summary

- **Build System:** Visual Studio solution builds (MSVC toolset `v145`), CMake partial (HashLib only)
- **UI Framework:** MFC/Unicode complete
- **G2 / G1 / NMDC:** implemented and in scope to preserve. NMDC hub chat now wires user-list merge (`$NickList` + `$MyINFO`) to remote `files.xml.bz2` browse via `CHostBrowser`; FileListing directories fill the existing Browse Host tree before `CNetwork` owns the hit chain; live hub interop unverified. **ADC/ADCS hub protocol is not implemented** (NMDC-side `ADCGet`/`ADCSND` ≠ ADC hubs). Feature depth vs latest ADC-EXT / gtk-gnutella unverified.
- **G2 / G1 / NMDC:** implemented and in scope to preserve. NMDC hub chat now wires user-list merge (`$NickList` + `$MyINFO`) to remote `files.xml.bz2` browse via `CHostBrowser`; FileListing directories fill the existing Browse Host tree; live hub interop unverified. **ADC/ADCS hub protocol is not implemented** (NMDC-side `ADCGet`/`ADCSND` ≠ ADC hubs). Feature depth vs latest ADC-EXT / gtk-gnutella unverified.
- **G2 / G1 / NMDC:** implemented and in scope to preserve. NMDC hub chat now wires user-list merge (`$NickList` + `$MyINFO`) to remote `files.xml.bz2` browse via `CHostBrowser`; live hub interop unverified. **ADC/ADCS hub protocol is not implemented** (NMDC-side `ADCGet`/`ADCSND` ≠ ADC hubs). Feature depth vs latest ADC-EXT / gtk-gnutella unverified.
- **Build System:** Visual Studio solution builds (MSVC toolset `v145`), CMake partial (HashLib + selected tests). Full-app CMake low priority; portable-slice CMake is the multiplatform foundation (`PORTABILITY_PLAN.md`, D-015).
- **Platforms:** Windows x64 **supported** (primary); Win32 **legacy** (still CI/release for Stage A); Linux/macOS **planned** (not supported).
- **UI Framework:** MFC/Unicode complete on Windows; MFC is frontend, not future EnvyCore
- **G2 / G1 / NMDC:** implemented and in scope to preserve. **ADC/ADCS hub protocol is not implemented** (NMDC-side `ADCGet`/`ADCSND` ≠ ADC hubs). Feature depth vs latest ADC-EXT / gtk-gnutella unverified.
- **BitTorrent v1:** Solid (DHT, ut_metadata, ut_pex, lt_tex, web seeds, trackers)
- **BitTorrent v2:** Library-only (Merkle tree + SHA-256); no wire protocol
- **ED2K:** Core transfers + SourceEx2 (0x83/0x84) present; Hello honesty for AICH/SecureIdent/CryptLayer/Ext Multipacket. Compressed upload send path, AICH C2C, Ext Multipacket handlers, callbacks/buddy, and live eMule/aMule interop still open. **SecureIdent RSA is not implemented** (#75; do not advertise).
- **Kademlia (active: `Kademlia.cpp` only):** Bootstrap, ping, find_node, HELLO, SEARCH/PUBLISH **wire handlers** present; **source SEARCH_RES → `AddSourceED2K`** for HighID types 1/4 with outstanding-search context (keyword hits never create sources). **TCP firewall-detection baseline** (`FIREWALLED_REQ`/`RES` + ACK count) present; UDP firewall tester / Buddy / UDP keys absent; outbound store-answer framing still simplified; live Kad2 interop **unverified**. Legacy `KadProtocol.cpp` / `KBucket` / `KadStorage` require undefined `ENVY_LEGACY_KADEMLIA` and are **inactive**.
- **IPv6:** Utilities exist, core connections IPv4-only (`docs/ipv6/PLAN.md`); prefer portable address types in #89
- **Headless / RPC:** not implemented (MFC GUI + limited Remote web UI); #161
- **Testing:** HashLib unit tests plus parser/policy/Hello smokes; opt-in live interop harness (`tools/interop/`, #160) is not required CI; protocol unit/integration seam remains #91

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
| **Compressed upload** | Send-side `COMPRESSEDPART` / `COMPRESSEDPART_I64` implemented (`UploadTransferED2K::DispatchNextChunk`, `Ed2kCompressedUpload.h`); live eMule/aMule evidence still via #160 | Done (code) / unverified live |
| **Live ED2K interop** | Envy ↔ eMule Community / aMule (Hello, HighID/LowID, search, SourceEx, transfer) | P0 |
| **RSA SecureIdent** | Real eMule challenge-response after ED2K baseline (`docs/DEVELOPMENT_PLAN.md`) | P0/P1 |
| **AICH C2C protocol** | AICHFILEHASHREQ (0x9E) / AICHFILEHASHANS (0x9D) handlers — required for AICH corruption recovery from peers | Medium |
| **MULTIPACKET_EXT2 full batching** | Current handler treats each entry as separate FILEREQUEST; implement proper batched processing | Low |
| **PUBLICIP_REQ / PUBLICIP_ANSWER** (0x97/0x98) | **Partial (phase 1):** inbound REQ answered with peer IPv4; outbound REQ when public IP unknown; ANSWER state-gated. Live interop via #160 | Low |
| **CALLBACK / REASKCALLBACKTCP** (0x99/0x9A) | **Partial (phase 1):** C2C CALLBACK (38-byte Buddy layout) when Kad ID matches; REASKCALLBACKTCP deferred (needs Buddy). Classic server push already existed | P0 baseline |
| **BUDDYPING / BUDDYPONG** (0x9F/0xA0) | Buddy system for low-ID clients | P0 Kad/ED2K |
| **FWCHECKUDPREQ** (0xA7) | Firewall check for Kad integration | P0 Kad |

---

## Phase 3: Kademlia DHT Completion (PARTIALLY COMPLETE)

**Goal:** Move from "wire-compatible for bootstrap" to "fully functional DHT participant."

### Done (wire surface in `Kademlia.cpp` — not app-complete)
- BOOTSTRAP_REQ/RES, PING/PONG, FIND_NODE, HELLO handlers
- Routing table — XOR zone tree (`Envy/KadRoutingTable.h`): `CanSplit` (K=10, KBASE=4, KK=5, max depth 127), LRU/type liveness, 1-slot replacement cache, stale-zone FIND_NODE refresh, `/24` diversity (2/bin, 10 global, 1 IP). Local tests only; live DHT evidence remains #160.
- nodes.dat import via `HostCache` (**implemented** for local files: legacy v0 + new-format v1/v2/v3; v3 bootstrap edition bounded). Remote HTTP `nodes.dat` is not wired. Not a complete Kad bootstrap/interop claim.
- Rate limiting, blacklist integration
- Request tracking, IP endianness

### Partial (wire handlers exist; app integration incomplete)
- **SEARCH_KEY / SEARCH_SOURCE / SEARCH_RES** — handlers in `Kademlia.cpp`. **Source SEARCH_RES delivery:** inbound eMule/aMule framing parsed; outstanding search context; HighID sources → `AddSourceED2K` (`KadSearchResDelivery.h` + EnvyTests). Keyword SEARCH_RES does not create sources. Buddy/callback source types and live interop remain open. No app callers yet for `SearchKeyword` / `SearchSource` (register context when called).
- **PUBLISH_KEY / PUBLISH_SOURCE / PUBLISH_RES** — handlers present; `StoreEntry` is a no-op stub; no app callers for `PublishKeyword` / `PublishSource`. Envy outbound answers to SEARCH_*_REQ still use simplified `WriteEntryTags` (not reference TagList).
- Legacy `KadProtocol` / `KBucket` / `KadStorage` — **inactive** (`ENVY_LEGACY_KADEMLIA` undefined).

### TODO

| Item | Detail | Priority |
|------|--------|----------|
| ~~Deliver SEARCH_RES to downloads~~ | HighID source SEARCH_RES → `AddSourceED2K` (keyword excluded; buddy types deferred) | Done (partial) |
| **App-trigger source search** | Call `SearchSource` from ED2K download source acquisition when Kad is enabled | P0 |
| **Align outbound SEARCH_RES/store tags** | Envy `WriteEntryTags` vs eMule AnswerID+TagList when answering peers | P1 |
| ~~Bucket splitting / LRU / refresh / eclipse `/24`~~ | Zone tree + LRU + bounded replacement + stale-zone FIND_NODE + `/24` caps (`KadRoutingTable.h`, EnvyTests) | Done (local; live #160) |
| ~~FIREWALLED_REQ/RES~~ | TCP firewall-detection baseline (exact 2/4-byte framing, bounded checks, public-IP consensus). UDP tester / Buddy deferred. | Done (partial) |
| **FINDBUDDY_REQ/RES** | Buddy system for NAT traversal | P0 |
| **CALLBACK_REQ/RES** | Kad callback mechanism | P0 |
| **UDP hole punching** | NAT traversal for firewalled nodes (historical Kad2; not Ember/eSE overlays) | P0 |
| ~~Firewall self-check~~ | TCP Unknown/Testing/Open/Firewalled via ACK consensus; UDP state remains Unknown | Done (partial) |
| **Wire EnableKadHello / KadFindValue** | Settings exist but are not read by `Kademlia.cpp` | Medium |
| **Kad remote nodes.dat download** | HTTPS discovery type + size/timeout/atomic replace. Local ImportNodes v1/v2/v3 is done. Coordinate with #86/#160. Do not advertise Kad complete. | P1 |
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

Incremental only. References: eMule Qt, aMule, aria2-next, Rucio. No rewrite. Portability plan: `docs/20_arch/PORTABILITY_PLAN.md`.

| Item | Detail | Priority |
|------|--------|----------|
| **EnvyCore extraction** | Protocol/transfer/library behind a stable internal API; keep MFC as first frontend (#161). New core APIs avoid MFC/Win32 types (D-013). | P1 |
| **First-party protocol test seam** | Parsers/state machines without MFC windows (#91); feeds EnvyCore | P1 |
| **Headless / CLI / RPC** | Native REST `/api/v1` (D-017); HTML Remote is not that API. Audit: `docs/20_arch/AUDIT_REMOTE_API_2026-09.md` | P1 |
| **\*arr download client** | qBittorrent Web API v2 **subset** after native transfers (D-018). Not “qBittorrent-compatible” until tests | P1/P2 |
| **Torznab client** | caps + search consumer for Prowlarr/Jackett; not a Torznab server | P2 |
| **Platform abstraction** | Sockets/DNS/FS/threads/RNG/NAT hooks behind portable interfaces; no mass `#ifdef` | P1 (after seam) |
| **CMake portable slice** | EnvyCore / parsers / HashLib / tests / headless with MSVC+Clang+GCC; no MFC required | P1 |
| **CMake for full MFC app** | Extend CMake to main app, services, plugins | Low |
| **Linux x86_64 CI bootstrap** | After portable tests exist; advisory until green | P1/P2 |
| **macOS ARM64 CI bootstrap** | After Linux path proves useful; advisory until green | P1/P2 |
| **Win32 Stage B/C** | Evaluate release/CI removal only with evidence (D-014) | Later |
| **C++20 adoption** | Concepts, ranges, coroutines where beneficial | Low |
| **Protocol virtual dispatch** | Replace `switch(PROTOCOL_*) + downcast` with virtual methods on transfer/neighbour classes. Keep `/GR-`; do not enable global RTTI. The two C++ `dynamic_cast` ED2K defects (`EDPacket::WriteFile`, `CUploadQueue::StartImpl`) are already replaced with construction-proven `static_cast`. | Low |
| **Smart pointer migration** | Replace raw `new`/`delete` with `unique_ptr`/`shared_ptr` | Low |
| **Future multi-OS desktop GUI** | Qt/wx/etc. evaluation only after headless API; dedicated issue; not started | Deferred |

---

## Priority Summary

Aligned with `docs/DEVELOPMENT_PLAN.md`.

### P0 — ED2K / Kad interop baseline
1. Live Envy ↔ eMule Community / aMule validation (Hello, HighID/LowID, search, SourceEx, transfer, Kad bootstrap/search/publish).
2. Firewalled / callback / Buddy / firewall-check behaviour.
3. ~~Kad bucket splitting + LRU + refresh (needed for a real routing table).~~ Routing maintenance landed (zone split / LRU / refresh / `/24` limits); live DHT evidence remains #160. Firewall/Buddy/callback still open (#86).
4. ~~SourceEx2 / Kad FIND_VALUE + PUBLISH (code present; live interop still unverified).~~
5. ~~BT protocol encryption~~ — Done (MSE/PE in `CBTClient` via `BTCrypto.h/cpp`).

### P0/P1 — SecureIdent RSA
6. Real eMule RSA SecureIdent **after** the ED2K baseline. Not advertised today (`ED2K_VERSION_SECUREID = 0`).

### P1 — IPv6, core/UI, headless, portability foundations
7. IPv6 address/socket/DNS/host-cache foundation (`docs/ipv6/PLAN.md`, #89). Prefer portable address types. No Kad6 yet.
8. Incremental `EnvyCore` / MFC split (#91 → #161; eMule Qt, aMule, aria2-next).
9. Evaluate daemon / CLI / REST or JSON-RPC.
10. Cross-platform foundations doc + decisions (D-012…D-015); Linux/macOS remain `planned`.
10a. Bootstrap remaining work after the 2026-09-18 catalogue refresh: importer caps, Kad `nodes.dat` source type, last-known-good remote catalogue (`docs/30_protocols/bootstrap-sources.md`).
### P1 — Bootstrap follow-ups
- After the 2026-09-18 catalogue refresh (`docs/30_protocols/bootstrap-sources.md`):
  - Importer caps for `server.met` / hublist / GWC (P0 potential).
  - Kad remote `nodes.dat` discovery type (HTTPS). Local `ImportNodes` v1/v2/v3 + empty-cache local file path is implemented. Coordinate with #86/#160. Do not advertise Kad complete.
  - Last-known-good remote catalogue (async, never block startup).

### P1/P2 — BitTorrent (do not drop)
11. Compressed ED2K upload (send COMPRESSEDPART) — **code done**; live evidence via #160.
12. AICH C2C protocol.
13. BT uTP (BEP 29) — not wired; `Services/LibUTP` is unused by Envy code.
14. BT v2 infohash + .torrent parsing + wire (BEP 52).

### P2 / P3
15. DHT/security research (Ember/Rucio ideas, Envy-specific, not Kad2).
16. Kad6 / eSE-style overlay only after IPv6 + Kad2 interop.
17. HTTPS trackers, LPD, remaining low-priority opcodes.

### Transfer settings UX (after this foundation)

Do not mix with protocol P0 work. Sequence after the foundation PR:

1. Prove and fix `MaxPerHost` allow vs enforce off-by-one (`AllowMoreTo` / `CanUploadFileTo`).
2. Simple-mode summary of the two global caps + existing download MaxFiles/MaxTransfers (no new preferences).
3. Queue overlap preview / criteria docs (keep Small/Large/Partial/eDonkey queues).
4. Label `BitTorrent.UploadCount` as BT-only if shown near upload queues.
5. Bind / IPv6 / VPN leak UI — blocked until the core exists.

See `docs/50_user/transfer-settings.md`.

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
