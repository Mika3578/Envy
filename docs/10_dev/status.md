# Envy implementation status

Status: active
Last updated: 2026-09-19
Scope: Evidence-based protocol and architecture status for Envy on `develop`.
Source of truth: Envy source under `Envy/`, tests under `tests/`, and the documents linked below. External projects are references only.

This is the canonical **status matrix**. Roadmap sequencing lives in `docs/DEVELOPMENT_PLAN.md` and `docs/10_dev/roadmap.md`. External references live in `docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md`. Portability plan: `docs/20_arch/PORTABILITY_PLAN.md`.

Envy is a **Windows-native multi-network** client today (BitTorrent, Gnutella, Gnutella2, ED2K, Kad, Direct Connect, Remote/Web, library and multi-network search). ED2K/Kad interop work must not turn Envy into an eMule-only client. Linux and macOS are **planned**, not supported.

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
| Windows x64 product | implemented (primary) | — | preserve |
| Windows Win32/x86 product | implemented (legacy Stage A) | — | deprecate later (D-014) |
| Local crash reports | implemented (#90, Windows Debug+Release) | Crashpad (upload off) | preserve (no SaaS) |
| Linux x86_64 product | planned | aMule | planned → supported only with CI evidence |
| macOS ARM64 product | planned | aMule | planned → supported only with CI evidence |
| EnvyCore portable boundary | not implemented | eMule Qt, aria2-next | planned (#161) |
| Portable platform abstraction | not implemented | aMule, aria2-next | planned |
| ED2K basic interop | partial / unverified live | eMule Community, aMule | implemented (full baseline) |
| Kad2 | partial / unverified live | eMule Community, aMule | interoperable |
| SecureIdent RSA | not implemented | eMule Community (secondary: aMule) | implemented |
| IPv6 | partial | eMule AI, eMule Qt, eMule eSE | dual-stack |
| Headless daemon | not implemented | aMule, eMule Qt, aria2-next | planned |
| REST / JSON-RPC | not implemented (HTML Remote is not this API) | eMule Qt, aria2-next | planned (`/api/v1`, D-017) |
| qBittorrent Web API subset (*arr) | not implemented | Radarr QBittorrentProxyV2 | planned (D-018; subset only) |
| Torznab client | not implemented | Prowlarr, Jackett | planned |
| BitTorrent v1 | implemented | BEPs, aria2-next, libtorrent | preserve / extend |
| BitTorrent v2 | partial | BEP 52, aria2-next | implemented |
| Gnutella (G1) | implemented | Envy / Shareaza lineage | preserve |
| Gnutella2 (G2) | implemented | Envy / Shareaza lineage | preserve |
| Direct Connect (NMDC) | implemented (hub chat + file-list browse wired; live hub interop unverified) | NMDC, Shareaza, DC++ | preserve |
| Direct Connect (ADC/ADCS) | not implemented | ADC / ADC-EXT, EiskaltDC++ | planned (separate layer) |
| uTP (BEP 29) | not implemented | BEP 29, aria2-next | planned |
| Kad6 / next overlay | not implemented | eMule eSE (R&D only) | experimental (P3) |

## Evidence notes

### ED2K

- Handshake, transfer, Source Exchange v1/v2, large-file I64 packets, and many eMule opcodes are present in `Envy/EDClient.cpp` / `Envy/EDPacket.h`.
- Source Exchange remains **IPv4-only on-wire** (`docs/30_protocols/ed2k/SOURCE_EXCHANGE_INTEROP_NOTES.md`).
- Capability advertisement rule: Envy must advertise an eMule capability only when it is implemented and tested (`docs/DEVELOPMENT_PLAN.md`). Helpers live in `Envy/Ed2kHelloCapabilities.h` / `Envy/SecureIdentPolicy.h`.
- Honest-by-default Hello bits (advertise 0 until wired): AICH, SecureIdent, CryptLayer MiscOptions2 (TCP obfuscation unimplemented — `#121`; Hello bits must not start PUBLICKEY packet crypto), and Ext Multipacket (MiscOptions2 bit 5, `#129`, `Ed2kExtMultipacketAdvertised()`). Legacy MultiPacket (`0x92`/`0x93`) and Ext Multipacket (`0xA4`) C2C handlers are absent; Ext2 handlers are stubs that never `Send`. Compression Hello nibble remains advertised (`ED2K_VERSION_COMPRESSION`); send-side `COMPRESSEDPART` / `COMPRESSEDPART_I64` is implemented in `CUploadTransferED2K::DispatchNextChunk()` (`Ed2kCompressedUpload.h`) with peer-capability gating and eMule/aMule benefit fallback — live Envy ↔ eMule/aMule compressed transfer remains **unverified** until `#160`. Envy self-golden Hello/HelloAnswer TCP vectors live in `tests/test_ed2k_hello_golden.cpp` (`Ed2kHelloWire.h`) and `tools/interop/fixtures/golden/envy-self-*.json`; eMule/aMule capture slots are still empty.
- **LowID / callback (partial):** Classic ED2K server push remains (`ED2K_C2S_CALLBACKREQUEST` / `S2C_CALLBACKREQUESTED` → `Neighbours.PushDonkey` / `CEDNeighbour::OnCallbackRequested` / `EDClients.PushTo`). Phase-1 eMule C2C baseline (#87): `PUBLICIP_REQ`/`PUBLICIP_ANSWER` (0x97/0x98) and Buddy-delivered `CALLBACK` (0x99, 38-byte layout) are handled with bounded state in `Ed2kLowIdCallback.h` / `CEDClient`. This is **not** complete firewalled support — `REASKCALLBACKTCP`, Buddy selection, `BUDDYPING`/`BUDDYPONG`, `FWCHECKUDPREQ`, and direct UDP callback remain phase 2. Live LowID interop is still expected via #160.
- Live Envy ↔ eMule Community / aMule transfers remain **unverified**. Phase-1 opt-in harness: `python3 tools/interop/run.py` (`tools/interop/README.md`, issue #160). The harness is evidence infrastructure, not an interoperability claim. Public P2P availability is never required PR CI.
- P0 baseline before new ED2K extensions: Hello/HelloAnswer, MuleInfo, userhash, ClientID, HighID/LowID, callbacks, capability negotiation, compression, multipacket (only if implemented), search, Source Exchange, publish-as-source, upload/download, large files, and clean handling of unsupported extensions.

### Kad2

- **Active path:** `Envy/Kademlia.cpp` / `Envy/Kademlia.h` (UDP via `Datagrams` / `EDPacket` `ED2K_PROTOCOL_KAD`). Started when `Settings.eDonkey.EnableKad` is true (`CEnvyApp::InitKademlia`).
- **Legacy path (inactive):** `Envy/KadProtocol.cpp`, `KBucket.cpp`, `KadStorage.cpp` are compiled only under `ENVY_LEGACY_KADEMLIA`, which is **never defined**. Do not treat them as the live Kad2 stack. Header-only stubs (`KadFirewall.h`, `KadUDPKeys.h`, `KadIndex.h`) have no implementations. Live TCP firewall-check state lives in `KadFirewallCheck.h` (not the unused `KadFirewall.h` stub).
- Wire handlers present for bootstrap, HELLO, PING/PONG, REQ/RES (FIND_NODE), SEARCH_KEY/SOURCE/RES, PUBLISH_KEY/SOURCE/RES, **FIREWALLED_REQ/RES/ACK** — **partial**:
  - **Source SEARCH_RES delivery (focused slice):** inbound `KADEMLIA2_SEARCH_RES` is parsed in eMule/aMule form (`SenderID`+`TargetID`+`Count`+`AnswerID`+ED2K tags). Outstanding search context distinguishes keyword vs source vs unsolicited/stale/mismatched targets. Valid HighID source hits (types 1/4 with TCP port + IP) are fed through `CDownloadWithSources::AddSourceED2K` after `Downloads.FindByED2K` (no retained `CDownload*`). Keyword results never create sources. Buddy/callback source types 3/5/6 are refused until those paths exist. Helpers + EnvyTests: `Envy/KadSearchResDelivery.h`, `tests/test_kad_search_res_delivery_smoke.cpp`.
  - **TCP firewall-detection baseline (#86 phase 1):** `KADEMLIA_FIREWALLED_REQ` (0x50, exact 2-byte TCP port) / `KADEMLIA_FIREWALLED_RES` (0x58, exact 4-byte observed IPv4) / inbound `KADEMLIA_FIREWALLED2_REQ` (0x53, min 19 bytes) / UDP `FIREWALLED_ACK_RES` (0x59) and ED2K `OP_KAD_FWTCPCHECK_ACK` (0xA8) count toward TCP Open. Bounded outbound checks (max 4 verified contacts). Public IP requires two independent agreeing peers. TCP and UDP firewall states are distinct; UDP remains Unknown. Inbound REQ is rate-limited; probe IP is always the UDP source (port from payload only). Connect-back TCP is recorded, not executed. Does **not** flip `Network.IsFirewalled()`. Helpers + EnvyTests: `Envy/KadFirewallCheck.h`, `tests/test_kad_firewall_check_smoke.cpp`.
  - **Still open:** `StoreEntry` is a no-op stub; outbound `SearchKeyword` / `Publish*` / `SendHelloRequest` have no app callers; Envy's outbound answers to others' SEARCH_*_REQ still use the simplified `WriteEntryTags` store framing (not eMule TagList) — documented disagreement; HELLO uses hard-coded ports in places; `EnableKadHello` / `KadFindValue` settings are **not read** by `Kademlia.cpp`.
- Cold-start: `HostCache::Load` calls `CheckMinimumServers(PROTOCOL_KAD)` if the Kad list is empty. `DefaultServers.dat` still ships **no** `K` rows. When the Kad cache is empty, Envy imports a local `nodes.dat` from `Settings.General.DataPath` (and, if present, a fresh eMule/aMule `config\nodes.dat`). `CHostCache::ImportNodes` parses legacy v0 plus new-format **v1 / v2 / v3** via `Envy/KadNodesDat.h` (v3 edition 1 is bootstrap-only: XOR-closest 50 contacts, not the whole 500-1000 pool). UDP-key and `verified` bytes are consumed and discarded — runtime UDP-key protocol is **not implemented**. `CKademlia::Bootstrap()` still reads `HostCache.Kademlia` (up to 5 BOOTSTRAP_REQ, 30 s throttle). If the cache is still empty it logs that no bootstrap contacts were found. Remote HTTP `nodes.dat` discovery is a follow-up, not a completeness claim.
- **Absent:** UDP firewall tester (`FWCHECKUDPREQ` / `KADEMLIA2_FIREWALLUDP`), Buddy, Kad callback, UDP keys, notes search/publish, bucket split/LRU/refresh, eclipse /24 limits.
- **Kad TCP firewall-detection baseline implemented; UDP firewall verification, Buddy and callback remain incomplete.** Do not say Kad firewall support is complete.
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
- MFC is the **Windows frontend**, not the long-term portable core.
- Remote/Web exists (`Remote/`) as a **partial** HTML control UI on the P2P HTTP port (`docs/API.md`). JSON `/api/*` in `Remote/api-specification.md` is **not served**. Native `/api/v1` is **planned** (D-017). `TransferState.h` is a mapping helper only.
- Headless daemon, CLI, and REST/JSON-RPC are **planned** (P1), inspired by aMule, eMule Qt, aria2-next, and Rucio. Migration must be incremental (#91, #161). See `docs/20_arch/AUDIT_REMOTE_API_2026-09.md`.
- Cross-OS product ports are **planned** only; see `docs/20_arch/PORTABILITY_PLAN.md`. Do not document Linux/macOS as supported.

### Platforms / portability

- **Supported:** Windows x64 (primary shipping target).
- **Legacy:** Windows Win32/x86 — still built and tested (D-014 Stage A); not a removal candidate yet.
- **Planned:** Linux x86_64, macOS ARM64 (then optional ARM64 variants). Non-targets: Linux x86-32, macOS 32-bit.
- vcpkg manifest currently `supports` Windows only; non-Windows dependency strategy follows portable-slice work.
- Authoritative full app build remains `Visual Studio/Envy.sln`; CMake portable slice is the multiplatform foundation (D-015).

### Transfer settings UI

- Settings → Internet → Uploads mapping is documented in `docs/50_user/transfer-settings.md`.
- Global upload/download caps are **implemented** (`Bandwidth.Uploads` / `Downloads`, `0` = unlimited).
- `Uploads.FairUseMode` is **implemented** (opt-in 10% audio/video per remote IPv4 client; charged from body bytes, HEAD/aborts roll back).
- Simple-mode activity caps and per-protocol bandwidth UI are **planned** only where a backend already exists.
- Status: **partial**. Do not claim a complete qBittorrent-style transfer pane.

### BitTorrent

- v1: DHT, magnet, PEX, LTEP, web seeds, trackers, MSE/PE (`Envy/BTCrypto.*`) are present per `docs/10_dev/roadmap.md` / CHANGELOG. DHT catalogue routers live in `DefaultServers.dat`; `CDHT::Connect` sends BEP 5 `find_node` to HostCache BitTorrent hosts when no node IDs are cached; known node IDs persist in `HostCache.dat`.
- v2 / BEP 52: HashLib SHA-256 exists; `CBTInfo::IsBitTorrentV2()` currently returns false and `m_oBTHv2` remains commented (`Envy/BTInfo.h`). Magnet `btmh:` parsing is not a complete v2 download path (`docs/30_protocols/bittorrent/BITTORRENT_V2_PLAN.md`).
- uTP: `Services/LibUTP` is vendored; Envy code does not call it. Status: **not implemented**.
- Do not sacrifice BitTorrent work to make Envy an eMule-only client.

### G1 / G2 / Direct Connect

- G1: `Envy/G1Packet.*`, `Envy/G1Neighbour.*`, `Envy/NeighboursWithG1.*`.
- G2: `Envy/G2Packet.*`, `Envy/G2Neighbour.*`, `Envy/NeighboursWithG2.*`.
- **NMDC (preserve):** `Envy/DCClient.*`, `Envy/DCNeighbour.*`, `Envy/DCPacket.*`, transfer classes. Client `$Supports` includes NMDC-side `ADCGet`/`ADCSND` file-transfer extensions — these are **not** an ADC hub protocol.
- **NMDC hub users + file-list browse:** `$GetNickList` is still sent after `$Hello`. `$NickList` is a bounded nick-only seed merged into the hub session’s `m_oUsers` (identity is **hub + nick**; `CChatCore::FindSession` still keys by address+protocol only, so two hubs on the same IP with different ports can still coalesce chat sessions — Browse/`/msg` use `Neighbours.Get(IN_ADDR)` likewise). `$MyINFO` remains the metadata path; `$Quit` still removes users. Hub chat can Browse a selected remote user through existing `CHostBrowser` `PROTOCOL_DC` (`files.xml.bz2`). Incoming lists are fail-closed at transfer and parse time; FileListing directories populate the Browse Host left tree from an owned path/index snapshot **before** `CNetwork` owns the hit chain. Outgoing lists skip files without Tiger. This is **not** “full DC++ support”. Live hub tests are not part of CI.
- **ADC/ADCS hub protocol: not implemented.** `adc://` / `adcs://` are skipped in hublist import (`HostCache`); no ADC `CSUP`/`CINF`/`CID`/`PID` hub session. Future ADC support must be a **separate layer**, not a graft onto the NMDC parser.
- Default public hublist URL (2026-09): `https://dchublist.org/hublist.xml.bz2`, with additional HTTPS `H` rows in `Data/DefaultServices.dat`. This is bootstrap only — not “hublist support complete”.
- G1/G2 depth versus gtk-gnutella / latest G2 extras remains **unverified**; that is not an invitation to remove them.
- **Bootstrap catalogues (2026-09-18):** shipped `Data/DefaultServices.dat` / `Data/DefaultServers.dat` are the cold-start sources (GWC/UHC, `server.met`, hublists, BT DHT DNS). Learned hosts stay in `HostCache.dat` / `Discovery.dat`. Kad has **no** shipped contacts; `CKademlia::Bootstrap()` no-ops when `HostCache.Kademlia` is empty. Details: `docs/30_protocols/bootstrap-sources.md`. Do not call Kad or ADC “complete”.

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
- `docs/20_arch/PORTABILITY_PLAN.md` — cross-platform foundations
- `docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md` — external projects
- `docs/KNOWN_LIMITATIONS.md`
- `docs/DECISIONS.md` (D-008, D-012…D-015)
- `tools/interop/README.md` — opt-in live eMule/aMule harness (#160; not an interop claim)
- `docs/50_user/transfer-settings.md` — Uploads/Downloads limit mapping (partial; no fake capabilities)
