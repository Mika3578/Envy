# Envy Development Status

**Last Updated:** March 2026
**Default branch:** `develop`
**Build baseline:** Visual Studio solution `Visual Studio/Envy.sln` (VS 18.x), MSVC toolset `v145`, C++17 (`stdcpp17`)

This document summarizes the current state of the repository based on actual code inspection and comparison against reference implementations (eMule, aMule, libtorrent, qBittorrent, Transmission).


Canonical context: operational dashboard in `docs/DEV_TRACKER.md`; strategic plan in `docs/DEVELOPMENT_PLAN.md`.

---

## Build & Tooling

### Visual Studio (primary)
- **Status:** Working in CI and locally
- **Solution:** `Visual Studio/Envy.sln`
- **Toolset:** `v145` (configured in `.vcxproj`)
- **C++ standard:** C++17 (`stdcpp17`)
- **Platforms/configurations:** Win32/x64, Debug/Release
- **Output layout:** projects output to folders like `Envy\Release x64\`

### Local build helper
- `build_all.ps1` builds Debug/Release x Win32/x64 via `MSBuild.exe` (requires MSBuild on PATH).

### CMake (secondary)
- **Status:** Incomplete (HashLib + tests only)
- `CMakeLists.txt` adds `HashLib/` and `tests/` (when `BUILD_TESTS=ON`).
- TODOs remain for the main app, services, and plugins.

---

## Testing

### Automated unit tests (EnvyTests)
- **Status:** Working in CI and locally
- **Project:** `tests/EnvyTests.vcxproj` (console app, part of `Envy.sln`)
- **CMake:** `tests/CMakeLists.txt` (when `BUILD_TESTS=ON`)
- **Tests:** 13 tests covering HashLib algorithms (MD4, MD5, SHA-1, SHA-256, ED2K)
- **Results:** 13/13 passing
- **CI:** Tests run automatically after each build in `.github/workflows/build.yml`
- **Code coverage:** OpenCppCoverage runs on Debug x64 test binaries; Cobertura XML and HTML artifact `coverage-report` (14-day retention)

### CI coverage
- CI builds Debug and Release for Win32/x64 (`.github/workflows/build.yml`).
- CI runs unit tests after each build.
- CI also runs code analysis, formatting checks, and markdown link checking (`.github/workflows/code-quality.yml`).

### Legacy integration tests
- `tests/test_runner.cpp` and related files exist but have deep MFC dependencies.
- Require Envy core refactored into a static library to compile.

---

## Protocols: Full Comparison

### BitTorrent (vs libtorrent / qBittorrent / Transmission)

**Overall: v1 core solid, v2 and transport gaps**

#### Core v1 Protocol

| Feature | Envy | libtorrent | qBittorrent | Status |
|---------|------|------------|-------------|--------|
| Peer wire protocol (handshake, choke, request, piece, cancel) | Yes | Yes | Yes | Complete |
| 20-byte SHA-1 infohash | Yes | Yes | Yes | Complete |
| .torrent parsing (bencode, files, pieces, announce-list) | Yes | Yes | Yes | Complete |
| Multi-file torrents | Yes | Yes | Yes | Complete |
| Private torrents (no PEX/DHT) | Yes | Yes | Yes | Complete |
| Piece verification (SHA-1) | Yes | Yes | Yes | Complete |
| TCP peer connections | Yes | Yes | Yes | Complete |
| HTTP tracker announce | Yes | Yes | Yes | Complete |
| UDP tracker announce/scrape | Yes | Yes | Yes | Complete |
| Multi-tracker tiers | Yes | Yes | Yes | Complete |
| Web seeds (BEP-19) | Yes | Yes | Yes | Complete |

#### Extensions (BEPs)

| Extension | BEP | Envy | libtorrent | Status |
|-----------|-----|------|------------|--------|
| Extended protocol (BEP-10) | 10 | Yes | Yes | Complete |
| ut_metadata (magnet) | 9 | Yes | Yes | Complete |
| ut_pex (peer exchange) | 11 | Yes | Yes | Complete |
| lt_tex (tracker exchange) | 28 | Yes | Yes | Complete |
| Source exchange (Shareaza/Envy) | Custom | Yes | No | Complete |
| Fast peers | 6 | Defined, not used | Yes | **TODO** |
| NAT traversal | 10 | Defined, not used | Yes | **TODO** |

#### DHT

| Feature | Envy | libtorrent | Status |
|---------|------|------------|--------|
| DHT bootstrap | Yes | Yes | Complete |
| DHT search | Yes | Yes | Complete |
| DHT announce | Yes | Yes | Complete |
| DHT ping | Yes | Yes | Complete |
| DHT node persistence | Yes | Yes | Complete |
| IPv6 in DHT | Partial (paths exist) | Yes | **TODO** |

#### Magnet Links

| Feature | Envy | Status |
|---------|------|--------|
| `xt=urn:btih:` (v1 hash) | Yes | Complete |
| `xt=btmh:` (v2 hash) | Parsed, no v2 logic | **TODO** |
| `tr=` (trackers) | Yes | Complete |
| `dn=` (display name) | Yes | Complete |
| `xl=` (size) | Yes | Complete |
| `bn=` (DHT nodes) | Yes | Complete |
| `ws=` (web seeds) | Yes | Complete |
| Metadata via ut_metadata | Yes | Complete |

#### BitTorrent v2 / BEP-52

| Feature | Envy | libtorrent | Status |
|---------|------|------------|--------|
| SHA-256 infohash | Parsed in URL only | Yes | **TODO** |
| Merkle tree library | Yes (build, verify, piece layers) | Yes | Complete (library only) |
| `meta version` detection | Partial (detected, not acted on) | Yes | **TODO** |
| v2 .torrent parsing | Partial (meta version detected) | Yes | **TODO** |
| 32-byte infohash | Not implemented (`m_oBTHv2` commented out) | Yes | **TODO** |
| Hash request/response (BEP-52 msg 21-23) | Not implemented | Yes | **TODO** |
| Hybrid mode (v1+v2) | Not implemented | Yes | **TODO** |

#### Transport & Security

| Feature | Envy | libtorrent | Status |
|---------|------|------------|--------|
| Protocol encryption (MSE/PE, BEP-10) | Yes (`BTCrypto.h/cpp`, integrated in `CBTClient`) | Yes | Complete (DH+RC4, initiator+responder) |
| uTP (UDP transport, BEP-29) | Not implemented (TCP only) | Yes | **TODO** |
| HTTPS trackers | Not implemented | Yes | **TODO** |
| IPv6 peers in PEX | Not implemented | Yes | **TODO** |
| Local peer discovery (BEP-14) | Not implemented | Yes | **TODO** |
| HTTP scrape | Commented out (`ScrapeTracker()`) | Yes | **TODO** |

---

### eDonkey2000 / eMule (vs eMule 0.60+ / aMule)

**Overall: Core transfers and handshake solid; several advertised features are incomplete or mis-advertised**

#### Core ED2K

| Feature | Envy | eMule | Status |
|---------|------|-------|--------|
| HELLO / HELLOANSWER | Yes | Yes | Complete |
| FILEREQUEST / FILEREQANSWER / FILENOTFOUND | Yes | Yes | Complete |
| FILESTATUS / FILESTATUSREQUEST | Yes | Yes | Complete |
| QUEUEREQUEST / QUEUERANK / STARTUPLOAD / FINISHUPLOAD | Yes | Yes | Complete |
| REQUESTPARTS / SENDINGPART (32-bit) | Yes | Yes | Complete |
| HASHSETREQUEST / HASHSETANSWER | Yes | Yes | Complete |
| EMULEINFO / EMULEINFOANSWER | Yes | Yes | Complete |
| Queue ranking (eMule + eDonkey formats) | Yes | Yes | Complete |
| File comments (FILEDESC) | Yes | Yes | Complete |
| Preview request/answer | Yes | Yes | Complete |
| Chat captcha | Yes | Yes | Complete |
| Protocol version detection (0xE3, 0xC5, 0xD4) | Yes | Yes | Complete |

#### Large File Support (64-bit)

| Feature | Envy | eMule | Status |
|---------|------|-------|--------|
| REQUESTPARTS_I64 (0xA3) | Yes | Yes | Complete |
| SENDINGPART_I64 (0xA2) | Yes | Yes | Complete |
| COMPRESSEDPART_I64 (0xA1) receive | Yes | Yes | Complete |
| m_bEmLargeFile capability flag | Yes | Yes | Complete |

#### Encryption & Authentication

| Feature | Envy | eMule | Status |
|---------|------|-------|--------|
| CryptLayer RSA handshake | Yes | Yes | Complete |
| CryptLayer RC4 encrypt/decrypt | Yes | Yes | Complete |
| PUBLICKEY (0x85) | Yes | Yes | Complete |
| ANSWERCryptLayer (0xB3) | Yes | Yes | Complete |
| Capability flags (supports/requests/requires) | Yes | Yes | Complete |
| SecureID challenge generation (crypto random) | Yes | Yes | Complete |
| SecureID challenge/response flow | Yes | Yes | Complete |
| SecureID advertised version (ED2K_VERSION_SECUREID) | Yes (3) | 3 | Complete |

#### Compressed Transfers

| Feature | Envy | eMule | Status |
|---------|------|-------|--------|
| Receive COMPRESSEDPART (0x40) | Yes (zlib inflate) | Yes | Complete |
| Receive COMPRESSEDPART_I64 (0xA1) | Yes | Yes | Complete |
| **Send COMPRESSEDPART (upload)** | **No** | Yes | **TODO** |
| **Send COMPRESSEDPART_I64 (upload)** | **No** | Yes | **TODO** |
| Packet-level deflate (TCP) | Yes | Yes | Complete |

#### Source Exchange

| Feature | Envy | eMule | Status |
|---------|------|-------|--------|
| REQUESTSOURCES (0x81) | Yes | Yes | Complete |
| ANSWERSOURCES (0x82) | Yes | Yes | Complete |
| REQUESTSOURCES2 (0x83) | Yes | Yes | Complete |
| ANSWERSOURCES2 (0x84) | Yes | Yes | Complete |
| Advertised SourceEx2 (nOpt2 bit 10) | Yes | Yes | Complete |

#### Multi-Packet Extensions

| Feature | Envy | eMule | Status |
|---------|------|-------|--------|
| MULTIPACKET_EXT2 (0xA9) | Partial (simplified parse) | Full batched | **TODO: full batching** |
| MULTIPACKETANSWER_EXT2 (0xB0) | Partial | Full | **TODO: full batching** |
| HASHSETREQUEST2 (0xB1) | Yes | Yes | Complete |
| HASHSETANSWER2 (0xB2) | Yes | Yes | Complete |
| FileIdentifier | Yes | Yes | Complete |

#### AICH (Advanced Intelligent Corruption Handling)

| Feature | Envy | eMule | Status |
|---------|------|-------|--------|
| Build hash tree (180KB blocks) | Yes | Yes | Complete |
| VerifyFile() | Yes | Yes | Complete |
| Store/retrieve per-peer | Yes | Yes | Complete |
| **AICHFILEHASHREQ (0x9E) C2C protocol** | **Not implemented** | Yes | **TODO** |
| **AICHFILEHASHANS (0x9D) C2C protocol** | **Not implemented** | Yes | **TODO** |
| **Hash algorithm** | **SHA-1** | MD4 for blocks | **TODO: verify compatibility** |
| Advertised version | ED2K_VERSION_AICH=1 | 1 | OK |

#### Missing Opcodes (vs eMule 0.60+)

| Opcode | Purpose | Status |
|--------|---------|--------|
| FWCHECKUDPREQ (0xA7) / KAD_FWTCPCHECK_ACK (0xA8) | Firewall check for Kad >=6/7 | **TODO** |
| PUBLICIP_REQ (0x97) / PUBLICIP_ANSWER (0x98) | Public IP discovery | **TODO** |
| CALLBACK (0x99) / REASKCALLBACKTCP (0x9A) | Callback for firewalled clients | **TODO** |
| BUDDYPING (0x9F) / BUDDYPONG (0xA0) | Buddy system for firewalled | **TODO** |

---

### Kademlia / Kad2 (vs eMule Kad2)

**Overall: Wire-compatible for basic operations; missing advanced DHT features**

#### Implemented (verified compatible with eMule/aMule)

| Feature | Envy | eMule | Status |
|---------|------|-------|--------|
| BOOTSTRAP_REQ/RES | Yes | Yes | Complete |
| PING/PONG | Yes | Yes | Complete |
| REQ/RES (FIND_NODE) | Yes | Yes | Complete |
| HELLO_REQ/RES | Yes | Yes | Complete |
| Routing table (XOR distance, K=10) | Yes | Yes | Complete |
| nodes.dat import (v0-3) | Yes | Yes | Complete |
| Rate limiting | Yes | Yes | Complete |
| Blacklist integration | Yes | Yes | Complete |
| Request tracking | Yes | Yes | Complete |
| IP endianness (host-order storage) | Yes | Yes | Complete |

#### Implemented (Kad2 search/publish)

| Feature | Envy | eMule | Status |
|---------|------|-------|--------|
| SEARCH_KEY_REQ / SEARCH_SOURCE_REQ | Yes | Yes | Complete |
| SEARCH_RES | Yes | Yes | Complete |
| PUBLISH_KEY_REQ / PUBLISH_SOURCE_REQ | Yes | Yes | Complete |
| PUBLISH_RES | Yes | Yes | Complete |
| DHT value store (keyword/source) | Yes | Yes | Complete |

#### Missing (vs eMule 0.60+)

| Feature | eMule | Envy | Impact |
|---------|-------|------|--------|
| FIREWALLED_REQ/RES | Yes | No | No firewalled node handling |
| FINDBUDDY_REQ/RES | Yes | No | No buddy system |
| CALLBACK_REQ/RES | Yes | No | No Kad callbacks |
| Bucket splitting | Yes | No (simple add) | Routing table doesn't scale |
| LRU replacement | Yes | No (rejects when full) | Loses useful contacts |
| Bucket refresh | Yes | No | Stale routing table over time |
| Eclipse protection (/24 subnet limits) | Yes | No | Vulnerable to eclipse attacks |
| UDP hole punching | Yes | No | Cannot reach firewalled nodes |
| Firewall check (FWCHECKUDPREQ) | Yes | No | Cannot detect own firewall status |

---

### Gnutella2 (G2)

**Overall: Fully implemented**

| Feature | Status |
|---------|--------|
| G2 packet handling (QUERY, HIT, PUSH, CHAT, PROFILE) | Complete |
| Hub/Leaf/Ultra-peer mode | Complete |
| Query routing (hub forwarding, leaf queries) | Complete |
| G1-G2 conversion and interop | Complete |
| Handshake and node-type negotiation | Complete |
| Chat sessions | Complete |
| Settings (hubs, leafs, client mode, deflate) | Complete |

---

### Gnutella (G1)

**Overall: Fully implemented**

| Feature | Status |
|---------|--------|
| G1 packet handling (GGEP) | Complete |
| Ultrapeer/Leaf mode | Complete |
| Ping/Pong routing | Complete |
| Query routing | Complete |
| Settings (TTL, GGEP, UTF-8) | Complete |

---

### DC++

**Overall: Implemented**

| Feature | Status |
|---------|--------|
| Hub connection ($Hello, $Lock, $Supports, $MyINFO) | Complete |
| Chat | Complete |
| Search via hub | Complete |
| Download transfers | Complete |
| Hub list import (.xml.bz2) | Complete |

---

### HTTP / FTP

| Feature | Status |
|---------|--------|
| HTTP download (range, chunked, gzip, redirects, TigerTree) | Complete |
| FTP download (passive mode) | Complete |
| FTP download (active mode) | Commented out |

---

## Other Systems

### Security

| Feature | Status |
|---------|--------|
| IP filtering / blacklist (IsDenied, Ban, AddressMap, HashMap) | Complete |
| ED2K CryptLayer (RSA + RC4) | Complete |
| ED2K obfuscation flags and ports | Complete |
| Vendor/agent blocking | Complete |
| Client banning | Complete |
| Kademlia blacklist (via Security.IsDenied) | Complete |
| External blacklist file loading | Complete |
| P0.2 crypto security (secure RNG) | Complete |
| RC4 cipher strength | Weak (industry-wide; not Envy-specific) |

### Plugin System

| Feature | Status |
|---------|--------|
| COM-based plugin interfaces (IGeneralPlugin, etc.) | Complete |
| ~18 plugins (7Zip, RAR, ZIP builders; Preview; MediaPlayer; SkinScan; VirusTotal; WebHook; DocumentReader) | Complete |

### UPnP / NAT

| Feature | Status |
|---------|--------|
| UPnP port mapping (AddPortMapping, RemovePortMapping) | Complete |
| UPnP device discovery | Complete |
| MiniUPnP integration | Complete |
| GetExternalIP | Not implemented (returns empty) |
| IPv6 UPnP | Not implemented |

### IPv6

| Feature | Status |
|---------|--------|
| IPv6 utility classes (IPv6Address, CIPv6Manager, dual-stack) | Complete |
| ED2K IPv6 settings and metrics | Complete |
| **Core connection layer (CConnection)** | **IPv4 only** (`AF_INET`, comment "not IPv6 yet") |
| **IPv6 in PEX / peer exchange** | **Not implemented** |

### Skinning

| Feature | Status |
|---------|--------|
| XML-based skin format (colorScheme, fonts, watermarks, commandImages) | Complete |
| ~24 skin themes (ShareazaOS, Windows 10, Windows Collection, Resize) | Complete |
| SkinScan validation plugin | Complete |

### HashLib

| Algorithm | Status |
|-----------|--------|
| MD4 | Complete (RFC 1320 tested) |
| MD5 | Complete (RFC 1321 tested) |
| SHA-1 | Complete (FIPS 180-4 tested) |
| SHA-256 | Complete (FIPS 180-4 tested, BEP-52 ready) |
| ED2K | Complete (MD4-based, tested) |
| Tiger Tree | Complete |
| AICH | Complete |

---

## Summary: Strengths & Gaps

### Strengths (vs single-protocol clients)
- Multi-protocol in one client: BT + G2 + G1 + ED2K + DC++ + HTTP/FTP
- G2 and G1 fully implemented with hub/leaf and query routing
- BT v1 solid with DHT, ut_metadata, ut_pex, lt_tex, web seeds
- ED2K core transfers, CryptLayer, and large file support working
- Extensive plugin and skinning system
- Secure RNG throughout (P0.2 crypto hardening)

### Key Gaps (what to upgrade)
1. **BitTorrent v2** - No wire protocol, no 32-byte infohash, no hybrid mode (library-only Merkle tree)
2. **uTP** - TCP only; no UDP-based transport
3. **BT protocol encryption** - MSE/PE implemented and integrated (`BTCrypto.h/cpp`, `CBTClient`); needs live interop testing
4. **ED2K compressed upload** - Can receive but not send compressed parts (COMPRESSEDPART send TODO)
5. **Kademlia** - Bucket splitting, LRU replacement, bucket refresh, and firewalled handling still TODO (FIND_VALUE/PUBLISH/Store implemented)
6. **IPv6** - Utilities exist but core connections are IPv4-only
7. **HTTPS trackers** - Only http:// and udp:// supported
8. **Local peer discovery** - No BEP-14 (mDNS/LPD)

---

## Next

- [Build](build.md) - [Roadmap](roadmap.md) - [Architecture](../20_arch/architecture.md) - [Protocols](../30_protocols/)
