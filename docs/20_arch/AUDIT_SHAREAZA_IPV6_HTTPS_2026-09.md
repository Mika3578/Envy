# Audit: Shareaza IPv6 / HTTPS recovery (2026-09)

Status: audit (evidence-based). Not a compatibility claim and **not** an implementation.

- **Date:** 2026-09-20
- **Fork / branch:** `Mika3578/Envy` `develop` `d3095e97`
- **Historical reference:** `ansani/Shareaza` `master` [`f24b0ce`](https://github.com/ansani/Shareaza/commit/f24b0ce3753067e02fb6ee7dbf82d8c214c291d2) (last master commit 2024-06-21)
- **Related issues (reuse, do not duplicate):** [#89](https://github.com/Mika3578/Envy/issues/89) IPv6 foundation, [#88](https://github.com/Mika3578/Envy/issues/88) BT HTTPS trackers + IPv6 PEX, [#162](https://github.com/Mika3578/Envy/issues/162) G1/G2 audit, [#179](https://github.com/Mika3578/Envy/issues/179) portable sockets/DNS, [#163](https://github.com/Mika3578/Envy/issues/163) ADCS (separate), [#230](https://github.com/Mika3578/Envy/issues/230) bind/VPN
- **Related docs:** `docs/ipv6/PLAN.md`, `docs/ipv6/SCOPE.md`, [D-020](../DECISIONS.md), [D-021](../DECISIONS.md), `docs/20_arch/HTTPS_TLS_RESTORATION_PLAN.md`, `docs/40_quality/testing/NETWORK_IPV6_HTTPS_TEST_STRATEGY.md`

Trust order (D-008): **specification → live/modern reference clients → ansani/Shareaza archaeology → current ENVY code**. Shareaza is never copied as architecture or TLS.

Evidence tags: **code** (this fork), **external** (Shareaza/spec), **recommendation**.

Do not read “a type or file exists” as “supported”.

---

## Executive summary

ENVY and Shareaza share a lineage but have diverged. ENVY is ahead on modernisation, ED2K/Kad, packet validation, tests, and CI. Shareaza `master` still executes a **dual-family socket/cache/G2/BT path** that ENVY does not.

HTTPS is **not** “TLS moved to WinINet for downloads”. ENVY has **two HTTP stacks**:

| Stack | Role | TLS today |
| --- | --- | --- |
| Transfer engine (`CDownloadTransferHTTP` + raw sockets) | Files, G1/G2 HTTP sources, web seeds, Range/Tiger/chunked | **None.** `https://` is remapped to `PROTOCOL_HTTP` port 80 (**code**) |
| Auxiliary WinINet (`CHttpRequest`) | VersionChecker, Update Servers, Discovery GWC, HTTP trackers | **Possible** when the URL is `https://` (**code**) |

P2P HTTPS (`PROTOCOL_SSL` + `CDownloadTransferHTTPS` + OpenSSL on `CConnection`) is a **lost transfer capability**. Auxiliary HTTPS is a **kept** WinINet path. Shareaza had both stacks; ENVY dropped only the transfer TLS stack.

IPv6: reimplement Shareaza **surfaces** behind a family-neutral endpoint (D-020). Do **not** reproduce `IN_ADDR`/`IN6_ADDR` overload pairs.

IPv6/HTTPS remain **P1/P2**. They must not outrank P0 ED2K/Kad interop (#160, #86, #75).

---

## Present in ENVY

| Item | Evidence | Notes |
| --- | --- | --- |
| G1/G2/BT/ED2K/DC engines | `Envy/*Neighbour*`, `BTClient`, `EDClient` | Keep; do not reimport Shareaza engines |
| HTTP P2P contract (Range, Tiger, metadata, gzip, chunked, redirect cap 5) | `Envy/DownloadTransferHTTP.*` | Already covers the HTTP part of Shareaza’s HTTPS class |
| Auxiliary `https://` via WinINet | `HttpRequest.cpp` `SetURL`; `VersionChecker.cpp`; `DlgUpdateServers.cpp`; `DiscoveryServices.cpp` `SendWebCacheRequest`; HTTP BT trackers | Not the download engine |
| Packet/body caps | `#81`/`#82` helpers | Keep on any future TLS path |
| MSE/PE | `Envy/BTCrypto.*` | Ahead of Shareaza |
| ED2K/Kad modern layers + tests | Hello wire, Kad routing, EnvyTests | Shareaza is not normative |
| Crashpad, CI, vcpkg | D-019, `vcpkg.json` | Do not import BugSplat/Qodana |
| OpenSSL in vcpkg | `vcpkg.json` | Not wired as a P2P TLS client (**code**: no `SSL_connect` in `Connection.cpp`) |

---

## Partial

| Item | ENVY | Gap |
| --- | --- | --- |
| IPv6 | Settings under `eDonkey` only; jech `dht.c` has IPv6 primitives | Core sockets/HostCache/DNS remain IPv4. `IPv6Support.*` is **not in `Envy.vcxproj`** and has no other `#include` (**code**) |
| Documented `Settings.Connection.EnableIPv6` | Named in `docs/ipv6/PLAN.md` | **Does not exist** in `Settings.cpp`. Drift |
| HTTPS catalogues | WinINet `InternetOpenUrl` without explicit `INTERNET_FLAG_SECURE` | Scheme usually drives SSL; cert/SNI policy not ENVY-owned |
| BT trackers | HTTP + UDP | `https://` rejected in `BTInfo.cpp` (ToDo). Shareaza also builds tracker URLs as `http:` only (**external**) |
| Remote | HTML on P2P HTTP port | No inbound TLS (D-017: reverse proxy first) |
| Redirects | Cap 5 in `DownloadWithSources.cpp` | `Location: https://` is reparsed by `CEnvyURL` and becomes HTTP:80 |
| `docs/50_user/ed2k-settings-guide.md` IPv6 | Describes Prefer IPv6 as operational | Flags are unwired. Canonical status is `docs/10_dev/status.md` |

---

## Present historically in Shareaza, absent as a live ENVY path

Proved by Shareaza **execution** (`master` `f24b0ce`), not by branch names. IPv6 lives on Shareaza **master**, not on a 2025 IPv6-named branch. 2025 branches are VS2026 and Doxygen.

| Capability | Shareaza | ENVY |
| --- | --- | --- |
| TCP listen/accept IPv6 | `Handshakes::ListenIPv6`, `m_hSocketIPv6` | One IPv4 listen |
| TCP connect IPv6 | `Connection::ConnectTo(IN6*)` | `ConnectTo(IN_ADDR*)` only |
| UDP/SGP IPv6 | `Datagrams` `SOCKADDR_IN6` | `socket(PF_INET)` |
| Local IPv6 identity | `Network.m_pHostIPv6`, `IsListeningIPv6`, `IsStableIPv6`, `GetMyAddressFor(IN6)` | `SOCKADDR_IN m_pHost` |
| HostCache IPv6 | `CHostCacheMapIPv6`, ser **21** | `IN_ADDR` map, ser **2** |
| G2 query keys IPv6 | `QueryKeys::Create/Check(IN6)`, `SetKeyIPv6` | `DWORD` IPv4 |
| G2 UDP IPv6 + SNA 4/16/20 | `OnPacket(SOCKADDR_IN6)` | `OnPacket(SOCKADDR_IN*)`; SNA 4-byte |
| PEX `added6`/`dropped6` | `BTClient.cpp` 18-byte compact | `added` 6-byte only |
| LTEP `ipv6` | Yes | No |
| Tracker `peers6` / `&ipv6=` | Yes (on HTTP announces) | No |
| DHT C++ IPv6 wrapper | `CDHT::Ping(IN6)` | `Ping(IN_ADDR)`; `dht.c` unused for v6 |
| `IsDenied` IPv6 | `Security.h` + ser 6 prefix | `IsDenied(IN_ADDR*)` |
| P2P HTTPS transfer | `PROTOCOL_SSL`, `ParseHTTPS` port 443, `CDownloadTransferHTTPS` | Remap to HTTP:80; no SSL protocol id |
| GeoIP IPv6 lookup | `GeoIP_*_v6` | IPv4 `by_ipnum` only (both GeoIP.dat-era) |

Shareaza **also incomplete** (do not treat as dual-stack complete): hostname DNS remains `gethostbyname` (A); `DiscoveryServices` still `IN_ADDR`; G1 GGEP IPP is 6-byte IPv4; HTTPS IPv6 `Initiate` uses `ConnectToIPv6` **without** `SSL_connect`; HTTPS trackers not built.

`DownloadTransferHTTPS` never appears in ENVY git history (**code**). Lost at divergence, not deleted in a later ENVY commit.

---

## To reimplement (behaviour, not source)

1. Family-neutral endpoint (D-020) then sockets, cache, security, DNS A/AAAA.
2. G2 optional child **lengths** (same type names `UDP`/`SNA`/`NA`/`QNA`).
3. BT BEP 7/10/11/32 (Shareaza is archaeology after the BEPs).
4. Transfer TLS under existing HTTP engine (D-021), plus stop silent `https://` → port 80.
5. HTTPS trackers via auxiliary WinINet (#88) — cheaper than P2P TLS.
6. Reachability **concept** only (`docs/20_arch/REACHABILITY_PROBE_DESIGN.md`).

---

## Do not reuse

| Item | Why |
| --- | --- |
| `SSL*` on `CConnection` | No cert/hostname check; blocking `SSL_connect`; IPv6 TLS stub |
| `IN_ADDR`/`IN6_ADDR` overload explosion | Blocks D-013 / EnvyCore / #89 |
| Two HostCache maps | One map on the endpoint type |
| `gethostbyname` + first-colon split | No AAAA; breaks `[v6]:port` |
| GeoIP.dat | Plan GeoIP2 (phase 3) |
| ConnectionTest PHP, BugSplat, Qodana, vendored zlib | ENVY already superseded |
| Shareaza ED2K/Kad IPv6 as spec | ENVY ahead; ED2K wire stays IPv4; Kad6 is P3 |
| `IPv6Support.*` as the abstraction | Orphaned, ED2K-oriented, probes `ipv6.google.com` |

---

## Reference only

- Shareaza G2 IPv6 child lengths vs G2 spec.
- Shareaza PEX6 compact layout vs [BEP 11](https://www.bittorrent.org/beps/bep_0011.html).
- Shareaza `ConnectionTest/` as **idea** (external TCP+UDP reachability), never the PHP.
- G1 GGEP TLS (`GGEP_HEADER_TLS_SUPPORT`) — commented in **both** trees.

---

## Uncertain / needs validation

| Question | Why |
| --- | --- |
| WinINet cert policy on catalogue `https://` | Relies on OS store; not unit-tested here |
| Whether any live G2 peers emit 16-byte SNA | Need captures after parser exists |
| Dual-stack listen: `IPV6_V6ONLY=0` vs two sockets | Must measure on Windows 10 1809+ (#89) |
| Web-seed `https://` frequency | Product impact of transfer TLS vs tracker TLS |

---

## IPv6 matrix

| Function | Shareaza | ENVY | Normative ref | Benefit | Risk | Priority | Depends | Future tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Endpoint type | Dual native structs | None (`CEnvyAddress` planned) | D-013, #89 | One type for cache/keys | Churn | P1 | — | parse/format/hash |
| TCP v6 | Live | Missing | BSD sockets | Dual-stack peers | Bind/`V6ONLY` | P1 | Address type | loopback v6 |
| UDP v6 | Live | Missing | G2/BT UDP | Queries/DHT | SGP caps | P1 | Sockets | loopback UDP |
| DNS AAAA | Literals only; hostnames A | `gethostbyname` + colon split | RFC 3493 | Names | First-colon IPv6 bug | P1 | Address type | A/AAAA fixtures |
| HostCache | ser 21 + IPv6 map | ser 2 IPv4 | SCOPE.md | Persist hubs | Disk loss | P1 | Address type | migration |
| Security | `IsDenied(IN6)` | IPv4 only | Ban bypass | Integrity | Mapped v4 tricks | P1 | Address type | CIDR v6 |
| G2 IPv6 | OnPacket IN6; SNA 4/16/20 | IPv4 only | G2 spec | Hub reachability | Wire break | P1 | Sockets + #162 | golden packets |
| BT peers6/PEX6 | Live | Missing | BEP 7/11 | Peer supply | Malformed lists | P1/P2 #88 | Sockets | 18-byte compact |
| DHT nodes6 | C++ wrapper | lib only | BEP 32 | Bootstrap | Split tables | P1/P2 #88 | Sockets | nodes6 parse |
| GeoIP v6 | Legacy GeoIP.dat v6 | IPv4 ipnum | GeoIP2 | UI | Obsolete DB | P3 | Dual-stack | — |
| UPnP v6 | CHECK_TCP6; IGD v4 | IPv4 IGD | PCP | Reachability | CGNAT | P3 | Sockets | — |
| Kad6 | Archaeology | Forbidden until dual-stack + Kad2 | eMule eSE | — | Protocol mix | P3 | #86 | — |

---

## HTTPS matrix

| Function | Shareaza | ENVY | Modern bar | Priority | Action |
| --- | --- | --- | --- | --- | --- |
| Parse `https://` (downloads) | Port 443, `PROTOCOL_SSL` | Strip, port 80, `PROTOCOL_HTTP` | Keep scheme | P1 security | Fail-closed or TLS-intent |
| P2P TLS client | OpenSSL, no verify | None | Cert + hostname + SNI | P1/P2 | Schannel under HTTP engine (D-021) |
| Aux `https://` | WinINet | WinINet | OS store | — | Keep |
| HTTPS trackers | `http:` only | Rejected in `BTInfo` | BEP 7 over TLS | #88 | WinINet |
| Range/Tiger/chunked | HTTPS class clone | HTTP class | Keep ENVY | — | Reuse |
| Redirect `https` | HTTPS class | Cap 5 then `CEnvyURL` downgrade | Scheme allowlist | P1 | With parse fix |
| Remote TLS | HTTP | HTTP | Reverse proxy (D-017) | P4 | Do not mix |
| IPv6 + P2P TLS | Broken (plain TCP) | N/A | TLS on v6 | — | Do not copy |

### `https://example.com/file` path (**code**)

1. `CEnvyURL` `'h'` → `ParseHTTP`.
2. Strip `https://`, `Network.Resolve(..., INTERNET_DEFAULT_HTTP_PORT)`, `PROTOCOL_HTTP`.
3. `CDownloadSource::CreateTransfer` → `CDownloadTransferHTTP`.
4. `ConnectTo(IN_ADDR*, port)` — cleartext TCP.

WinINet is **not** on this path. `ShellExecute` for some UI `https://` links is a **third** path (browser), not a download.

---

## Planned documentation / implementation series

Do not open implementation PRs until D-020/D-021 stay Active and tests in `NETWORK_IPV6_HTTPS_TEST_STRATEGY.md` exist.

```text
This audit
 ├─ ipv6/PLAN.md refresh (#89)
 │   └─ D-020 address ADR
 │       └─ tech: CEnvyAddress (no wire change)
 │           └─ tech: dual-stack sockets (flag off)
 │               ├─ HostCache/Security
 │               ├─ BT IPv6 (#88)  [BEPs first]
 │               └─ G2 IPv6 (#162)
 └─ HTTPS restoration plan
     └─ D-021 TLS ADR
         └─ tech: TLS transport
             └─ tech: transfer integration
 Reachability design (later, security review first)
```

**GitHub cap:** max 3 development PRs (`AGENTS.md` rule 13). Implementation branches wait for slots.

---

## Classification vs backlog

| Topic | Class |
| --- | --- |
| Dual-stack foundation | **PLANNED** (#89); code **MISSING** |
| Phase 0 IPv6 docs | **DONE** (PR #17) |
| `IPv6Support.*` | **OBSOLETE** / orphan |
| P2P HTTPS transfer | **MISSING** (no dedicated issue; overlap #88) |
| Aux HTTPS | **PARTIAL** / kept |
| HTTPS trackers + PEX6 | **PLANNED** (#88) |
| Silent HTTPS downgrade | **MISSING** (security) |
| Kad6 | **PLANNED** P3; blocked |
| Shareaza VS2026 branch | **ALREADY SUPERSEDED IN ENVY** |
