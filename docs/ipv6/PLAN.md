# IPv6 Dual-Stack Implementation Plan (Living)

_Last Updated: 2026-09-20_
_Status Legend: `todo` | `in-progress` | `done` | `deferred` | `not implemented`_

## Goal

Deliver **feature-flagged** IPv6 dual-stack support across Envy networking surfaces while keeping:

- legacy IPv4 peers and trackers working unchanged when the flag is off,
- existing on-disk caches readable (dual-reader + `.bak` on first write),
- IPv4-only deployments as the default until tests exist.

P1 in `docs/DEVELOPMENT_PLAN.md`. **Not implemented** beyond Phase 0 docs. Do not start Kad6 before phases 1–2. Policy: D-008, `docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md`.

Shareaza (`ansani/Shareaza` master) is a **surface inventory**, not a type system. Specs and live clients first; see `docs/20_arch/AUDIT_SHAREAZA_IPV6_HTTPS_2026-09.md`. HTTPS/TLS is a **separate** track (D-021).

## What is not implemented (do not advertise)

| Item | Reality on `develop` (2026-09-20) |
| --- | --- |
| `CEnvyAddress` | Named in docs only (D-020). No type in code. |
| `Settings.Connection.EnableIPv6` / `PreferIPv6` / `IPv6Port` | **Do not exist** in `Settings.cpp`. Earlier revisions of this plan named them as if present. |
| `Settings.eDonkey.PreferIPv6` / `EnableDualStack` / `IPv6ConnectTimeout` | Keys exist; **unwired** to sockets. |
| `Envy/IPv6Support.*` | Sources exist; **not in `Envy.vcxproj`**; no `#include` from other Envy files. Orphan. Not the address abstraction. |
| Dual-stack listen/connect/UDP | IPv4 `SOCKADDR_IN` / `PF_INET` only |
| HostCache IPv6 | Serialization version **2**, `IN_ADDR` map |
| G2 IPv6 children / BT `peers6` / PEX6 / DHT `nodes6` C++ wrapper | Missing |
| Kad6 | Forbidden until this plan’s foundation exists |

Phase 0 documentation (this file + `SCOPE.md`) is **done**. Everything else is `todo`.

## Rollout guardrails (when code exists)

- **Primary flag (to add in Phase 2):** `Settings.Connection.EnableIPv6` default **OFF**.
- **Preference flag (to add):** `Settings.Connection.PreferIPv6` affects dial order only.
- **Fallback:** IPv6 init failure → continue IPv4.
- **Disk:** every cache version bump has a dual-reader; write `.bak` once.

## Shareaza surfaces to cover (behaviour, not copy)

Map each row to a phase. Dual `IN_ADDR`/`IN6_ADDR` overloads are **rejected** (D-020).

| Surface | Phase | Notes |
| --- | --- | --- |
| Address abstraction | 1 | `CEnvyAddress` / future `Envy::Endpoint` |
| TCP listener / connect | 2 | Measure `IPV6_V6ONLY` on Windows 10 1809+ |
| UDP | 2 | Including SGP size caps |
| DNS A/AAAA | 2 | `getaddrinfo`; stop `gethostbyname` + first-colon split |
| HostCache | 3 | One map; migration from ser 2 |
| Discovery | 3 | Shareaza itself still IPv4 here — do better |
| Security / bans | 3 | Mapped-v4 must not bypass v4 bans |
| Persistence | 3 | `hostcache.dat`, `discovery.dat` |
| GeoIP | 3 | GeoIP2, not GeoIP.dat v6 |
| G2 | 6 | Optional children 4/16/18/20 after sockets; #162 |
| BitTorrent peers | 4 | BEP 7 — libtorrent/qBittorrent/Transmission before Shareaza |
| PEX `added6`/`dropped6` | 4 | BEP 10/11; #88 |
| Tracker `peers6` / `&ipv6=` | 4 | HTTP announce; HTTPS trackers are D-021/WinINet |
| DHT `nodes6` | 4 | BEP 32; `dht.c` already has primitives |
| UI | 8 | Bracketed literals; no “IPv6 ready” until 1–2 work |
| Reachability | later | `docs/20_arch/REACHABILITY_PROBE_DESIGN.md` — not Shareaza PHP |
| Tests | 1+ then 9 | Strategy: `docs/40_quality/testing/NETWORK_IPV6_HTTPS_TEST_STRATEGY.md` |

## Phase tracker

| Phase | Scope | Status | Exit criteria |
|---|---|---|---|
| 0 | Scoping, file inventory, migration planning | done | `SCOPE.md` + this plan; 2026-09 audit refresh |
| 1 | Address abstraction (`CEnvyAddress`) + IPv4 bridges (no wire changes) | todo | App identical in IPv4-only mode; unit tests listed in the test strategy |
| 2 | Dual-stack sockets (TCP listen/connect + UDP) + DNS + flag OFF default | todo | Loopback v4-only / v6 / dual locally |
| 3 | Host cache / discovery / Security / GeoIP persistence | todo | New cache versions + old-reader migration tests |
| 4 | BitTorrent BEP 7 / 10 / 11 / 32 | todo | Golden `peers6`/`added6`/`nodes6`; live interop **not** required CI |
| 5 | ED2K transport boundaries (wire stays IPv4 payloads) | todo | No ED2K payload-format regressions |
| 6 | Gnutella2 optional negotiated IPv6 children | todo | Old peers unchanged; do not advertise G2 IPv6 until parse+reply+errors tested |
| 7 | Kademlia family-split tables | deferred | **After** Kad2 IPv4 interop (#86). Kad6 overlay is P3 |
| 8 | UI + settings + address inputs | todo | Display/validation; settings actually wired |
| 9 | Broader integration tests + CI skip-if-no-v6 | todo | Required jobs stay offline |
| 10 | Final docs/security/changelog | todo | No “supported” wording until 1–4 evidence |

## Phase details

### Phase 1 — Address abstraction

See D-020. Introduce `CEnvyAddress` (`sockaddr_storage` behind the Windows adapter; public API family-neutral).

API: parse/format, family, scope id, port, private/loopback/link-local/multicast, ordering/hash, serialization helper, temporary `IN_ADDR` bridges.

Replace call sites **incrementally**. First PR: type + tests only.

**Anti-pattern:** Shareaza-style `IN_ADDR` + `IN6_ADDR` overload pairs.

### Phase 2 — Socket layer dual-stack

- TCP listen: choose `AF_INET6` + `IPV6_V6ONLY=0` **or** two sockets after measuring Windows 10 1809+ (#89). Document the choice in the implementation PR.
- UDP send/recv selects family per endpoint.
- Add `EnableIPv6` / `IPv6Port` / `PreferIPv6` under `Settings.Connection`.
- Resolver: `getaddrinfo` A/AAAA; fix `[v6]:port`.
- UPnP/NAT-PMP v6: log failure, non-fatal (D-009 still IPv4-first).

**Rollback:** `EnableIPv6=false` keeps the old IPv4 bind.

### Phase 3 — Cache / discovery / filter / GeoIP

- One HostCache map keyed by `CEnvyAddress`.
- Bump `hostcache.dat` / `discovery.dat`; dual-reader; `.bak` on first migration.
- Blocklist: v4 and v6 CIDR; mapped-v4 vs v4 ban tests.
- GeoIP2 (phase-3 dependency discussion in `DEVELOPMENT_PLAN.md` before adding to `vcpkg.json`).

### Phase 4 — BitTorrent IPv6

Normative: [BEP 7](https://www.bittorrent.org/beps/bep_0007.html), [BEP 10](https://www.bittorrent.org/beps/bep_0010.html), [BEP 11](https://www.bittorrent.org/beps/bep_0011.html), [BEP 32](https://www.bittorrent.org/beps/bep_0032.html). Then libtorrent, qBittorrent, Transmission, BiglyBT. Shareaza last.

Split PRs if needed: peers6 / tracker / PEX6 / DHT nodes6 (#88).

### Phase 5 — ED2K IPv6 boundaries

- Wire IP fields stay IPv4.
- AAAA/connect to servers is optional transport only.
- Source Exchange IPv6 tuples are **not** in this phase unless a spec + eMule evidence says so.

### Phase 6 — G2 IPv6

- Optional children; never send IPv6 payloads to peers that did not negotiate.
- Lengths: 4 (IPv4), 16 (IPv6 addr), 18/20 (addr+port variants) — confirm against G2 spec + captures, not only Shareaza.
- Do not set a capability bit until parse, process, replies, and errors are tested (#162).

### Phase 7 — Kademlia

- Split tables only after Kad2 IPv4 is honest.
- Kad6 / eSE overlay remains P3.

### Phase 8 — UI

- Bracketed IPv6 with port; family column optional.
- Wire the Connection settings that Phase 2 added.
- Input via `getaddrinfo`, not `inet_addr`.

### Phase 9 — Tests

See `docs/40_quality/testing/NETWORK_IPV6_HTTPS_TEST_STRATEGY.md`. Phase 1 tests land **with** the type, not only at the end.

### Phase 10 — Docs

- `docs/ipv6/ARCHITECTURE.md`, `USER_GUIDE.md`, `ED2K.md` when behaviour exists.
- Changelog: never “IPv6 support” as a blanket Added line.

## Risk register

1. **High:** Signature churn.
2. **High:** Cache migration data loss.
3. **High:** Advertising G2/BT IPv6 before tests.
4. **Medium:** Mixed-family “stable” / firewalled flags.
5. **Medium:** UI truncation of long literals.
6. **Medium:** `IPV6_V6ONLY` surprises on Windows.

## Rollback

- Runtime: `EnableIPv6=false` (once the key exists).
- Code: small PRs per subsystem.
- Data: `.bak` of caches.

## Related

- D-020 address ADR · D-013 EnvyCore types · #89 #88 #162 #179 #230
- HTTPS: `docs/20_arch/HTTPS_TLS_RESTORATION_PLAN.md` (out of this plan)
- Reachability: `docs/20_arch/REACHABILITY_PROBE_DESIGN.md` (later)
