# D-020 — Family-neutral network endpoint

Status: **Proposed** (docs only; no type exists in code).

- **Date:** 2026-09-20
- **Issues:** [#89](https://github.com/Mika3578/Envy/issues/89), [#179](https://github.com/Mika3578/Envy/issues/179)
- **Audit:** `docs/20_arch/AUDIT_SHAREAZA_IPV6_HTTPS_2026-09.md`
- **Plan:** `docs/ipv6/PLAN.md`

## Context

ENVY sockets, HostCache, Security, Discovery, G2, BitTorrent, and most UI paths still carry `IN_ADDR` / `SOCKADDR_IN`. Shareaza `master` added parallel `IN6_ADDR` / `SOCKADDR_IN6` overloads. That recovered dual-stack *surfaces* but duplicated every API. It also blocks D-013 (portable EnvyCore) and #179 (portable sockets/DNS).

`CEnvyAddress` is named in `docs/ipv6/PLAN.md` and `docs/ARCHITECTURE.md`. The type is **not implemented**. `Envy/IPv6Support.*` is an ED2K-oriented helper, **not listed in `Envy.vcxproj`**, and is not this ADR’s type.

## Decision

Introduce one **endpoint abstraction**, then migrate layers inward:

```text
Endpoint (family + bytes + port + scope)
        ↓
socket layer (listen / connect / UDP)
        ↓
host cache / security / discovery
        ↓
protocol engines (G2, BT, ED2K transport, DC)
        ↓
UI / settings / logging
```

Do **not** copy Shareaza’s `ConnectTo(IN_ADDR*)` + `ConnectTo(IN6_ADDR*)` (and the matching HostCache/Security/QueryKeys explosion).

Windows first. Portable EnvyCore may later expose `envy::Endpoint` without MFC/`SOCKET` types (D-013). The first Windows type may wrap `sockaddr_storage` internally.

### Name

Keep **`CEnvyAddress`** for the first Windows/MFC-facing type:

| Candidate | Verdict |
| --- | --- |
| `CEnvyAddress` | **Chosen.** Already in plan/#89; matches `CEnvyURL` / `CEnvyFile`. |
| `CEnvyEndpoint` | Clearer (address+port) but a rename-only churn. Revisit if EnvyCore lands a portable name first. |
| `IPv6Address` / `CIPv6Manager` | Reject. Family-specific; orphaned `IPv6Support`. |
| Shareaza dual native structs | Reject. |

A later portable alias `envy::Endpoint` is allowed; do not bikeshed the name in protocol PRs.

## Required operations

The type must cover at least:

| Area | Requirement |
| --- | --- |
| Family | `Unspec` / `IPv4` / `IPv6` (no other families in v1) |
| IP bytes | 4 or 16; never mixed |
| Port | `uint16_t` host order in the object; network order only at socket/wire edges |
| IPv6 scope ID | Stored; required for link-local bind/connect |
| Parse | Dotted IPv4; RFC 5952 IPv6; `[v6]:port`; `v4:port`; reject first-colon split of IPv6 |
| Format | Bracket when port is shown with IPv6 |
| Comparison | Family + bytes + port + scope; define whether unspecified port matches |
| Hash | Stable for `CMap` / `std::unordered_*` keys |
| Classification | loopback, link-local, multicast, private/reserved (RFC 1918 / 4193 / 4291 / 6890) |
| IPv4-mapped IPv6 | Detect `::ffff:0:0/96`; **normalize to IPv4** at trust boundaries (bans, HostCache keys) unless a documented exception exists |
| Serialization | `family_tag + length + bytes + port [+ scope]`; versioned |
| Legacy bridge | `FromIN_ADDR` / `ToSOCKADDR_IN` during migration; fail closed if family mismatch |

Out of v1: Unix sockets, Bluetooth, onion, IPv4-compatible `::a.b.c.d` (deprecated).

## Migration

1. Type + unit tests. No protocol call-site rewrite in the first implementation PR.
2. Temporary IPv4 bridges next to `ConnectTo(IN_ADDR*)`.
3. Socket layer behind **`Settings.Connection.EnableIPv6` default OFF** (flag does not exist yet; do not document it as present).
4. HostCache/Security/Discovery disk version bumps with dual readers + `.bak`.
5. Protocol engines only after sockets + cache.

No mass `IN_ADDR` → `CEnvyAddress` sweep.

## Compatibility

| Surface | Impact |
| --- | --- |
| IPv4 | Must be bit-identical when the flag is off |
| Wire | None in the type-only PR |
| Disk | None until HostCache/Security PRs |
| Win32 / x64 | Both; test pointer/size assumptions |
| UI | None until a later display PR |
| Plugins | No public plugin ABI for addresses today |

## Security

- Mapped IPv6 used to bypass IPv4 bans must canonicalize before `IsDenied`.
- Link-local without scope must not be treated as globally reachable.
- Multicast/reserved must not become HostCache “good hubs”.
- Parser must bound length; no `gethostbyname` inside the type.

## Alternatives considered

| Option | Why not |
| --- | --- |
| Dual `IN_ADDR`/`IN6_ADDR` APIs (Shareaza) | N× overloads; Win32 types leak into EnvyCore |
| Keep `DWORD` IPv4 forever | Cannot represent AAAA or G2 16-byte SNA |
| Boost.Asio / other socket libs | New dependency; MFC `SOCKET` already used |

## Follow-up

Implementation PR name (not opened in this pass): `net/address-abstraction`. Tests: `docs/40_quality/testing/NETWORK_IPV6_HTTPS_TEST_STRATEGY.md`.
