# Network test strategy — IPv6 and HTTPS

Status: plan. No new required CI jobs in this documentation pass.

- **Date:** 2026-09-20
- **Depends on:** `docs/20_arch/AUDIT_SHAREAZA_IPV6_HTTPS_2026-09.md`, D-020, D-021
- **Rule:** required GitHub checks must stay **local and deterministic**. Never gate merge on the public Internet, STUN, or third-party HTTPS sites.

Live interop (optional, like `tools/interop/`) may use a **maintainer-controlled** probe later. It must remain `workflow_dispatch` / non-required.

## Principles

1. Golden packets and byte fixtures over live hubs.
2. Loopback dual-stack on the CI image is allowed if the runner has `::1` (document SKIP if not).
3. TLS tests use a **repo-local** fixture (self-signed + hostname SAN generated in the test, or checked-in test PKI under `tests/fixtures/tls/` with a documented throwaway CA).
4. No `ipv6.google.com`, no production update servers, no random trackers.
5. Malformed inputs fail closed (existing packet-cap policy).
6. Implementation PRs add the tests for *their* layer; this file lists the backlog so docs PRs do not claim coverage.

## IPv6

| ID | Case | Layer | Required in PR? | Notes |
| --- | --- | --- | --- | --- |
| V6-P01 | Parse IPv4 / IPv6 / `[v6]:port` | Address type | Yes (tech A) | |
| V6-P02 | Format + round-trip | Address type | Yes | RFC 5952 preferred |
| V6-P03 | Invalid (empty, garbage, truncated, extra `]`) | Address type | Yes | |
| V6-P04 | Scope ID (`fe80::1%12` / numeric) | Address type | Yes | |
| V6-P05 | IPv4-mapped `::ffff:a.b.c.d` → canonical IPv4 at trust edge | Address type | Yes | Ban-bypass |
| V6-P06 | Classification: loopback / link-local / multicast / ULA / RFC1918 | Address type | Yes | |
| V6-T01 | TCP loopback `::1` | Sockets | Yes (tech B) | Flag on |
| V6-T02 | UDP loopback `::1` | Sockets | Yes | |
| V6-T03 | v4-only mode (flag off) | Sockets | Yes | Identical to today |
| V6-T04 | v6-only listen (no IPv4 bind) | Sockets | If OS allows | SKIP documented |
| V6-T05 | Dual-stack accept v4 and v6 | Sockets | Yes | Two sockets vs `V6ONLY` |
| V6-H01 | HostCache ser old → new | Cache | Yes (tech C) | `.bak` + dual reader |
| V6-H02 | HostCache new → old reader fails safe | Cache | Yes | No silent truncate |
| V6-S01 | Security deny IPv4, mapped v6, v6 CIDR | Security | Yes (tech C) | |
| V6-D01 | DNS: A-only, AAAA-only, both, NXDOMAIN | DNS | Fixture / mock | No public DNS |
| V6-G01 | G2 SNA/NA/QNA/UDP lengths 4 / 16 / 18 / 20 | G2 | Yes (tech E) | Golden packets |
| V6-G02 | G2 ignore/refuse IPv6 children without negotiation | G2 | Yes | Old peers |
| V6-B01 | Compact `peers6` 18-byte | BT | Yes (tech D) | BEP 7 |
| V6-B02 | PEX `added6`/`dropped6` | BT | Yes | BEP 11 |
| V6-B03 | Tracker bencode `peers6` | BT | Yes | |
| V6-B04 | DHT `nodes6` | BT | Yes | BEP 32 |
| V6-X01 | First-colon hostname:port must not split IPv6 | DNS/URL | Yes (tech A/B) | Current bug |

Public DHT/PEX interop is **optional evidence**, never required CI.

## HTTPS / TLS

| ID | Case | Stack | Required in PR? |
| --- | --- | --- | --- |
| TLS-01 | Valid cert + matching hostname | A Schannel | Yes (tech F) |
| TLS-02 | Untrusted / self-signed (wrong CA) | A | Yes — fail |
| TLS-03 | Expired | A | Yes — fail |
| TLS-04 | Hostname mismatch | A | Yes — fail |
| TLS-05 | SNI sent | A | Yes (capture or Schannel callback) |
| TLS-06 | TLS 1.2 accepted | A | Yes |
| TLS-07 | TLS 1.3 accepted when OS offers | A | Yes / SKIP |
| TLS-08 | TLS 1.0/1.1 refused | A | Yes |
| TLS-09 | Connect IPv4 loopback TLS | A | Yes |
| TLS-10 | Connect IPv6 loopback TLS | A | After dual-stack |
| HTTP-01 | HTTP Range 206 | A+HTTP | Yes (tech G); already HTTP-tested |
| HTTP-02 | Resume / overlapping ranges | A+HTTP | Yes |
| HTTP-03 | Redirect HTTP→HTTPS (cap) | A | Yes |
| HTTP-04 | Redirect HTTPS→HTTP | A | Yes — **fail closed** |
| HTTP-05 | Redirect loop | A | Yes — existing cap 5 |
| HTTP-06 | Unsupported scheme | URL | Yes |
| HTTP-07 | Handshake / body timeout | A | Yes |
| HTTP-08 | Partial body / early close | A+HTTP | Yes |
| HTTP-09 | Invalid `Content-Length` | HTTP | Yes |
| HTTP-10 | Oversized headers | HTTP | Yes |
| HTTP-11 | Malformed chunked | HTTP | Yes |
| URL-01 | Download `https://` must not become port 80 | URL | Yes — even before Schannel |
| AUX-01 | WinINet `https://` fixture | B | Optional; not required CI |

## CI placement

| Suite | Where | Required? |
| --- | --- | --- |
| Address/parse/golden packets | `tests/EnvyTests` (MSVC) | Yes, once code lands |
| Loopback TCP/UDP | EnvyTests or a small console harness | Yes if stable on `windows-2025` |
| TLS fixture | EnvyTests + local listener | Yes for tech F |
| Live reachability | Future probe (see reachability design) | **Never** required |
| `ipv6.google.com` style probes | Forbidden | — |

`IPv6Support`’s external ping pattern is **not** a test strategy.

## Mapping to implementation PRs

```text
tech A address     → V6-P*
tech B sockets     → V6-T*, V6-D01, V6-X01
tech C cache/sec   → V6-H*, V6-S01
tech D BT IPv6     → V6-B*
tech E G2 IPv6     → V6-G*
tech F TLS found.  → TLS-*
tech G transfer    → HTTP-*, URL-01
```
