# IPv6 / HTTPS recovery series (index)

Living index for the documentation-first recovery of dual-stack networking and download HTTPS. Not a claim that either feature ships.

**GitHub:** reuse [#89](https://github.com/Mika3578/Envy/issues/89), [#88](https://github.com/Mika3578/Envy/issues/88), [#162](https://github.com/Mika3578/Envy/issues/162), [#179](https://github.com/Mika3578/Envy/issues/179), [#230](https://github.com/Mika3578/Envy/issues/230). Do not file duplicates. `AGENTS.md` rule 13: max 3 development PRs.

## Documents

| Doc | Role |
| --- | --- |
| [AUDIT_SHAREAZA_IPV6_HTTPS_2026-09.md](AUDIT_SHAREAZA_IPV6_HTTPS_2026-09.md) | Verified gap audit vs `ansani/Shareaza` |
| [../ipv6/PLAN.md](../ipv6/PLAN.md) | Dual-stack rollout |
| [../ipv6/SCOPE.md](../ipv6/SCOPE.md) | File/disk inventory |
| [ADR_NETWORK_ADDRESS_ABSTRACTION.md](ADR_NETWORK_ADDRESS_ABSTRACTION.md) | D-020 |
| [HTTPS_TLS_RESTORATION_PLAN.md](HTTPS_TLS_RESTORATION_PLAN.md) | Transfer vs aux HTTPS |
| [ADR_HTTP_TLS_TRANSPORT.md](ADR_HTTP_TLS_TRANSPORT.md) | D-021 |
| [../40_quality/testing/NETWORK_IPV6_HTTPS_TEST_STRATEGY.md](../40_quality/testing/NETWORK_IPV6_HTTPS_TEST_STRATEGY.md) | Tests before code |
| [REACHABILITY_PROBE_DESIGN.md](REACHABILITY_PROBE_DESIGN.md) | Future external probe |

## Dependency graph

```text
Audit docs
 ├─ IPv6 plan
 │   └─ D-020 address ADR
 │       └─ tech A  net/address-abstraction
 │           └─ tech B  net/dual-stack-socket-foundation
 │               ├─ tech C  net/ipv6-hostcache-security
 │               ├─ tech D  bittorrent/ipv6-peer-support  (#88; split peers6/PEX6/tracker/DHT if large)
 │               └─ tech E  g2/ipv6-foundation  (#162)
 └─ HTTPS plan
     └─ D-021 TLS ADR
         ├─ (early) fail-closed https URL parse
         ├─ tech F  net/https-transport-foundation
         │   └─ tech G  transfer/https-download-support
         └─ HTTPS trackers via WinINet  (#88; independent of F)
 Test strategy  (feeds A–G)
 Reachability design  → tech H later, after security review
```

## Future technical PRs (descriptions only — do not open while architecture PRs are Draft)

| Branch | Scope | Must not include |
| --- | --- | --- |
| `net/address-abstraction` | `CEnvyAddress` + tests + IPv4 bridges | Wire, listen, HostCache rewrite |
| `net/dual-stack-socket-foundation` | parse/resolve, listen, connect, UDP, flag OFF, IPv4 fallback | Full G2/BT/Kad6/UI |
| `net/ipv6-hostcache-security` | family-neutral cache, persist, migration, bans, dedup | Protocol engines |
| `bittorrent/ipv6-peer-support` | BEP 7/11/32 as split PRs if needed | Shareaza as spec |
| `g2/ipv6-foundation` | negotiated children + tests | Capability bit without parser |
| `net/https-transport-foundation` | Schannel session + local TLS tests | `DownloadTransferHTTPS` clone |
| `transfer/https-download-support` | Engine integration | Remote TLS, ADCS |
| Reachability client/server | After design approval | Shareaza PHP |

Trust order remains D-008: spec → modern clients (libtorrent, qBittorrent, Transmission, BiglyBT, eMule where relevant) → Shareaza archaeology → ENVY.
