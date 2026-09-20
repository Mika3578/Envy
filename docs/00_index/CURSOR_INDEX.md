# Cursor Index (Quick Entry Points)

## Foundation
| Doc | Purpose |
|-----|---------|
| [build](../10_dev/build.md) | Build steps, troubleshooting |
| [guide](../10_dev/guide.md) | Dev workflow, setup |
| [standards](../10_dev/standards.md) | Code standards |
| [contributing](../10_dev/contributing.md) | How to contribute |
| [status](../10_dev/status.md) | Current implementation state (canonical matrix) |
| [architecture](../20_arch/architecture.md) | System design |
| [PORTABILITY_PLAN](../20_arch/PORTABILITY_PLAN.md) | Cross-platform foundations (planned OS targets; EnvyCore / platform / UI) |
| [remote-api](../20_arch/remote-api.md) | Native API / *arr subset / Torznab client (planned); audit 2026-09 |
| [IPv6 plan](../ipv6/PLAN.md) | Dual-stack **not implemented**; D-020; Shareaza = surfaces only |
| [HTTPS/TLS plan](../20_arch/HTTPS_TLS_RESTORATION_PLAN.md) | Transfer HTTPS absent; D-021 Schannel vs WinINet split |

## Planning
- [roadmap](../10_dev/roadmap.md) · [DEVELOPMENT_PLAN](../DEVELOPMENT_PLAN.md) · [modernization-summary](../10_dev/modernization-summary.md) (historical snapshot)
- [REFERENCE_IMPLEMENTATIONS](../30_protocols/REFERENCE_IMPLEMENTATIONS.md) · [DECISIONS](../DECISIONS.md) (D-008, D-012…D-015, D-020/D-021 proposed) · [PORTABILITY_PLAN](../20_arch/PORTABILITY_PLAN.md)
- [Shareaza IPv6/HTTPS audit](../20_arch/AUDIT_SHAREAZA_IPV6_HTTPS_2026-09.md) · [address ADR](../20_arch/ADR_NETWORK_ADDRESS_ABSTRACTION.md) · [TLS ADR](../20_arch/ADR_HTTP_TLS_TRANSPORT.md)

## Protocols
- **ED2K:** [README](../30_protocols/ed2k/README.md) · [gap analysis](../30_protocols/ed2k/ED2K_KAD_GAP_ANALYSIS.md) · [search fixes](../30_protocols/ed2k/ED2K_SEARCH_FIXES.md) · [LowID callback baseline](../30_protocols/ed2k/ED2K_LOWID_CALLBACK_BASELINE.md) · [live interop harness](../../tools/interop/README.md) (#160, opt-in)
- **Kad:** [kad2-compatibility-report](../30_protocols/kad/kad2-compatibility-report.md) (opcode match ≠ live interop)
- **BitTorrent:** [README](../30_protocols/bittorrent/README.md)
- **Bootstrap catalogues:** [bootstrap-sources](../30_protocols/bootstrap-sources.md) (shipped GWC/UHC/`server.met`/hublist/DHT routers ≠ HostCache)

## Quality
- [Security audit](../40_quality/security/SECURITY_AUDIT_REPORT.md) · [Performance audit](../40_quality/performance/performance-audit.md) · [IPv6/HTTPS test strategy](../40_quality/testing/NETWORK_IPV6_HTTPS_TEST_STRATEGY.md)
- [Crash reporting](../10_dev/crash-reporting.md) · [CI/CD audit 2026-09](../10_dev/CI_AUDIT_2026-09.md) · [DevSecOps map](../10_dev/devsecops-envy.md)
