# Working decision log (archived 2026-11-26)

Status: archived
Last updated: 2026-11-26
Scope: Chronological working decision log formerly kept in `docs/DEVELOPMENT_PLAN.md` ("Decisions Log" section, 2026-04-22 to 2026-10-01).
Source of truth: The canonical decision register is [`docs/DECISIONS.md`](../../DECISIONS.md). Rows D-001…D-024 there supersede the matching entries below; entries without a table row remain historical context only.

## Decisions Log
- **2026-09-19:** Remote automation (D-017, D-018): native REST `/api/v1` as source of truth; inbound API on Windows HTTP Server API (`http.sys`) dedicated port, not `CRemote`/P2P HTTP; outbound Torznab via `CHttpRequest`; first *arr adapter is a qBittorrent Web API v2 **subset**. Details: `docs/20_arch/AUDIT_REMOTE_API_2026-09.md`.
- **2026-09-19 / #354:** Hybrid crash reporting — **x64** uses BugSplat SDK v8.0.0 (`ThirdParty/BugSplat`, `/MT` static lib + out-of-process monitor); **Win32** keeps Crashpad (vcpkg, local DB, upload off). Not Sentry Native, Breakpad, CrashRpt, or homemade `MiniDumpWriteDump`. Canonical: `docs/10_dev/crash-reporting.md` (D-019, D-020).
- **2026-09-18:** Adopt cross-platform foundations (D-012…D-015): EnvyCore + platform abstraction + retained MFC Windows frontend; Linux/macOS `planned` not `supported`; Win32 legacy Stage A only; CMake portable slice prioritized over full-app CMake. Canonical doc: `docs/20_arch/PORTABILITY_PLAN.md`. Open question #1 resolved toward multi-OS **as a long-term target**, with Windows-first delivery.
- **2026-09-17:** #140 wording: MiniUPnPc 2.0 targeted discovery is one receive phase for requested ST values, not a strict wall-clock SSDP deadline; absolute SSDP and HTTP timeout bounding → [#142](https://github.com/Mika3578/Envy/issues/142) / P3.
- **2026-09-18:** #166 / D-009 P1 delivered: WFAS `INetFwPolicy2` replaces `INetFwMgr`; application rules on all profiles; UPnP via rule-group enable. Next: P2 LocalPort/ExternalPort.
- **2026-09-17:** #140 P0 runtime PASS (post-squash HEAD): targeted discovery + gateway-only rootdevice fallback; non-IGD devices never receive WAN mapping commands. Remaining MiniUPnPc 2.0 SSDP/HTTP latency → [#142](https://github.com/Mika3578/Envy/issues/142) / P3. Separate backlog: bind/listen must not wait for NAT completion → [#141](https://github.com/Mika3578/Envy/issues/141). Order remains P1 WFAS → P2 ports → P3 MiniUPnPc 2.3.x.
- **2026-09-17:** SSDP success != usable IGD. #140 uses targeted `upnpDiscoverDevices` with `searchalltypes=1` (one discovery receive phase), filters to explicit IGD/WAN ST, and limits rootdevice fallback to the selected gateway IP with exact LOCATION string dedupe. `UPNP_GetValidIGD` runs once on filtered candidates; results `0`/`3` never issue WAN commands.
- **2026-09-16:** NAT/Firewall recovery is phased PRs (not a monolith): P0 modern interface selection (#140), P1 Windows Firewall WFAS (`INetFwPolicy2`), P2 LocalPort/ExternalPort model (behavior-preserving first), P3 MiniUPnPc 2.3.x **vendored** update (no vcpkg introduction for this alone), P4 NatTraversalManager + PCP/NAT-PMP, P5 CGNAT/diagnostics. Do not declare inbound reachability fixed without runtime evidence on a non-CGNAT path.
- **2026-09-15:** Keep C++ RTTI disabled project-wide (`RuntimeTypeInfo=false` / `/GR-`). Do not enable `/GR` to make `dynamic_cast` work. Protocol-specific actions belong on the transfer/neighbour classes via `virtual`/`override`. Localized `static_cast` is acceptable only when the construction path proves the concrete type (first case: `PROTOCOL_ED2K` uploads are always `CUploadTransferED2K` from `CEDClient::OnQueueRequest`). The protocol enum remains valid for UI, stats, logs, filtering, and serialization.
- **2026-09-11:** Persist `eDonkey.EnableKad` via `Settings.Add` (#124) separately
  from Kad routing-table work (#86) and from Kad→`AddSourceED2K` source delivery.
  Default remains `true` per settings reference; no migration (key never existed).
- **2026-09-11:** For #87 Hello honesty, stop advertising AICH until C2C
  handlers exist. Keep CryptLayer MiscOptions2 bits at 0 until TCP
  obfuscation interop is audited separately from packet PUBLICKEY crypto.
  SecureIdent advertisement remains 0 (#75).
- **2026-09-11:** Adopt an explicit reference-implementation policy (D-008): specifications first; eMule Community/aMule as ED2K/Kad de-facto interop; eMule Qt/aria2-next/eMule AI as architecture; Ember/eSE as experimental only. Envy stays multi-network.
- **2026-09-10:** Runtime performance work starts with reproducible benchmarks (#111). No IOCP rewrite issue until peer-scalability evidence after Buffer/lock optimizations. No dedicated LibraryBuilder hashing issue until measurements show a user-visible bottleneck. #92 stays correctness/stability (lock order); #113 tracks contention separately.
- **2026-09-10:** Adopt a two-speed CI: path-aware PR jobs (`if:`, never
  `paths-ignore` on required workflows), CodeQL C++ `build-mode: none` on PRs
  and manual traced builds on `develop`/schedule, vcpkg files binary cache
  (`x-gha` removed upstream). Required Protect develop check names are listed
  in `.github/settings.yml` (including `PR Gate` as a required CI wait).
- **2026-09-10:** For issue #75, choose safe disable of fake SecureIdent over
  implementing RSA in the same PR. Advertisement stays at version 0 until a
  dedicated RSA SecureIdent workstream lands. ED2K connectivity must not depend
  on SecureIdent.
- **2026-05-27:** Rewrote `develop` into a linear history with no merge commits while preserving the final tree through backup refs; enforce linear history going forward via the active `Protect develop` ruleset (squash-only on `develop`), global GitHub merge settings (no merge commits; squash/rebase enabled), and contributor `git pull --ff-only` hygiene.
- **2026-05-15:** Repository hygiene baseline on `develop` requires explicit branch-state tracking and GitHub label prerequisites (`ci`, `dependencies`) before enforcing CI as mandatory gates.
- **2026-04-22:** Added IPv6 dual-stack Phase 0 scoping inventory and phased rollout plan under `docs/ipv6/`.
- **2026-04-22:** Remote web UI must use cryptographic token generation (`crypto.getRandomValues`) and allowlist-based redirect validation for all client-side navigation paths.
- **2026-04-22:** Keep Visual Studio solution as authoritative full-build path while CMake remains partial.
- **2026-04-22:** Standardize new audit reports under `docs/audit/`.
- **2026-04-22:** Treat this plan as a required living artifact for project management continuity.

## Open Questions
1. ~~Should this project explicitly remain Windows-only, or is cross-platform parity still a target?~~ **Resolved 2026-09-18 (D-012):** long-term multi-OS via EnvyCore; Windows remains the only supported product OS until Linux/macOS meet support criteria in `PORTABILITY_PLAN.md`. Headless/API still proceeds on Windows first (#161).
2. What is the acceptable backward-compatibility policy for legacy protocols/features? Working default: preserve G1/G2/DC/BitTorrent; ED2K/Kad changes must remain eMule/aMule-compatible unless versioned as optional Envy extensions.
3. Which dependency update cadence (monthly/quarterly) is realistic for maintainers?
4. ~~Should remote API documentation be strict contract-first or implementation-first?~~ **Resolved 2026-09-19:** OpenAPI describes **implemented** routes plus explicitly `planned` ones (`x-envy-status`). No fictional served surface. See `docs/api/openapi.yaml`.
5. ~~REST versus JSON-RPC for a future Envy daemon API?~~ **Resolved 2026-09-19 (D-017/D-018):** native **REST** `/api/v1` (OpenAPI). qBittorrent-shaped REST subset for *arr. Transmission JSON-RPC is not the first adapter. aria2 JSON-RPC is a reference only.
6. Which Preview/stable release carries the Win32 Stage B cut-over (#454), and which prior release is documented as the 32-bit fallback?
