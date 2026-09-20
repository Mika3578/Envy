# Decisions (ADR-lite)

Canonical table: [`docs/DECISIONS.md`](../DECISIONS.md).

Use this file to record decisions that affect architecture, protocol compatibility, security posture, or developer workflow.

### Decision: Reference implementation policy
- **Date:** 2026-09-11
- **Status:** accepted
- **ID:** D-008 in `docs/DECISIONS.md`
- **Context:** Several maintained P2P clients are useful for Envy (eMule Community, aMule, eMule Qt, eMule AI, aria2-next, Ember, Rucio, eMule eSE), but they are not equivalent: some are de-facto ED2K/Kad wire references, others are architecture or experimental overlays.
- **Decision:** Specification / BEP / RFC first; live interoperability second; established implementations third; newer implementations fourth; experimental extensions last. Ember/eSE features are never documented as eMule/Kad2. Envy remains multi-network.
- **Consequences:** ED2K/Kad P0 targets eMule Community and aMule. Kad6 and Ember crypto stay P3/P2 research. BitTorrent/G1/G2/DC are preserved.
- **References:** `docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md`, `docs/DEVELOPMENT_PLAN.md`, `docs/10_dev/status.md`.

### Decision: Cross-platform foundations
- **Date:** 2026-09-18
- **Status:** accepted
- **ID:** D-012…D-015 in `docs/DECISIONS.md`
- **Context:** Envy is a Windows MFC monolith; future multi-OS work must not start as a rewrite or claim unsupported platforms.
- **Decision:** Target EnvyCore + platform abstraction + retained MFC Windows frontend. Linux/macOS are **planned** not supported. New EnvyCore APIs avoid MFC/Win32 types. Win32 stays in CI (Stage A). CMake portable slice is foundational; full-app CMake stays low priority.
- **Consequences:** #91/#161/#89 proceed Windows-first under the portability plan; no required Linux/macOS CI until portable code exists; no Win32 removal without evidence.
- **References:** `docs/20_arch/PORTABILITY_PLAN.md`, `docs/ARCHITECTURE.md`.

### Decision: Remote API stack and *arr adapter
- **Date:** 2026-09-19
- **Status:** accepted
- **ID:** D-017, D-018 in `docs/DECISIONS.md`
- **Context:** Automation (Radarr/Prowlarr/Jackett) needs a real API layer, not HTML Remote query-RPC, and must not mix Torznab search with download-client control.
- **Decision:** Native REST `/api/v1`; inbound `http.sys` on a dedicated localhost port; Torznab via `CHttpRequest`; first *arr adapter is a qBittorrent Web API v2 **subset**.
- **Consequences:** No new HTTP frameworks; no “qBittorrent-compatible” wording until tests; Transmission deferred; OpenAPI only implemented+planned.
- **References:** `docs/20_arch/AUDIT_REMOTE_API_2026-09.md`, `docs/20_arch/remote-api.md`.

### Decision: Crash capture engine (BugTrap replacement)
- **Date:** 2026-09-19
- **Status:** accepted
- **ID:** D-019 in `docs/DECISIONS.md`
- **Context:** Issue #90 must replace obsolete BugTrap without a mandatory SaaS. An in-process `MiniDumpWriteDump` prototype is not strong enough for heap-corruption / stack-overflow / fast-fail.
- **Decision:** Crashpad is the capture engine (local DB, empty upload URL, `SetUploadsEnabled(false)`). Sentry Native is Option B only and is not linked into ENVY. Isolated `tools/crash-probe` records crash-class evidence.
- **Consequences:** Ship `crashpad_handler.exe` next to `Envy.exe`. Keep next-launch GitHub UX. No silent telemetry.
- **References:** `docs/10_dev/crashpad-vs-sentry-native.md`, `docs/10_dev/crash-reporting.md`.

### Decision: Family-neutral network address
- **Date:** 2026-09-20
- **Status:** proposed
- **ID:** D-020 in `docs/DECISIONS.md`
- **Context:** IPv6 recovery must not copy Shareaza `IN_ADDR`/`IN6_ADDR` overload pairs; EnvyCore (D-013) needs a portable endpoint.
- **Decision:** One `CEnvyAddress` value type (family, bytes, port, scope). Layer: endpoint → sockets → cache/security → protocols. First code PR is type+tests only.
- **Consequences:** No dual HostCache maps; `IPv6Support.*` is not the abstraction; G2/BT IPv6 wait on this type.
- **References:** `docs/20_arch/ADR_NETWORK_ADDRESS_ABSTRACTION.md`, `docs/ipv6/PLAN.md`, #89.

### Decision: HTTP/TLS transport split
- **Date:** 2026-09-20
- **Status:** proposed
- **ID:** D-021 in `docs/DECISIONS.md`
- **Context:** P2P HTTPS was lost; auxiliary WinINet `https://` still works. Shareaza OpenSSL did not verify certificates.
- **Decision:** Schannel under the transfer HTTP engine; keep WinINet for catalogues/trackers. Fail closed on download `https://` until TLS exists (no port-80 remap).
- **Consequences:** HTTPS trackers (#88) can proceed on WinINet without Schannel. Remote inbound TLS stays D-017.
- **References:** `docs/20_arch/ADR_HTTP_TLS_TRANSPORT.md`, `docs/20_arch/HTTPS_TLS_RESTORATION_PLAN.md`.

## Template

### Decision: <short title>
- **Date:** YYYY-MM-DD
- **Status:** proposed | accepted | superseded
- **Context:** What problem are we solving?
- **Decision:** What did we decide?
- **Consequences:** Trade-offs, risks, follow-ups.
- **References:** Links to docs, issues, code paths.
