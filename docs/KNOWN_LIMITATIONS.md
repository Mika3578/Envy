# Known Limitations

This document tracks important current constraints that affect development and validation.

- **Toolchain runner dependency:** Authoritative `v145` parity is not guaranteed in every hosted CI context.
- **Incomplete CMake:** Top-level CMake does not yet model the full authoritative application build.
- **Limited protocol parser tests:** Automated coverage for malformed/edge packet paths remains partial; ED2K SourceEx and inbound length-underflow guards are covered by `tests/test_protocol_parser_smoke.cpp`, but full MFC-linked ReadBuffer integration tests are still absent.
- **ED2K SecureIdent:** eMule-compatible RSA SecureIdent is **not implemented**. As of #75 Envy does not advertise SecureIdent and never marks peers verified; inbound SecureIdent packets are ignored without blocking ED2K transfer. See `docs/DEVELOPMENT_PLAN.md` SecureIdent roadmap and `docs/10_dev/status.md`.
- **ED2K/Kad live interop:** Opcode-level documentation is not a substitute for Envy ↔ eMule Community / aMule transfer tests. Live interoperability remains **unverified**. Phase-1 opt-in harness: `tools/interop/README.md` (#160). Required CI never launches reference clients or depends on the public P2P network.
- **No headless daemon:** Envy is an MFC GUI process. Remote/Web is a limited HTML control surface, not a stable JSON REST engine API. Native `/api/v1` is **planned** (`docs/20_arch/remote-api.md`).
- **Remote bind setting unused:** `Settings.Remote.BindAddress` defaults to `127.0.0.1` but is not applied to a socket; HTML Remote is accepted on the P2P HTTP listener after an IP allowlist check.
- **Legacy UI/core coupling:** MFC and core protocol logic remain tightly coupled in key paths. Long-term extraction is planned (#161); MFC remains the Windows frontend.
- **Not multiplatform yet:** Linux and macOS are **planned**, not supported. Only Windows ships today (x64 primary, Win32 legacy). See `docs/20_arch/PORTABILITY_PLAN.md`.
- **IPv6 dual-stack not implemented:** Phase 0 docs only. `CEnvyAddress` does not exist; `IPv6Support.*` is not compiled; core sockets, HostCache, and Source Exchange are IPv4-only (`docs/ipv6/PLAN.md`, D-020).
- **HTTPS downloads not implemented:** Transfer path remaps `https://` to HTTP port 80. Auxiliary WinINet `https://` catalogues still work. HTTPS BT trackers are rejected (`docs/20_arch/HTTPS_TLS_RESTORATION_PLAN.md`, D-021).
- **CI limitations:** CI signals are useful but not a complete substitute for full local/VS validation. Non-Windows CI is not required until a portable slice exists.
- **Unsigned Preview builds:** Preview installers/Zips published via GitHub Releases are not Authenticode-signed until a certificate is configured in CI. Windows SmartScreen / Smart App Control may block or warn on first run; verify downloads against `SHA256SUMS.txt` on the Release page.
- **Protocol gaps:** Some advanced ED2K/Kad/BitTorrent features remain partial or planned.
- **NMDC live file-list browse:** Hub user list + `files.xml.bz2` browse is wired in code. FileListing directories populate the existing Browse Host left tree (not a DC++-identical share widget); the tree is built before `CNetwork` owns the hit chain. Covered by EnvyTests smokes (no GUI/network). Live tests against a real NMDC hub and DC++ (active and passive, inbound Envy file list) are **not** part of CI and remain unverified here. This is not ADC hub support and not a claim of full DC++ feature parity.
