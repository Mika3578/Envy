# Dependency Register (Initial Seed)

> Status: **Incomplete baseline**. This is a starting register, not a full audited SBOM.
> Portability lens added 2026-09-18 (`docs/20_arch/PORTABILITY_PLAN.md`). No dependency replacements in that foundations work.

| Dependency / Component | Location | Purpose | Portability | Owner / Status | Risk | Update Strategy | Notes |
|---|---|---|---|---|---|---|---|
| HashLib (in-repo) | `HashLib/` | Hashing primitives used by core/tests | **Portable candidate** (CMake path exists) | Owner TBD / Active | Medium | Manual review + targeted tests | Prefer multi-compiler builds (MSVC/Clang/GCC) without MFC |
| SQLite (vendored + vcpkg) | `Services/` / vcpkg | Data persistence | Portable | Owner TBD / Active | Medium | Periodic vendor sync + CVE review | Confirm exact version mapping in follow-up PR (#83) |
| zlib (vendored + vcpkg) | `Services/` / vcpkg | Compression support | Portable | Owner TBD / Active | Medium | Periodic vendor sync + CVE review | Common attack surface in parser/decompression flows |
| bzip2 (vendored + vcpkg) | `Services/Bzlib` / vcpkg | Compression | Portable | Owner TBD / Active | Low | Vendored MSVC project + vcpkg cadence | Authoritative app build uses `Services/Bzlib` |
| OpenSSL (vcpkg) | vcpkg | Crypto (planned for new core paths) | Portable | Owner TBD / Planned | Medium | vcpkg + CVE review | No current Envy source or build target consumes OpenSSL |
| MiniUPnP (vendored) | `Services/MiniUPnP` | NAT traversal / port mapping | Mostly portable C; OS glue is platform-specific | Owner TBD / Active | Medium | Vendored sync to MiniUPnPc 2.3.x + absolute SSDP/HTTP timeout bounding (D-009 / #142); not vcpkg-only for now | Currently 2.0 (2016); Windows firewall/NAT integration stays in platform layer |
| UnRAR-related code | `Envy/` + vendor paths | Archive extraction support | Mixed | Owner TBD / Active | High | Security-first updates with regression tests | Prior traversal-class vulnerabilities require continued scrutiny |
| LibUTP (vendored) | `Services/LibUTP` | uTP transport (unused by Envy yet) | Portable C candidate | Owner TBD / Unused | Medium | Leave until BT uTP work (#88) | Not wired |
| BugTrap (vendored) | `Services/BugTrap` | Crash reporting (legacy on `develop`) | **Windows-only** | Owner TBD / Legacy | Medium | Replacement track (#90, D-017 Crashpad) | Do not treat as EnvyCore; do not reintroduce after removal |
| Crashpad (evaluation) | `tools/crash-probe` only | Out-of-process crash capture | **Windows-only** | Evaluation (#90) | Medium | vcpkg port `crashpad` 2026-07-02; not in root `vcpkg.json` | Upload off; see `docs/10_dev/crashpad-vs-sentry-native.md` |
| sentry-native (evaluation) | `tools/crash-probe` only | Option B dashboard SDK (Crashpad backend) | **Windows-only** | Evaluation (#90) | Medium | vcpkg 0.16.0 on ENVY baseline; `backend` feature only | `wer` feature is `windows & !static`; not a product dep yet |
| MFC / ATL / Win32 | system / VS | UI + historical app coupling | **Windows-only** | Active product UI | High for portability | Keep for Windows frontend; ban from **new** EnvyCore APIs (D-013) | Not removed; not a portable core dependency |
| GeoIP data | `Data/` | Geo lookup data | OS-agnostic data | Active | Low | Data refresh process | Access via filesystem platform API |
| gtest (vcpkg feature) | vcpkg `tests` feature | Unit tests | Portable | Owner TBD / Unused | Low | Remove unused feature or wire tests to gtest | Current `tests/` uses the in-repo `TestSuite` framework |

## Portability classes (how to read the column)

| Class | Meaning |
| --- | --- |
| Portable / portable candidate | Can live under EnvyCore or tests without Windows SDK/MFC |
| Windows-only | Stays on Windows frontend or Windows platform adapter |
| Needs abstraction | Usable long-term only behind a platform interface |
| Vendored vs vcpkg | Prefer vcpkg for new portable deps when license-clean (AGENTS.md: no GPL-2/3); MiniUPnP remains vendored for the NAT track (D-009) |

## Follow-up Required
- Assign explicit owners for top dependencies.
- Add exact version identifiers and upstream source links.
- Add update cadence and validation checklist per dependency.
- When non-Windows CI starts, extend `vcpkg.json` `supports` only for packages actually built off Windows (separate PR).
