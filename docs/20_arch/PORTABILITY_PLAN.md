# Cross-platform portability plan

Status: active (planning)
Last updated: 2026-10-20
Scope: Architectural foundations, documentation, and sequencing for a **future** multi-OS Envy.
**Linux and macOS are `planned`, not `supported`.** Do not claim multiplatform product support until those targets compile, run, and have CI evidence.

Canonical companions:

- Status vocabulary: `docs/10_dev/status.md`
- Strategic sequence: `docs/DEVELOPMENT_PLAN.md`
- Decisions: `docs/DECISIONS.md` (D-012 … D-015, D-024)
- Existing extraction work: issues [#91](https://github.com/Mika3578/Envy/issues/91), [#161](https://github.com/Mika3578/Envy/issues/161), [#89](https://github.com/Mika3578/Envy/issues/89)
- Tracker issues filed 2026-09-18: [#177](https://github.com/Mika3578/Envy/issues/177) (parent), [#178](https://github.com/Mika3578/Envy/issues/178) (Win32 policy), [#179](https://github.com/Mika3578/Envy/issues/179) (platform abstraction), [#180](https://github.com/Mika3578/Envy/issues/180) (non-Windows CI)

---

## 1. Current state (verified 2026-10-20 on `develop`)

| Area | Reality |
| --- | --- |
| Product | Windows-native MFC monolith (`Envy/`) |
| Authoritative build | `Visual Studio/Envy.sln` (MSVC `v145`, Win32 + x64) |
| CMake | Partial / non-authoritative (`CMakeLists.txt`, `CMakePresets.json`); HashLib + selected tests |
| vcpkg | `supports: windows & (x86 \| x64 \| arm64)` — Windows-only today |
| CI | GitHub Actions on Windows: x64 + Win32 Release (and Debug on `develop`) |
| Headless / EnvyCore | Not extracted; planned under #161 |
| Protocol test seam | Planned under #91 (parsers/state machines without MFC windows) |
| IPv6 | Helpers exist; core connection path still IPv4-centric (#89, `docs/ipv6/`) |
| Remote/Web | Limited HTML control surface on the P2P HTTP port; not a portable headless API (`docs/20_arch/remote-api.md`) |

Network code still depends heavily on Winsock / Win32 / MFC synchronization (`WSAStartup`, async DNS tied to `HWND` patterns, `SOCKADDR_IN`, `HANDLE`, SEH). That is expected for the current product; it is **debt to bound**, not something this plan rewrites now.

---

## 2. Target architecture

Progressive extraction — never a full rewrite. Keep the MFC Windows frontend while the core becomes portable.

```text
                EnvyCore
                   │
    ┌──────────────┼───────────────┐
    │              │               │
 Protocols     Transfers     Library/Search
    │              │               │
    └──────────────┴───────────────┘
                   │
           Platform Abstraction
     sockets / DNS / filesystem /
     threads / clock / RNG / NAT /
     interfaces / process services
                   │
       ┌───────────┼───────────┐
     Windows      Linux       macOS
       │
   MFC frontend

EnvyCore
   │
Local API / headless
   │
WebUI / CLI / future GUI
```

### Layer responsibilities

| Layer | Owns | Must not own |
| --- | --- | --- |
| **EnvyCore (portable)** | transport framing abstractions, parsers, protocol engines, peer/source management, transfers/queue, hashes/content identity, metadata, library/storage, search/discovery, core settings, events, internal API | MFC UI types, `HWND`, Win32-only public interfaces |
| **Platform abstraction** | sockets, DNS, network interfaces, filesystem, clocks/timers, threads/sync, secure RNG, process/OS integration, NAT traversal hooks, firewall/credential storage integration | protocol wire semantics, UI widgets |
| **Frontends** | MFC Windows (current), headless/daemon, WebUI, CLI; future desktop GUI only after a dedicated evaluation | protocol wire format changes |

Wire protocols (BitTorrent, Gnutella, Gnutella2, ED2K, Kad, NMDC, future ADC) stay **byte-compatible**. Portability must never justify wire-format changes.

Separation that must stay explicit:

```text
protocol logic  vs  platform transport  vs  UI
```

Parsers and state machines are the first portable/testable candidates (#91 → #161).

---

## 3. Essential interface rule (new work only)

> New interfaces that belong to the future `EnvyCore` must not expose MFC or Win32 types when a reasonable portable abstraction exists.

Avoid on **new** core-facing APIs:

- MFC/ATL: `CString`, `CFile`, `CList`, `CMap`, `CAtlList`, `CCriticalSection`, `CEvent`, …
- Win32: `HANDLE`, `HWND`, `SOCKET`, `SOCKADDR_IN`, …

This does **not** mean mass-replacing those types in historical code. Windows implementations may keep MFC/Win32 **behind** platform/frontend boundaries. Do not launch a mechanical `CString` / MFC / Win32 migration.

---

## 4. Product platforms (desired long-term priority)

| Priority | Platform | Status word |
| ---: | --- | --- |
| 1 | Windows x64 | **implemented** (primary) |
| 2 | Linux x86_64 | **planned** |
| 3 | macOS ARM64 | **planned** |
| 4 | Linux ARM64 | planned if useful |
| 5 | Windows ARM64 | **planned** feasibility evaluation (#456); unsupported until it has a real build target, CI, packaging and runtime validation (`CMakePresets` already has an arm64 preset) |
| 6 | macOS x86_64 | optional, only if cost is reasonable or via Universal Binary |

Policy (D-024): the product moves to **64-bit only**. Linux ARM64 is subject to feasibility. iOS is out of scope.

Explicit non-targets (no new work, no support claims):

- Linux x86 32-bit
- macOS 32-bit
- Any other 32-bit product target
- Claiming Linux/macOS “supported” before compile + test + CI evidence

Windows x86/Win32 is not a *new* target: it is the existing **legacy** build, retired in stages (section 5).

---

## 5. Win32 / x86 policy (64-bit-only, phased retirement)

The maintainer decision recorded in D-024 (tracker #178; supersedes D-014) is to retire all 32-bit product targets progressively. This section is policy only: nothing below has been removed yet.

| Role | Status | Policy |
| --- | --- | --- |
| Windows x64 | Implemented, supported | Official primary platform |
| Windows x86 / Win32 | Legacy, scheduled for retirement | Still built, tested and shipped during Stage A; Stage B stops publishing packages, and Stage C removes the target |
| Linux x86_64, macOS ARM64 | Planned | Portable core first; no support claim before compile + test + CI evidence |
| Linux ARM64, Windows ARM64 | Planned, feasibility only (#456) | No support claim |
| macOS x86_64 | Optional | Only if maintenance cost is reasonable |
| Linux x86, macOS 32-bit, iOS | Not targeted | No new work |
| Windows XP / Vista / 7 / 8 / 8.1 | Already unsupported | Dropped earlier; minimum runtime is Windows 10 1809 (`Envy/StdAfx.h`, installer `MinVersion=10.0.17763`). Not part of this retirement; changing the minimum needs its own decision |

Forbidden until the relevant stage PR: dropping Win32 from CI, release artifacts or solution configurations.

### Progressive stages

**Stage A (current):** Win32 builds, CI and release configurations stay intact, and required checks and branch protections stay enforced. Win32 keeps catching type-size, cast, pointer, serialization and 32/64 assumption bugs.

**Stage B (#454):** validate migration of users, settings, libraries, downloads and plugins on x64; stop publishing Win32 installers and portable packages; keep Win32 CI temporarily for regression coverage. The Linux/macOS ports are **not** a prerequisite, provided the residual risks (loss of 32-bit type-size coverage, no 32-bit fallback for end users beyond earlier releases) are documented in the Stage B PR.

**Stage C (#455):** remove Win32 build targets, x86 dependencies and obsolete release infrastructure; remove the remaining Crashpad integration and retain native BugSplat on Windows x64 subject to runtime validation (#353); replace useful Win32 regression coverage with explicit fixed-width serialization, overflow, parsing and portability tests; remove the Win32 CI jobs only together with the `Protect develop` required-check update, never by bypassing protections.

Stage B and C each need their own PR and maintainer approval; this policy does not execute them.

### Out of scope for the retirement

- Win32 *API* names and calls (`HANDLE`, `HWND`, `SOCKET`, ...) are the Windows API, not the 32-bit x86 target, and stay.
- P2P wire formats and legitimate 32-bit protocol fields stay unchanged.
- Legacy compatibility declarations (the Vista/7/8/8.1 `supportedOS` entries in `Envy/Res/Manifest.xml`, the XP-era `_WIN32_WINNT` defaults in `HashLib/stdafx.h`, commented XP blocks in `Envy/StdAfx.h`) are noted for a later technical cleanup and are not edited by the policy PR.

### Planning overlap

| Item | Role | Disposition under this policy |
| --- | --- | --- |
| #178 | Architecture policy | This document and D-024 |
| #454 | Stage B: stop Win32 user releases | Sequenced first; acceptance criteria stay in the issue |
| #455 | Stage C: remove Win32 toolchain and Crashpad | Follows Stage B |
| #353 | BugSplat x64 end-to-end validation | Prerequisite for relying on BugSplat as the sole reporter |
| #449 | Win32 Crashpad toolchain discovery | Closed by Stage C when Crashpad is removed |
| #466 / PR #468 | Unify BugSplat across Win32 and x64 | A BugSplat x86 backend is no longer planned; recommendation: close PR #468 as superseded and fold #466 into #455 (keep only x64 hardening that still applies) |

---

## 6. CMake strategy (clarified)

| Track | Priority | Notes |
| --- | --- | --- |
| Full legacy app via CMake | Low | `Visual Studio/Envy.sln` remains authoritative for the complete Windows MFC product (D-002 / D-004) |
| CMake for portable pieces | **High (foundational)** | `EnvyCore`, portable libs, parsers, HashLib, unit tests, future headless |

Future portable components should build at least with **MSVC, Clang, and GCC** without requiring MFC or the Windows SDK.

Do **not** convert the whole solution to CMake in the portability foundations work.

---

## 7. GUI policy

1. MFC remains the current Windows frontend.
2. First multiplatform objective is **core / headless**, not a new GUI.
3. Remote/WebUI can become a first truly multi-OS UI once a stable local API exists (#161).
4. Qt, wxWidgets, or other desktop toolkits are deferred to a dedicated evaluation issue.
5. No new GUI framework is introduced by this plan.

---

## 8. Network / IPv6 relationship (#89)

Do not abstract the entire stack now. Future network work (especially IPv6 dual-stack) must avoid introducing **new** Windows-only assumptions when a portable type is reasonable.

In particular, the future IPv4/IPv6 address type should be independent of `SOCKADDR_IN` at the core boundary (platform adapters may still map to OS socket addresses).

See `docs/ipv6/PLAN.md` and issue #89.

---

## 9. Dependencies (audit lens — no replacements here)

Classify work by: portable / Windows-only / replaceable / needs abstraction / vendored / vcpkg / license / maintenance.

| Component | Lens (initial) | Notes |
| --- | --- | --- |
| HashLib | Portable candidate | Already has CMake path; priority for multi-compiler builds |
| zlib, bzip2, sqlite3 | Portable (vendored + vcpkg) | Prefer portable APIs at core boundary |
| OpenSSL (vcpkg) | Portable | Prefer over Windows-only crypto for new core paths when practical |
| MiniUPnP | Mostly portable C; Windows NAT/firewall glue is OS-specific | Keep vendored track (D-009); platform layer owns OS integration |
| Crash reporting (x64) | Windows-only BugSplat (SDK v8.0.0, optional upload) | Primary backend (D-020); Stage C keeps BugSplat on x64 after Win32 removal. Not EnvyCore. |
| Crash reporting (Win32) | Windows-only Crashpad (local DB, upload off) | Legacy Stage A capture (D-019); removed in D-024 Stage C (#455). Not EnvyCore. |
| MFC / ATL / Win32 | Windows frontend + historical core coupling | Not a core dependency for new EnvyCore interfaces |
| LibUTP (vendored) | Portable C candidate | Not wired by Envy yet |
| GeoIP DB / data files | Data; OS-agnostic | Path/fs access goes through platform layer |

No large dependency swap is part of the foundations task. See `docs/DEPENDENCIES.md`.

---

## 10. Relation to existing issues

| Issue | Role in this plan |
| --- | --- |
| [#91](https://github.com/Mika3578/Envy/issues/91) | First extraction/test seam: parsers & state machines without UI; feeds EnvyCore |
| [#161](https://github.com/Mika3578/Envy/issues/161) | EnvyCore boundary + headless/API on Windows first |
| [#89](https://github.com/Mika3578/Envy/issues/89) | Dual-stack address/socket foundation; prefer portable address types |
| [#85](https://github.com/Mika3578/Envy/issues/85) | Docs reconciliation; this plan must not reintroduce stale paths |
| Parent portability issue | [#177](https://github.com/Mika3578/Envy/issues/177) — tracks cross-OS sequencing, non-goals, and CI bootstrap criteria |
| Win32 retirement tracker | [#178](https://github.com/Mika3578/Envy/issues/178) — Stages A→C; execution in [#454](https://github.com/Mika3578/Envy/issues/454) and [#455](https://github.com/Mika3578/Envy/issues/455) |
| Platform abstraction | [#179](https://github.com/Mika3578/Envy/issues/179) — sockets/DNS/FS/threads/RNG frontier |
| Non-Windows CI | [#180](https://github.com/Mika3578/Envy/issues/180) — Linux then macOS advisory bootstrap |

**Maintainer note:** Issue create tokens cannot edit existing issues. Please add a short cross-link comment on #91/#161/#89 pointing at #177 and `docs/20_arch/PORTABILITY_PLAN.md` (and D-013 for new core APIs / portable address types).

---

## 11. Phases (documentation-level)

| Phase | Goal | Exit criteria (summary) |
| --- | --- | --- |
| F0 Foundations (this work) | Docs + decisions + issue links | Plan merged; Linux/macOS still `planned` |
| F1 Portable seam on Windows | #91 parsers/tests under MSVC x64 | Deterministic tests in CI without MFC windows |
| F2 EnvyCore / headless on Windows | #161 thin vertical slice + local API | Core init without MFC shell; MFC still works |
| F3 Portable platform stubs | Sockets/FS/threads/RNG behind interfaces | Core builds with Clang/GCC **on Windows or Linux** without MFC |
| F4 Linux x86_64 CI bootstrap | Compile + run portable tests | Linux job exists; **not** a required product gate until green and useful |
| F5 macOS ARM64 CI bootstrap | Same for macOS | Same caution as F4 |
| F6 Optional ARM64 expansion | Linux ARM64 / Windows ARM64 | Interest + cost justified |
| F7 Win32 Stage B/C | Release/CI retirement | #454 then #455, each with its own PR and approval |

Suggested future CI sequence (advisory until portable code exists):

```text
Windows x64
    ↓
portable unit/core tests on Windows
    ↓
Linux x86_64 Clang/GCC
    ↓
macOS ARM64 Clang
    ↓
Linux ARM64 / Windows ARM64 as warranted
```

Win32 remains in current Windows CI through Stage A and, if needed, temporarily through Stage B.

---

## 12. Criteria before calling Linux/macOS “supported”

All of the following:

1. Portable core (or a defined subset) compiles without MFC/Windows SDK.
2. Automated tests run on the target OS in CI.
3. Headless or equivalent non-GUI entry point can start/stop the core safely.
4. Maintainers agree the job is stable enough to document as supported in README/status.
5. No wire-protocol regressions on Windows x64 Release.

Until then, status vocabulary stays **`planned`**.

---

## 13. Non-goals (this foundations work and near-term)

- Porting the MFC app to Linux/macOS
- Removing MFC or rewriting the GUI
- Introducing Qt/wxWidgets/etc.
- Converting the entire repo to CMake
- Mass `#ifdef` forests or mass `CString` replacement
- Removing Win32 builds/tests/artifacts
- Changing protocol wire formats for portability
- Adding Linux/macOS as required CI checks before they compile
- Creating an empty fake `EnvyCore` tree with no usable boundary
- Announcing that Envy “is multiplatform”

---

## 14. Risks

| Risk | Mitigation |
| --- | --- |
| Premature “supported” claims | Status matrix + README wording; F0 docs only |
| Duplicate architecture issues | Reuse #91/#161/#89; one parent tracker |
| CMake vs VS confusion | D-002/D-004/D-015: VS for full app; CMake for portable slice |
| Win32 removed too early | Staged retirement (D-024): migration validation in Stage B, replacement fixed-width/overflow/parsing tests before Stage C |
| Protocol breakage during extraction | D-005; no wire changes for portability |
| Scope creep into Qt rewrite | GUI policy §7 |

---

## 15. Acceptance for the foundations documentation task

- [x] Real `develop` state audited (docs, VS solution, CMake, vcpkg, workflows, issues/PRs)
- [x] No duplicate of #91/#161/#89 scope
- [x] Target diagram and core/platform/UI split documented
- [x] EnvyCore interface rule documented (new APIs only)
- [x] Win32→x64/ARM64 policy documented without removal
- [x] CMake portable-vs-full-app strategy clarified
- [x] Linux/macOS marked `planned`, not `supported`
- [x] Parent / follow-up GitHub issues filed (#177–#180)
- [ ] Docs PR merged under AGENTS.md PR-cap rules
- [ ] Maintainer cross-links on #91/#161/#89 (bot cannot comment)

---

## Related

- `docs/ARCHITECTURE.md`
- `docs/20_arch/architecture.md`
- `docs/DECISIONS.md`
- `docs/DEPENDENCIES.md`
- `docs/ipv6/PLAN.md`
- `docs/API.md`
