# Architecture

## System Overview
Envy is a Windows desktop monolith with modular subsystems and plugin extension points. Long-term (P1, incremental): extract `EnvyCore` (protocol/transfer/library) behind an internal API while keeping the MFC UI as the first frontend. Inspired by eMule Qt / aMule / aria2-next; not a rewrite (`docs/DEVELOPMENT_PLAN.md`).

**Product status today:** Windows-native (x64 primary, Win32 legacy). Linux and macOS are **planned**, not supported. See `docs/20_arch/PORTABILITY_PLAN.md`.

### Current shape

```text
UI (MFC Wnd/Dlg/Page/Ctrl classes)
  ↕
Application Core (EnvyApp, settings, scheduler, lifecycle)
  ↕
Protocol Engines (BT, G2, ED2K, Kad, DC, HTTP/FTP)
  ↕
Storage/Metadata (Library, schemas, SQLite, cache)
  ↕
Services + Plugins (zlib, bzip2, miniupnp, plugin DLLs)
```

### Target shape (incremental)

Canonical diagram and layering rules live in
[`docs/20_arch/PORTABILITY_PLAN.md`](20_arch/PORTABILITY_PLAN.md) §2.
Short form: EnvyCore + platform abstraction; MFC remains the Windows frontend;
wire formats are never changed merely for portability.

## Main Components
- **Application shell (`Envy/Envy.cpp`)** — startup, command-line options, global state, process control, Crashpad crash capture (`CrashReporter` / `CrashPadHost`, Windows-only).
- **Networking/protocol subsystem**: per-network handlers and transfer state machines.
- **Library subsystem**: file indexing, metadata extraction, schema mapping, sharing rules.
- **Remote management surface (`Remote/`)**: HTML templates for a **partial** browser UI. Not a JSON REST/RPC daemon. Planned native API: `docs/20_arch/remote-api.md`.
- **Plugin host (`Plugins/`)**: media handlers, readers/builders, integration modules.

## EnvyCore interface rule (new work)

New interfaces that belong to the future `EnvyCore` must not expose MFC or Win32 types when a reasonable portable abstraction exists (`CString`, `CFile`, `CList`/`CMap`/`CAtlList`, MFC sync primitives, `HANDLE`, `HWND`, `SOCKET`, `SOCKADDR_IN`, …).

Historical code may keep those types. Windows implementations may use MFC/Win32 **behind** platform or frontend boundaries. Do not mass-migrate existing APIs. Details: `docs/20_arch/PORTABILITY_PLAN.md`, D-013 in `docs/DECISIONS.md`.

Extraction sequence reuses [#91](https://github.com/Mika3578/Envy/issues/91) (test/parser seam) and [#161](https://github.com/Mika3578/Envy/issues/161) (EnvyCore / headless). IPv6 work [#89](https://github.com/Mika3578/Envy/issues/89) uses a portable endpoint type `CEnvyAddress` (D-020; future EnvyCore alias `Envy::Endpoint`). The type is **not in code yet**. Do not add new `SOCKADDR_IN`/`IN6_ADDR` overload pairs at the core boundary. TLS for downloads is a separate stack (D-021), not Shareaza OpenSSL on `CConnection`.

## Build Architecture
- **Primary (full Windows app):** Visual Studio solution (`Visual Studio/Envy.sln`) with many native projects.
- **CMake — full legacy app:** low priority; not authoritative (D-002 / D-004).
- **CMake — portable slice (future target):** foundational for multiplatform — planned `EnvyCore`, parsers, a portable HashLib target, tests, future headless (D-015). These components should eventually build with MSVC, Clang, and GCC without requiring MFC/Windows SDK. Today’s partial CMake still assumes a Windows SDK in places; do not treat non-Windows CMake as available yet.

## Key Design Constraints
1. Windows + MFC coupling is foundational **today**; new core work must stop reinforcing it unnecessarily.
2. Protocol compatibility requires conservative behavior changes.
3. In-tree vendored dependencies reduce external setup but increase maintenance burden.
4. Platforms: Windows x64 implemented (primary); Win32 legacy; Linux/macOS planned only (`docs/20_arch/PORTABILITY_PLAN.md`).

## ADR Notes (Lightweight)
- **ADR-001 (historical):** Keep monorepo with in-tree dependencies for reproducible Windows builds.
- **ADR-002 (active):** Introduce modern tooling (CI, static checks, tests) without breaking existing release path.
- **ADR-003 (active):** Maintain Visual Studio as canonical full-app build while CMake grows for the portable slice.
- **ADR-004 (active):** Cross-platform is a long-term target via EnvyCore + platform abstraction; see D-012 … D-015 and `docs/20_arch/PORTABILITY_PLAN.md`.
