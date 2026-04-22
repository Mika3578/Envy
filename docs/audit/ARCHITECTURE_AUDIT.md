# Architecture Audit

- **Date:** 2026-04-22
- **Scope:** Entire repository (`Envy`, `HashLib`, `Services`, `Plugins`, `Remote`, `tests`, build and CI metadata)
- **Method:** Static repository inspection (no Windows build executed in this Linux container)

## Executive Summary
Envy is a large, Windows-first C++ monorepo centered on an MFC desktop client (`Envy`) with auxiliary tools (`TorrentEnvy`, `Unpacker`, `Installer`), in-tree third-party dependencies, and a plugin architecture loaded by the main process. The Visual Studio solution is the authoritative build graph; top-level CMake currently builds only HashLib and optional tests.

## High-Level Structure

```text
User / Network
   │
   ▼
Envy.exe (MFC app, CWinApp)
   ├─ UI windows/dialogs (Wnd*, Dlg*, Page*)
   ├─ Protocol engines (BitTorrent/G2/ED2K/DC/Kademlia)
   ├─ Library/metadata/indexing subsystem
   ├─ Security/filtering subsystem
   ├─ Remote web UI templates + handlers
   ├─ Plugin host (loads Plugins/*)
   └─ Services (SQLite, zlib, miniupnpc, bzip2, GeoIP, BugTrap, UnRAR)

HashLib.dll
   └─ MD4/MD5/SHA/Tiger/AICH/ED2K hash primitives
```

## Entrypoints and Build Graph
- **Primary application entrypoint:** `CEnvyApp theApp` bootstrapped from `Envy/Envy.cpp` (MFC lifecycle + command-line parsing).
- **Solution-level orchestrator:** `Visual Studio/Envy.sln` defines projects and dependencies.
- **Alternative build path:** `CMakeLists.txt` only covers `HashLib` and `tests`, with explicit TODO for full app migration.
- **Auxiliary binaries:** `TorrentEnvy`, `Unpacker`, `Installer`, and numerous `Plugins/*` modules.

## Module Responsibilities and Interactions

### Core application (`Envy/`)
- `Envy.cpp/.h`: process lifecycle, startup sequencing, application-wide state.
- Protocol stacks (`BT*`, `ED*`, `G2*`, `DC*`, `Kademlia*`): peer discovery, transfers, message parsing.
- Library/indexing (`Library*`, `Meta*`, `Schema*`): local catalog, metadata and schema-driven processing.
- UI (`Wnd*`, `Dlg*`, `Ctrl*`, `Page*`): MFC windows, dialogs, toolbars, settings and status panes.
- Security/services (`Security*`, `VersionChecker*`, `VendorCache*`, `Settings*`): content filtering, update checks, policy/config handling.

### Hashing (`HashLib/`)
- Shared cryptographic hash implementation used by core and tests.
- Includes asm-optimized sources for some algorithms and C++ fallbacks.

### Services (`Services/`)
- Vendored libraries compiled in-tree (SQLite, zlib, MiniUPnP, bzip2, BugTrap, UnRAR, etc.).
- Mixed freshness: some components are current (SQLite 3.51.1, zlib 1.3), others are visibly old snapshots (MiniUPnPc 2.0, UnRAR 5.30-era).

### Plugins (`Plugins/`)
- Separate DLL projects loaded by Envy for optional readers/builders/media features.
- Coupling is high with Windows APIs and internal interfaces.

### Remote web UI (`Remote/`)
- HTML/CSS/JS templates and API notes for remote control endpoints.
- Security config exists in JS, but final trust boundaries depend on server-side behavior in C++ code.

## Severity-Ranked Findings

### High
1. **Split build truth (VS solution vs partial CMake)** causes drift risk and onboarding friction.
2. **Very large, mixed-concern `Envy/` module** indicates weak architectural boundaries.
3. **In-tree vendored dependencies with uneven freshness** increase maintenance and security review burden.

### Medium
1. **Plugin surface is broad and tightly coupled**, complicating API evolution.
2. **Remote UI and native app docs are fragmented**, reducing discoverability.
3. **Cross-platform claims conflict with practical Windows/MFC dependency reality.**

### Low
1. **Legacy project files (`.vcproj`) coexist with modern files**, adding noise.
2. **Multiple roadmap/status document streams exist**, increasing inconsistency risk.

## Recommendations
1. Establish a single source of truth for build metadata (either complete CMake migration plan or explicit “VS-only” policy).
2. Define subsystem boundaries (network core, library core, UI shell) and enforce via include/link rules.
3. Inventory all vendored third-party code with owner + update cadence.
4. Create explicit plugin API stability policy with versioned interfaces.
5. Consolidate canonical docs in `/docs` and link/archive legacy planning files.
