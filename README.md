# Envy

Envy is a Windows-native, MFC-based peer-to-peer client with support for multiple legacy and modern networks (BitTorrent, G2, ED2K/Kad, DC, and related services). The repository is a monorepo containing the main desktop client, plugins, vendored native dependencies, installer tooling, and a growing test suite.

## Quick Start

### Prerequisites
- Windows 10/11 development environment
- Visual Studio with C++ + MFC/ATL workloads
- MSVC platform toolset `v145` (as referenced by project files)
- Optional: CMake 3.20+ (currently partial build support)

### Build (Authoritative path)
1. Open `Visual Studio/Envy.sln`.
2. Select `Debug` or `Release`, and `Win32` or `x64`.
3. Build solution.

### Build (Partial CMake path)
```bash
cmake -S . -B build -DBUILD_TESTS=ON
cmake --build build
ctest --test-dir build
```
> Note: current top-level CMake is intentionally incomplete and mainly covers `HashLib` + selected tests.

## Repository Layout
- `Envy/` – primary desktop application (UI + protocols + library)
- `HashLib/` – hashing library (MD4/MD5/SHA/Tiger/AICH/ED2K)
- `Services/` – vendored third-party native libraries (SQLite, zlib, MiniUPnP, etc.)
- `Plugins/` – optional feature modules loaded by the app
- `Remote/` – remote web UI templates/assets and API notes
- `tests/` – unit/integration test executables and framework glue
- `docs/` – architecture, setup, testing, deployment, and audit docs

## Documentation Index
- Architecture: `docs/ARCHITECTURE.md`
- Setup: `docs/SETUP.md`
- API: `docs/API.md`
- Testing: `docs/TESTING.md`
- Deployment/Release: `docs/DEPLOYMENT.md`
- Contribution guide: `docs/CONTRIBUTING.md`
- Development plan (living): `docs/DEVELOPMENT_PLAN.md`
- Audit reports: `docs/audit/`

## Current State
- Mature C++ codebase with active modernization effort.
- Visual Studio solution is the source of truth for full builds.
- CI workflows exist for build, quality checks, and CodeQL scanning.
