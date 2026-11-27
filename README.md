# Envy

[![Build](https://github.com/Mika3578/Envy/actions/workflows/build.yml/badge.svg)](https://github.com/Mika3578/Envy/actions/workflows/build.yml)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](LICENSE)

Envy is a free, open-source, Windows-native **multi-network peer-to-peer client**: BitTorrent (DHT, magnet links), Gnutella, Gnutella2, eDonkey2000/Kad, and Direct Connect in one application, with library management and multi-network search. It is licensed under the [GNU AGPL-3.0-or-later](LICENSE). The repository is a monorepo containing the main desktop client, plugins, vendored native dependencies, installer tooling, and a growing test suite.

**Supported product OS today:** Windows (x64 primary; Win32 legacy). **Linux and macOS are planned, not supported** — see `docs/20_arch/PORTABILITY_PLAN.md`.

Envy is not an eMule replacement and is not replaced by aMule, eMule Qt, aria2-next, or similar projects. Those are interoperability and architecture **references**; see `docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md`.

## Envy Preview Builds

The modernized version of Envy is currently under active development.

**Latest test release target:** Envy 4.2.0 Preview 1 (`v4.2.0-preview.1`)

- **Windows x64:** recommended download
- **Windows x86 (Win32):** legacy, scheduled for retirement (64-bit-only policy, D-024); no new 32-bit targets
- **Portable ZIP:** diagnostic / no-installer runs

Download builds from the GitHub [Releases](https://github.com/Mika3578/Envy/releases) page once Preview 1 is published.

This is **preview** software. Some P2P protocol functionality is still under development. Preview installers are **not Authenticode-signed**; Windows SmartScreen may warn on first run. See `docs/KNOWN_LIMITATIONS.md`.

## Quick Start

### Prerequisites
- Windows 10/11 development environment
- Visual Studio 2026 with the "Desktop development with C++" workload, including MFC and ATL components
- MSVC platform toolset `v145` (as referenced by project files)
- vcpkg (root `vcpkg.json` / Crashpad). Restore with `scripts/bootstrap-vcpkg.cmd` before the first Visual Studio build — see `docs/10_dev/build.md`
- Optional: CMake 3.20+ (currently partial build support)

### Build (Authoritative path)
1. Restore vcpkg: `scripts/bootstrap-vcpkg.cmd` (x64) or `-Triplet x86-windows-static` (Win32).
2. Open `Visual Studio/Envy.sln`.
3. Select `Debug` or `Release`, and `Win32` or `x64`.
4. Build solution.

### Build (Partial CMake path)
```bash
cmake -S . -B build -DBUILD_TESTS=ON
cmake --build build
ctest --test-dir build
```
> Note: current top-level CMake is intentionally incomplete and mainly covers `HashLib` + selected tests.

## How to contribute
Contributions of code, translations, skins, and docs are welcome. Start here:

1. Read the contributor guide: [.github/CONTRIBUTING.md](.github/CONTRIBUTING.md) (setup, PR workflow, review gates).
2. Pick a starter task from the [good first issue](https://github.com/Mika3578/Envy/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22) list, or browse [help wanted](https://github.com/Mika3578/Envy/issues?q=is%3Aopen+is%3Aissue+label%3A%22help+wanted%22).
3. For larger changes, check `docs/DEVELOPMENT_PLAN.md` and open an issue to discuss the approach first.

## Community
- Questions and ideas: [GitHub Discussions](https://github.com/Mika3578/Envy/discussions)
- Bugs and feature requests: [GitHub Issues](https://github.com/Mika3578/Envy/issues)
- Security reports: follow `.github/SECURITY.md`; please do not open a public issue for a vulnerability.

## Repository Layout
- `Envy/` – primary desktop application (UI + protocols + library)
- `HashLib/` – hashing library (MD4/MD5/SHA/Tiger/AICH/ED2K)
- `Services/` – vendored third-party native libraries (SQLite, zlib, MiniUPnP, etc.)
- `Plugins/` – optional feature modules loaded by the app
- `Remote/` – remote web UI templates/assets and API notes
- `tests/` – unit/integration test executables and framework glue
- `docs/` – architecture, setup, testing, deployment, and audit docs

## Documentation Index

### Canonical project docs
- **Strategic roadmap/decisions:** `docs/DEVELOPMENT_PLAN.md`
- **Protocol/architecture status matrix:** `docs/10_dev/status.md`
- **Technical modernization roadmap:** `docs/10_dev/roadmap.md`
- **External P2P references (spec first):** `docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md`
- **Session notes (gitignored):** `.local/DEV_TRACKER.md` (`docs/DEV_TRACKER.md` is gitignored and not committed)

### Contributor and governance docs
- Contribution guide: `.github/CONTRIBUTING.md` (compat pointer: `docs/CONTRIBUTING.md`)
- PR workflow checklist: `docs/PR_PLAYBOOK.md`
- Decision log (ADR-lite): `docs/DECISIONS.md`
- Known limitations: `docs/KNOWN_LIMITATIONS.md`
- Recommended issue/PR labels: `docs/LABELS.md`
- Dependency register (initial seed): `docs/DEPENDENCIES.md`

### Supporting references
- Architecture: `docs/ARCHITECTURE.md` · portability foundations: `docs/20_arch/PORTABILITY_PLAN.md`
- Setup: `docs/SETUP.md`
- API: `docs/API.md`
- Testing: `docs/TESTING.md`
- Deployment/Release: `docs/DEPLOYMENT.md`
- Audit reports: `docs/audit/`

## Current State
- Mature C++ codebase with active modernization effort.
- Visual Studio solution is the source of truth for full builds.
- CI workflows exist for build, quality checks, and CodeQL scanning.

## License
Envy is licensed under the **GNU Affero General Public License v3.0 or later** — see [`LICENSE`](LICENSE). Some bundled visual resources and third-party components carry additional terms; see [.github/CONTRIBUTING.md](.github/CONTRIBUTING.md) and `docs/DEPENDENCIES.md`.
