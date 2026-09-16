# Envy

Envy is a Windows-native, MFC-based **multi-network** peer-to-peer client (BitTorrent, Gnutella, Gnutella2, ED2K, Kad, Direct Connect, Remote/Web, plus library and multi-network search). The repository is a monorepo containing the main desktop client, plugins, vendored native dependencies, installer tooling, and a growing test suite.

Envy is not an eMule replacement and is not replaced by aMule, eMule Qt, aria2-next, or similar projects. Those are interoperability and architecture **references**; see `docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md`.

## Quick Start

### Prerequisites
- Windows 10/11 development environment
- Visual Studio 2026 with C++ + MFC/ATL workloads
- MSVC platform toolset `v145`
- [vcpkg](https://vcpkg.io/) (manifest mode; see `vcpkg.json`)

### Build (authoritative)

The **canonical Windows build** is `Visual Studio/Envy.sln` (MSBuild, toolset
`v145`, vcpkg manifest). That is the only path that builds the full Envy
application, plugins, and installer-facing outputs.

```powershell
msbuild "Visual Studio\Envy.sln" /m /p:Configuration=Release /p:Platform=x64 `
  /p:PlatformToolset=v145 /p:WindowsTargetPlatformVersion=10.0 `
  /p:VcpkgEnableManifest=true /p:VcpkgTriplet=x64-windows-static
```

Or open `Visual Studio/Envy.sln` and build, or run `.\build_all.ps1` for the
Debug/Release × Win32/x64 matrix.

There is **no root CMake app build**. Optional CMake under `HashLib/`
supports auxiliary library work only — it does **not** produce the Envy MFC
client. Tests are MSBuild-first (`tests/EnvyTests.vcxproj`).

### Version

Canonical product version metadata lives in `version.json`. Other files
(`vcpkg.json` `version-string`, installer scripts) should follow it; do not
edit version numbers in multiple places by hand.

### License

AGPL-3.0-or-later: root [`LICENSE`](./LICENSE) (same text as
`Envy/AGPL-License.txt`, kept for historical installer/docs paths).

## Repository Layout
- `Envy/` – primary desktop application (UI + protocols + library)
- `HashLib/` – hashing library (MD4/MD5/SHA/Tiger/AICH/ED2K)
- `Services/` – legacy vendored third-party trees (phasing toward `vcpkg.json`)
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
- Contribution guide: `docs/CONTRIBUTING.md`
- PR workflow checklist: `docs/PR_PLAYBOOK.md`
- Decision log (ADR-lite): `docs/DECISIONS.md`
- Known limitations: `docs/KNOWN_LIMITATIONS.md`
- Recommended issue/PR labels: `docs/LABELS.md`
- Dependency register (initial seed): `docs/DEPENDENCIES.md`

### Supporting references
- Architecture: `docs/ARCHITECTURE.md`
- Setup: `docs/SETUP.md`
- API: `docs/API.md`
- Testing: `docs/TESTING.md`
- Deployment/Release: `docs/DEPLOYMENT.md`
- Quality notes: `docs/40_quality/` (security checklist + analysis summaries)

## Current State
- Mature C++ codebase with active modernization effort.
- Visual Studio solution is the source of truth for full builds.
- CI workflows exist for build, quality checks, and CodeQL scanning.
