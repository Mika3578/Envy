# Envy Development Status

**Last Updated:** March 2026  
**Default branch:** `develop`  
**Build baseline:** Visual Studio solution `Visual Studio/Envy.sln` (VS 17.x), MSVC toolset `v145`, C++17 (`stdcpp17`)

This document summarizes the current state of the repository based on what’s actually present in the codebase and build configuration.

## 🏗️ Build & Tooling

### Visual Studio (primary)
- **Status:** ✅ Working in CI and locally
- **Solution:** `Visual Studio/Envy.sln`
- **Toolset:** `v145` (configured in `.vcxproj`)
- **C++ standard:** C++17 (`stdcpp17`)
- **Platforms/configurations:** Win32/x64, Debug/Release
- **Output layout:** projects output to folders like `Envy\Release x64\` (see `Envy/Envy.vcxproj` `OutDir`)

### Local build helper
- `build_all.ps1` builds Debug/Release × Win32/x64 via `MSBuild.exe` (requires MSBuild on PATH).

### CMake (secondary)
- **Status:** ⚠️ Incomplete (HashLib + tests only)
- `CMakeLists.txt` adds `HashLib/` and `tests/` (when `BUILD_TESTS=ON`).
- TODOs remain for the main app, services, and plugins.

## 🧪 Testing

### Automated unit tests (EnvyTests)
- **Status:** ✅ Working in CI and locally
- **Project:** `tests/EnvyTests.vcxproj` (console app, part of `Envy.sln`)
- **CMake:** `tests/CMakeLists.txt` (when `BUILD_TESTS=ON`)
- **Tests:** 12 tests covering HashLib algorithms (MD4, MD5, SHA-1, SHA-256, ED2K)
- **Results:** 12/12 passing (SHA-256 length encoding and message-schedule fixes applied)
- **CI:** Tests run automatically after each build in `.github/workflows/build.yml`

### CI coverage
- CI builds Debug and Release for Win32/x64 (`.github/workflows/build.yml`).
- CI runs unit tests after each build.
- CI also runs code analysis, formatting checks, and markdown link checking (`.github/workflows/code-quality.yml`).

### Legacy integration tests (manual, not compiled)
- `tests/test_runner.cpp` and related `test_*.cpp` files exist but have deep MFC dependencies.
- These tests have never been successfully compiled; they require the Envy core to be refactored into a static library.
- See `tests/INTEGRATION_TEST_README.md`.

## 🔗 Protocols (high-level)

### BitTorrent
- **Status:** ⚠️ Partial / in-progress
- **Evidence:** BT v2 magnet token detection (`btmh:`) exists in `Envy/EnvyURL.cpp`; DHT code exists under `Envy/BitTorrentDHT/`.
- **Typical remaining work:** full BT v2 metadata/Merkle integration, advanced extensions, broader interoperability testing.

### eDonkey2000 / eMule
- **Status:** 🟡 Enhanced, but not “parity” everywhere
- **SecureID:** implemented in `Envy/EDClient.cpp` (uses cryptographically secure random bytes).
- **CryptLayer:** implemented in `Envy/EDClient.cpp` (RSA handshake + RC4 keys).
- **MultiPacket Ext2 / FileIdentifiers:** opcodes and handlers exist (`Envy/EDPacket.h`, `Envy/EDClient.cpp`), but some capability flags are still marked as unsupported in code/comments, so treat this as partially implemented until verified against reference clients.
- **AICH:** `Envy/AICHManager.*` exists; integration tests cover AICH-related behavior.

### Kademlia (Kad2)
- **Status:** 🟡 Implemented; see protocol docs for verification scope
- **Evidence:** `Envy/Kademlia.*` and `Envy/KademliaPlatform.cpp` exist.
- **Docs:** `docs/30_protocols/kad/kad2-compatibility-report.md`

### IPv6
- **Status:** ⚠️ Not broadly integrated yet
- Core connection code is still IPv4-only (`Envy/Connection.cpp` comment: “not IPv6 yet”).
- IPv6 helper utilities exist (`Envy/IPv6Support.*`) but are not widely referenced from core networking code.

### UPnP
- **Status:** ✅ Present
- **Evidence:** UPnP components exist (`Envy/UPnPManager.*`, `Envy/MiniUPnP.*`).

## Next

- [Build](build.md) · [Roadmap](roadmap.md) · [Architecture](../20_arch/architecture.md) · [Protocols](../30_protocols/)
