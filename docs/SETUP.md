# Local Setup

## Requirements
- Windows host (native) for full build + runtime validation
- Visual Studio with:
  - Desktop development with C++
  - MFC/ATL components
  - Windows SDK 10.x
- vcpkg for the root `vcpkg.json` manifest (Crashpad). See `docs/10_dev/build.md`.
- NuGet (for restore step used in workflows)

## Clone and Build
```bash
git clone <repo-url>
cd Envy
```

### Visual Studio path (recommended)
1. Restore vcpkg (`scripts/bootstrap-vcpkg.cmd`). Visual Studio does not restore `vcpkg_installed` before `PreBuildEvent`.
2. Open `Visual Studio/Envy.sln`.
3. Restore NuGet packages if prompted.
4. Build `Release|x64` (or desired configuration).

### CMake path (limited)
```bash
cmake -S . -B build -DBUILD_TESTS=ON
cmake --build build
ctest --test-dir build
```

## Runtime Assets
The app expects data/resources from repository folders such as `Data/`, `Languages/`, `Skins/`, and service DLL outputs. Visual Studio post-build steps copy selected assets (e.g., `Vendors.xml`) into output directories.

## Environment Variables
- `VCPKG_ROOT` or `VCPKG_INSTALLATION_ROOT`: bootstrapped vcpkg tree used by `scripts/bootstrap-vcpkg.ps1` (falls back to `.\vcpkg` or PATH).
- No other mandatory project-wide env var file is currently defined in-repo. Most configuration appears to be runtime settings managed by the application itself.
