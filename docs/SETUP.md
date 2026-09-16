# Local Setup

## Requirements
- Windows host (native) for full build + runtime validation
- Visual Studio with:
  - Desktop development with C++
  - MFC/ATL components
  - Windows SDK 10.x
- NuGet (for restore step used in workflows)

## Clone and Build
```bash
git clone <repo-url>
cd Envy
```

### Visual Studio path (recommended)
1. Open `Visual Studio/Envy.sln`.
2. Ensure vcpkg manifest integration is available.
3. Build `Release|x64` (or desired configuration), toolset `v145`.

Or from PowerShell (authoritative flags):

```powershell
msbuild "Visual Studio\Envy.sln" /m /p:Configuration=Release /p:Platform=x64 `
  /p:PlatformToolset=v145 /p:WindowsTargetPlatformVersion=10.0 `
  /p:VcpkgEnableManifest=true /p:VcpkgTriplet=x64-windows-static
```

Matrix helper: `.\build_all.ps1`

### Optional HashLib CMake
There is no root CMake app build. For HashLib only:

```bash
cmake -S HashLib -B out/hashlib -G "Visual Studio 18 2026" -A x64
cmake --build out/hashlib --config Release
```

## Runtime Assets
The app expects data/resources from repository folders such as `Data/`, `Languages/`, `Skins/`, and service DLL outputs. Visual Studio post-build steps copy selected assets (e.g., `Vendors.xml`) into output directories.

## Environment Variables
No mandatory project-wide env var file is currently defined in-repo. Most configuration appears to be runtime settings managed by the application itself.
