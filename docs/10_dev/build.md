# Building Envy

**Last Updated:** September 2026
**Primary:** Visual Studio (`Visual Studio\Envy.sln`, toolset `v145`, C++20 first-party)
**Secondary:** Optional HashLib-only CMake under `HashLib/` (no root CMake)

## Quick reference

| Component | Status | Build |
|-----------|--------|-------|
| **Main app** | ✅ | Visual Studio |
| **HashLib** | ✅ | Visual Studio (optional: `HashLib/CMakeLists.txt`) |
| **Services** | ✅ | Visual Studio |
| **Plugins** | ✅ | Visual Studio |
| **Tests** | 🟡 | Standalone runner in `tests/` (see [status](status.md)) |

## 🏗️ Primary Build: Visual Studio 2026

### Prerequisites

1. **Visual Studio 2026** (Community/Professional/Enterprise)
   - Version 18.0+ required
   - MSVC toolset `v145` (as configured in the `.vcxproj` files)
   - Windows 10/11 SDK (projects target `WindowsTargetPlatformVersion` = `10.0`)

2. **Windows Requirements**
   - Windows 10/11 (64-bit recommended)
   - Administrator privileges (for some operations)

3. **Dependencies**
   - Managed via **vcpkg manifest** (`vcpkg.json`: zlib, bzip2, sqlite3, miniupnpc, openssl, …)
   - Legacy trees under `Services/` remain for in-tree builds being phased toward vcpkg (Phase 3)
### Build Steps

#### Step 1: Clone Repository
```bash
git clone https://github.com/Mika3578/Envy.git
cd Envy
```

#### Step 2: Open Solution
- Navigate to `Visual Studio/` directory
- Double-click `Envy.sln`
- Visual Studio 2026 will open the solution

#### Step 3: Select Configuration
- **Platform:** x64 (recommended) or Win32
- **Configuration:** Release (recommended) or Debug
- **Toolset:** v145 (automatically selected)

#### Step 4: Build Solution
- **Menu:** Build → Build Solution
- **Keyboard:** Ctrl+Shift+B
- **Status:** Monitor Output window for progress

#### Step 5: Verify Build
- Check the project output folder for `Envy.exe`
  - `Envy\Release x64\Envy.exe` (Release x64)
  - `Envy\Debug x64\Envy.exe` (Debug x64)
  - `Envy\Release Win32\Envy.exe` (Release Win32)
  - `Envy\Debug Win32\Envy.exe` (Debug Win32)

### Build Configurations

| Configuration | Purpose | Optimization | Symbols |
|---------------|---------|--------------|---------|
| **Release** | Production | /O2 (Max Speed) | No debug info |
| **Debug** | Development | /Od (Disabled) | Full debug info |

### Platform Differences

| Platform | Address Space | Recommended | Notes |
|----------|---------------|-------------|-------|
| **x64** | 64-bit | ✅ Primary | Better performance, larger files |
| **Win32** | 32-bit | ⚠️ Legacy | Limited to 2GB address space |

## 🔧 Secondary Build: HashLib CMake (optional)

Root `CMakeLists.txt` / `CMakePresets.json` were removed (incomplete
scaffolding; MSBuild remains authoritative). If you need a CMake-only
HashLib configure, use the tree under `HashLib/`:

```bash
cmake -S HashLib -B out/hashlib -G "Visual Studio 18 2026" -A x64
cmake --build out/hashlib --config Release
```

Do not expect the main Envy MFC app, Services, or Plugins to build via CMake
until a dedicated Phase 5 CMake PR.

## 🔍 Troubleshooting

### Common Build Errors

#### 1. Platform Toolset Mismatch
```
Error: MSB8036: The PlatformToolset version 'v145' is not supported by this version of Visual Studio.
```
**Solution:**
- Install a Visual Studio version that provides toolset `v145`, or retarget the solution/projects to the toolset you have installed.
- In Visual Studio: **Project → Retarget solution**, or update **Project Properties → General → Platform Toolset**.

#### 2. Windows SDK Missing
```
Error: Cannot find Windows SDK version 10.0.19041.0
```
**Solution:**
- Install Windows SDK 10.0.19041.0 or later
- VS Installer → Individual Components → Windows SDK

#### 3. MFC Dependencies
```
Error: Cannot open include file 'afxwin.h'
```
**Solution:**
- Ensure MFC is installed: VS Installer → Desktop development with C++ → MFC
- Check project settings: Configuration Properties → General → Use of MFC → Use MFC in a Static Library

#### 4. Unicode Configuration
```
Warning: Mixing Unicode and non-Unicode
```
**Solution:**
- All projects use Unicode character set
- Check: Configuration Properties → General → Character Set → Use Unicode Character Set

### Performance Issues

#### Slow Builds
- **Solution:** Use Release configuration (/O2 optimization)
- **Parallel Builds:** Tools → Options → Projects and Solutions → Build and Run → maximum number of parallel project builds

#### Large Binary Size
- **Expected:** Release build ~8-12MB (MFC statically linked)
- **Debug builds:** Much larger due to symbols

### Missing Dependencies

#### Precompiled Libraries
- **Location:** `Services/` directory
- **Required:** SQLite, zlib, GeoIP, BugTrap, MiniUPnP
- **Status:** All included, no external downloads needed

#### Plugin Dependencies
- **Build Order:** Services → HashLib → Main App → Plugins
- **COM Registration:** Some plugins require registration (admin rights)

## 🧪 Testing Build

### Manual Testing
1. **Launch Envy.exe**
2. **Basic Functionality:**
   - UI loads without crashes
   - Settings dialog accessible
   - Network configuration works

3. **Protocol Testing:**
   - G2 connections (should work)
   - Basic ED2K connections (limited functionality)
   - BT magnet links (basic support)

### Automated Testing
**Current:** CI builds `Visual Studio/Envy.sln` and runs `EnvyTests.exe` after
x64/Win32 Release (PRs) and after Release+Debug (`develop` pushes).

**What exists today:** Standalone integration tests in `tests/`:
- Run via `tests\run_integration_tests.bat` (will compile `tests\test_runner.cpp` if `cl.exe` is on PATH)
- Or compile manually from a Visual Studio Developer Command Prompt

See `tests/INTEGRATION_TEST_README.md` and `tests/MANUAL_CRYPTO_TESTING_GUIDE.md`.

## 📁 Build Output Structure

```
Envy/
├── Envy/Release x64/           # Main application output
│   ├── Envy.exe
│   └── Envy.pdb (if generated)
├── Services/*/Release x64/     # Service libraries (per-project)
├── Plugins/*/Release x64/      # Plugin DLLs (per-project)
└── HashLib/Release x64/        # HashLib output
```

## Embedded web HTML gzip resources

`Envy/Res/About.htm` and `Envy/Res/Browser.htm` are the source HTML pages.
MSBuild `CustomBuild` steps in `Envy/Envy.vcxproj` compress them with the
bundled `Envy/Res/gzip.exe` into `About.htm.gz` / `Browser.htm.gz`, which
`Envy.rc` embeds as `GZIP` resources (`IDR_HTML_ABOUT`, `IDR_HTML_BROWSER`).
At runtime, `LoadHTML` finds the `RT_GZIP` resource and decompresses via
`CBuffer::Ungzip()` before serving/rendering (not served as
`Content-Encoding: gzip`).

Manual regeneration from the repository root (all Envy configurations/platforms
use the same flags via MSBuild `CustomBuild`):

```bat
Envy\Res\gzip.exe -n -c Envy\Res\About.htm > Envy\Res\About.htm.gz
Envy\Res\gzip.exe -n -c Envy\Res\Browser.htm > Envy\Res\Browser.htm.gz
```

`-n` (`--no-name`) forces `mtime = 0` and omits the original filename so two
builds with unchanged HTML produce identical `.gz` bytes. The tracked `.gz`
files must remain valid binary gzip (see root `.gitattributes`: `*.gz binary`).

## 🔄 Build System Limitations

### Known Issues
1. **No root CMake:** App build is MSBuild-only; HashLib has optional local CMake
2. **No Cross-Platform:** Windows-only (MFC dependency)
3. **Precompiled Binaries:** Services contain prebuilt libraries
4. **Large Solution:** 30+ projects, complex dependencies

### Future Improvements
- **Phase 5 CMake (optional):** Full application build support, if pursued
- **Cross-Platform:** Qt migration for Linux/macOS
- **Reproducible Builds:** Source-only dependencies

## Support

- **Limitations / roadmap:** [status](status.md) · [roadmap](roadmap.md)
- **Workflow:** [guide](guide.md)
- **CI:** GitHub Actions (see Actions tab)

---

**Last Updated:** September 2026
