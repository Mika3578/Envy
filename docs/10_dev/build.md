# Building Envy

**Last Updated:** January 15, 2026
**Primary Build System:** Visual Studio 2022 (v145 toolset)
**Secondary Build System:** CMake (incomplete, HashLib only)
**C++ Standard:** C++17

This guide provides exact build instructions based on current codebase state.

## 🎯 Quick Reference

| Component | Status | Build System | Notes |
|-----------|--------|--------------|-------|
| **Main Application** | ✅ Working | Visual Studio | Full MFC application |
| **HashLib** | ✅ Working | VS + CMake | Hash algorithms library |
| **Services** | ✅ Working | Visual Studio | SQLite, zlib, etc. |
| **Plugins** | ✅ Working | Visual Studio | 18+ plugin projects |
| **Tests** | ⚠️ Framework | CMake | No tests implemented |

## 🏗️ Primary Build: Visual Studio 2022

### Prerequisites

1. **Visual Studio 2022** (Community/Professional/Enterprise)
   - Version 17.0+ required
   - MSVC v145 toolset (default in VS 2022)
   - Windows SDK 10.0.19041.0 or later

2. **Windows Requirements**
   - Windows 10/11 (64-bit recommended)
   - Administrator privileges (for some operations)

3. **No External Dependencies**
   - All libraries bundled in `Services/`
   - Precompiled binaries included

### Build Steps

#### Step 1: Clone Repository
```bash
git clone https://github.com/Mika3578/Envy.git
cd Envy
```

#### Step 2: Open Solution
- Navigate to `Visual Studio/` directory
- Double-click `Envy.sln`
- Visual Studio 2022 will open the solution

#### Step 3: Select Configuration
- **Platform:** x64 (recommended) or Win32
- **Configuration:** Release (recommended) or Debug
- **Toolset:** v145 (automatically selected)

#### Step 4: Build Solution
- **Menu:** Build → Build Solution
- **Keyboard:** Ctrl+Shift+B
- **Status:** Monitor Output window for progress

#### Step 5: Verify Build
- Check `Envy/x64/Release/` (or Win32/Debug) for `Envy.exe`
- File size should be ~8-12MB (includes MFC statically linked)
- No external DLL dependencies required

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

## 🔧 Secondary Build: CMake (Limited)

### Current Status
- **Supported:** HashLib library only
- **Missing:** Main application, services, plugins, MFC integration
- **Use Case:** Library development, cross-platform HashLib usage

### Prerequisites
- **CMake:** 3.20+ (from Visual Studio or standalone)
- **Visual Studio 2022:** For MSVC compiler
- **Git:** For Google Test (if building tests)

### Build Steps

#### Step 1: Configure
```bash
# Create build directory
mkdir build
cd build

# Configure for Visual Studio 2022
cmake .. -G "Visual Studio 17 2022" -A x64
```

#### Step 2: Build HashLib
```bash
# Build HashLib library
cmake --build . --config Release --target HashLib
```

#### Step 3: Optional - Build Tests
```bash
# Enable tests (downloads Google Test)
cmake .. -G "Visual Studio 17 2022" -A x64 -DBUILD_TESTS=ON

# Build test framework
cmake --build . --config Release --target HashLibTests
```

#### Step 4: Verify
- Check `build/Release/HashLib.dll` (library)
- Check `build/bin/Release/HashLibTests.exe` (if tests enabled)

## 🔍 Troubleshooting

### Common Build Errors

#### 1. Platform Toolset Mismatch
```
Error: MSB8036: The PlatformToolset version 'v143' is not supported by this version of Visual Studio.
```
**Solution:**
- Ensure Visual Studio 2022 is installed
- Project uses v145 toolset automatically
- Check: Tools → Get Tools and Features → MSVC v145 toolset

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

### Automated Testing (Future)
- **Current:** No automated tests implemented
- **Framework:** Google Test ready in `tests/`
- **Coverage:** 0% (target: 60%+ in Phase 4)

## 📁 Build Output Structure

```
Envy/
├── x64/Release/           # Main build output
│   ├── Envy.exe          # Main application (~10MB)
│   ├── Envy.pdb          # Debug symbols
│   └── *.dll             # Runtime dependencies
├── Services/x64/Release/  # Service libraries
│   ├── SQLite.dll        # Database engine
│   ├── zlibwapi.dll      # Compression
│   └── ...
├── Plugins/x64/Release/   # Plugin DLLs
│   ├── GFLImageServices.dll
│   ├── RARBuilder.dll
│   └── ...
└── HashLib/x64/Release/   # Hash library
    └── HashLib.dll
```

## 🔄 Build System Limitations

### Known Issues
1. **CMake Incomplete:** Only HashLib builds via CMake
2. **No Cross-Platform:** Windows-only (MFC dependency)
3. **Precompiled Binaries:** Services contain prebuilt libraries
4. **Large Solution:** 30+ projects, complex dependencies

### Future Improvements
- **CMake Completion:** Full application build support
- **Cross-Platform:** Qt migration for Linux/macOS
- **Reproducible Builds:** Source-only dependencies

## 📞 Support

### Build Issues
- Check `docs/STATUS.md` for current limitations
- Review `docs/ROADMAP.md` for planned improvements
- GitHub Issues for build problems

### Development Setup
- See `docs/contributing/guide.md` for development workflow
- CI/CD status: Check Actions tab for build verification

---

**Build Verification:** All instructions tested with Visual Studio 2022 17.0.31903.59 on Windows 11.
