# Envy - Peer-to-Peer File Sharing Application

[![Build Status](https://github.com/Mika3578/Envy/workflows/Build%20and%20Test/badge.svg)](https://github.com/Mika3578/Envy/actions)
[![Code Quality](https://github.com/Mika3578/Envy/workflows/Code%20Quality/badge.svg)](https://github.com/Mika3578/Envy/actions)
[![CodeQL Security](https://github.com/Mika3578/Envy/workflows/CodeQL%20Security%20Scan/badge.svg)](https://github.com/Mika3578/Envy/actions)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

**Version:** 4.0  
**License:** AGPL v3.0  
**Status:** Modernization in Progress

## Overview

Envy is a comprehensive peer-to-peer file sharing application supporting multiple protocols including BitTorrent, Gnutella2 (G2), and eDonkey2000. Built with C++ using MFC (Microsoft Foundation Classes), it provides a feature-rich P2P client with extensive plugin support.

## 📖 Project Origins

Envy is a mature fork of Shareaza, originally developed as a multi-network peer-to-peer filesharing and torrent client. The project is available on SourceForge at [https://sourceforge.net/projects/getenvy/](https://sourceforge.net/projects/getenvy/), where it continues to be actively maintained and developed.

**Key Features from SourceForge:**
- Multi-protocol support: BitTorrent/DHT, G2/Gnutella², Gnutella, ED2K/eMule, DC++, HTTP/FTP
- Highly skinnable interface with extensive customization options
- Built-in blacklist support for content filtering
- Cross-platform compatibility (Windows or Wine)

This repository represents the modernization and continued development of the Envy P2P client, focusing on infrastructure updates, protocol enhancements, and codebase improvements while maintaining compatibility with the established P2P networks.

## 🚀 Quick Start

### Prerequisites

- **Visual Studio 2026** (or Visual Studio 2022 with v143 toolset)
- **Windows SDK** 10.0.19041.0 or later
- **CMake** 3.20+ (optional, for modern builds)
- **Git** 2.30+

### Building with Visual Studio

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-org/envy.git
   cd envy
   ```

2. **Open solution:**
   - Open `Visual Studio\Envy.sln` in Visual Studio 2026

3. **Select configuration:**
   - Configuration: Release/Debug
   - Platform: x64/Win32
   - Platform Toolset: v145 (VS2026)

4. **Build:**
   - Build → Build Solution (Ctrl+Shift+B)
   - Or use: `.\scripts\verify-build.ps1`

### Building with CMake

```powershell
# Create build directory
mkdir build
cd build

# Configure (Windows)
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build . --config Release --parallel

# With tests
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
cmake --build . --config Release
ctest --config Release
```

## 📋 Development

### Code Formatting

**Check formatting:**
```powershell
.\scripts\format-code.ps1 -CheckOnly
```

**Format code:**
```powershell
.\scripts\format-code.ps1
```

### Static Analysis

**Run CppCheck:**
```powershell
.\scripts\run-static-analysis.ps1
```

**Reports saved to:** `reports/cppcheck-report.xml`

### Build Verification

**Test all configurations:**
```powershell
.\scripts\verify-build.ps1 -Configuration All -Platform All
```

**Single configuration:**
```powershell
.\scripts\verify-build.ps1 -Configuration Release -Platform x64
```

### Dependency Updates

**Check dependency status:**
```powershell
.\scripts\update-dependencies.ps1 -DryRun
```

**See update instructions:**
```powershell
.\scripts\update-dependencies.ps1 -Dependency SQLite
```

## 🏗️ Architecture

### Core Components

- **Envy Application** - Main application (MFC-based UI)
- **Network Layer** - Multi-protocol P2P networking
- **Library System** - File management and metadata
- **Plugin Framework** - Extensible architecture
- **Security Framework** - Content filtering and blocking
- **Database Layer** - SQLite for local storage

### Supported Protocols

| Protocol | Status | Features | Compatibility Notes |
|----------|--------|----------|-------------------|
| **BitTorrent** | ⚠️ Good | DHT, Magnet Links, μTP | Missing BT v2 (BEP-52) |
| **Gnutella2** | ✅ Full | G2 Network, Hub Routing | Fully compatible |
| **eDonkey2000** | ⚠️ Partial | Kad Network, File Sources | Missing CryptLayer, SecureID |
| **HTTP/FTP** | ✅ Basic | Direct Downloads | Standard implementation |
| **Kademlia DHT** | ⚠️ Partial | Bootstrap, Contact Mgmt | XOR distance bug, limited indexing |

### Technology Stack

- **Language:** C++17
- **Framework:** MFC (Microsoft Foundation Classes)
- **Database:** SQLite 3.x
- **Build System:** Visual Studio 2026 (v145 toolset), CMake 3.20+
- **Networking:** Custom Winsock implementation
- **Compression:** zlib, bzip2
- **Hashing:** Custom library (MD4, MD5, SHA-1, SHA-256, Tiger)

## 📁 Project Structure

```
Envy/
├── Envy/                 # Main application source
├── HashLib/              # Hash algorithm library
├── Services/             # Third-party libraries
│   ├── SQLite/          # Database engine
│   ├── zlib/            # Compression
│   ├── MiniUPnP/        # UPnP support
│   └── ...
├── Plugins/              # Plugin implementations
├── Languages/            # Localization files
├── Skins/               # UI themes
├── Visual Studio/        # Build configurations
├── scripts/              # Build and utility scripts
├── tests/                # Unit tests (Google Test)
└── CMakeLists.txt        # Modern CMake build system
```

## 🔧 Development Tools

### Automated Tools

- **Code Formatting:** clang-format with CI validation
- **Static Analysis:** MSBuild Code Analysis, CodeQL security scanning
- **Build Verification:** GitHub Actions with artifact collection
- **Dependency Management:** Dependabot with automated PRs
- **Issue Management:** Automated labeling and stale management
- **Documentation:** AI-powered development assistance

### CI/CD Pipeline

GitHub Actions provides comprehensive automation with optimized workflows:

#### Build & Test (`build.yml`)
- **Automated builds** for all configurations (Debug/Release, Win32/x64)
- **NuGet package restoration** and MSBuild compilation
- **Build verification** with artifact collection
- **Parallel job execution** for faster feedback

#### Code Quality (`code-quality.yml`)
- **Static analysis** with MSBuild Code Analysis
- **Code formatting** checks with clang-format
- **Documentation validation** with markdown link checking
- **Dependency review** for security vulnerabilities

#### Security Scanning (`codeql.yml`)
- **CodeQL security analysis** for C++ vulnerabilities
- **Automated weekly scans** on Mondays
- **Custom query suites** for security and quality
- **SARIF report generation** for GitHub Security tab

#### Release Management (`release.yml`)
- **Automated release builds** with version tagging
- **Cross-platform packaging** (Win32/x64)
- **ZIP archive creation** with metadata
- **GitHub release publishing** with assets

#### Issue Management (`stale.yml`)
- **Automated stale issue management**
- **Configurable close timing** and labeling

#### Development Automation
- **Dependabot** for automated dependency updates
- **Issue templates** for bug reports and feature requests
- **Pull request templates** with checklists
- **AI agent documentation** for development assistance

## 📚 Documentation

### Core Documentation
- **[Development Agents](AGENTS.md)** - AI agents and automated tools for development
- **[Dev Tracker](dev-docs/DEV_TRACKER.md)** - Development progress tracker with visual status indicators
- **[Audit Report](AUDIT_REPORT.md)** - Comprehensive ED2K/Kademlia audit, task tracking, and roadmap
- **[P2P Compatibility Analysis](dev-docs/P2P_COMPATIBILITY.md)** - Protocol compatibility assessment and modernization roadmap
- **[Implementation Summary](dev-docs/IMPLEMENTATION_SUMMARY.md)** - Completed features and current status

### Developer Documentation (`dev-docs/`)
- **[Architecture](dev-docs/ARCHITECTURE.md)** - System architecture and component design
- **[Developer Guide](dev-docs/DEVELOPER_GUIDE.md)** - Development practices and contribution guidelines
- **[Documentation Index](dev-docs/README.md)** - Overview of all developer documentation

## 🎯 Modernization Status

### Phase 1: Critical Infrastructure Updates (In Progress)

**Completed:**
- ✅ Visual Studio 2026 (v145 toolset) migration
- ✅ CMake build system skeleton
- ✅ **Complete CI/CD pipeline** with 5 specialized workflows
- ✅ Code formatting tools (clang-format) with CI validation
- ✅ Static analysis tools (MSBuild Code Analysis, CodeQL)
- ✅ Build verification scripts and automation
- ✅ HashLib CMake implementation (example)
- ✅ GitHub configuration (dependabot, issue templates, PR templates)
- ✅ AI agent documentation and development guidelines

**In Progress:**
- 🔄 Build verification and testing
- 🔄 Dependency updates (SQLite, zlib, etc.)
- 🔄 CMake component definitions
- 🔄 Unit testing framework setup

### Phase 2: P2P Protocol Modernization (Planned)

**Critical Protocol Fixes:**
- 🔴 Fix Kademlia XOR distance calculation bug
- 🔴 Complete CryptLayer obfuscation implementation
- 🔴 Implement SecureID system for ED2K
- 🔴 Add BitTorrent v2 (BEP-52) support

**Advanced Features:**
- 🟡 Implement full Kad DHT indexing
- 🟡 Add modern BT extensions (Fast, DHT scrape)
- 🟡 Complete AICH hash tree functionality
- 🟡 Cross-protocol optimization features

See **[dev-docs/P2P_COMPATIBILITY.md](dev-docs/P2P_COMPATIBILITY.md)** for detailed analysis and **[dev-docs/MODERNIZATION_PROGRESS.md](dev-docs/MODERNIZATION_PROGRESS.md)** for infrastructure status.

## 🧪 Testing

### Unit Tests

**Build with tests:**
```powershell
cmake -B build -S . -DBUILD_TESTS=ON
cmake --build build --config Release
ctest --config Release
```

**Run specific tests:**
```powershell
.\build\bin\Release\HashLibTests.exe
```

See **[tests/README.md](tests/README.md)** for testing documentation.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run code formatting: `.\scripts\format-code.ps1`
5. Run static analysis: `.\scripts\run-static-analysis.ps1`
6. Test your changes
7. Submit a pull request

### Code Style

- 4 spaces indentation (no tabs)
- 120 character line limit
- Use `.clang-format` for formatting
- Follow existing naming conventions

## 📄 License

This project is licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0).

See [AGPL-License.txt](Envy/AGPL-License.txt) for details.

## 🔗 Resources

- **Visual Studio 2026:** https://visualstudio.microsoft.com/
- **CMake:** https://cmake.org/
- **SQLite:** https://www.sqlite.org/
- **Modernization Plan:** [MODERNIZATION_PLAN.md](MODERNIZATION_PLAN.md)

## 📞 Support

- **Documentation:** See `docs/` directory
- **Issues:** GitHub Issues
- **Development Guide:** [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md)

---

**Last Updated:** January 13, 2026
**Build System:** Visual Studio 2026 (v145), CMake 3.20+
**C++ Standard:** C++17
**P2P Compatibility:** Updated protocol analysis and modernization roadmap
