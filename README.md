# Envy - Peer-to-Peer File Sharing Application

[![Build Status](https://github.com/Mika3578/Envy/workflows/Build%20and%20Test/badge.svg)](https://github.com/Mika3578/Envy/actions)
[![Code Quality](https://github.com/Mika3578/Envy/workflows/Code%20Quality/badge.svg)](https://github.com/Mika3578/Envy/actions)
[![CodeQL Security](https://github.com/Mika3578/Envy/workflows/CodeQL%20Security%20Scan/badge.svg)](https://github.com/Mika3578/Envy/actions)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

**Version:** 4.0  
**License:** AGPL v3.0  
**Status:** Modernization in Progress

## Overview

Envy is a comprehensive peer-to-peer file sharing application supporting multiple protocols including BitTorrent, Gnutella2 (G2), and eDonkey2000. Built with C++17 using MFC (Microsoft Foundation Classes), it provides a feature-rich P2P client with extensive plugin support.

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

- **Visual Studio 2022** (v145 toolset)
- **Windows SDK** 10.0.19041.0 or later
- **CMake** 3.20+ (incomplete, HashLib only)
- **Git** 2.30+

### Version Management

The project uses automatic version management with semantic versioning:

```powershell
# Interactive version bumping
.\scripts\bump-version.ps1 -Interactive

# Bump patch version
.\scripts\bump-version.ps1 -Type patch -UpdateFiles

# See version management docs
# scripts/README-version-management.md
```

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
   - Platform: x64/Win32 (x64 recommended)
   - Platform Toolset: v145 (VS2022)

4. **Build:**
   - Build → Build Solution (Ctrl+Shift+B)

### Building with CMake

**Note:** CMake build system is incomplete. Currently only supports HashLib library and test framework setup.

```powershell
# Create build directory
mkdir build
cd build

# Configure (Windows) - HashLib only
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build HashLib
cmake --build . --config Release --parallel

# With tests (framework setup only, no tests implemented)
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
cmake --build . --config Release
ctest --config Release
```

### Legacy Build Instructions

For those using older versions of Visual Studio:

1. Install Visual Studio Community (free) from http://www.visualstudio.com/products/visual-studio-community-vs
2. Open `Visual Studio\Envy.sln`
3. If needed, run `SetVS201X.bat` to update project files for earlier versions
4. Build Solution

**Note:** This project is self-contained with no external dependencies beyond Visual Studio.

## 📋 Development

### Code Formatting

Code formatting is configured with `.clang-format`. Use your IDE's formatting tools or clang-format directly.

### Static Analysis

Static analysis tools are configured (`.clang-tidy`, `.cppcheck-suppressions`). Run analysis through your IDE or CI/CD pipeline.

### Build Verification

Build verification is handled through GitHub Actions CI/CD pipeline. Check the Actions tab for build status.

### Dependency Updates

Dependency management is handled through GitHub's Dependabot integration.

## 🏗️ Architecture

### Core Components

- **Envy Application** - Main application (MFC-based UI)
- **Network Layer** - Multi-protocol P2P networking
- **Library System** - File management and metadata
- **Plugin Framework** - Extensible architecture
- **Security Framework** - Content filtering and blocking
- **Database Layer** - SQLite for local storage

### Supported Protocols

| Protocol | Status | Features | Missing Features |
|----------|--------|----------|------------------|
| **BitTorrent** | ⚠️ Partial | Basic DHT, Magnet Links, μTP | BT v2 (BEP-52), IPv6, advanced extensions |
| **Gnutella2** | ✅ Full | G2 Network, Hub Routing | Fully compatible |
| **eDonkey2000** | ⚠️ Partial | Basic Kad (bootstrap/ping only) | CryptLayer, SecureID, AICH, multipacket, SourceEx2 |
| **HTTP/FTP** | ✅ Basic | Direct Downloads | Standard implementation |
| **Kademlia DHT** | ⚠️ Stub | Bootstrap, Ping/Pong only | Full indexing, XOR distance fix, nodes.dat import |

### Technology Stack

- **Language:** C++17
- **Framework:** MFC (Microsoft Foundation Classes)
- **Database:** SQLite 3.x
- **Build System:** Visual Studio 2022 (v145 toolset), CMake 3.20+ (incomplete)
- **Networking:** Custom Winsock implementation (IPv4 only)
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
├── scripts/              # Version management scripts
├── tests/                # Unit tests (Google Test framework - no tests implemented)
└── CMakeLists.txt        # CMake build system (HashLib only)
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
- **Note:** Testing framework configured but no unit tests implemented

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

Complete documentation is available in the [`docs/`](./docs/) directory.

### Current Status & Roadmap
- **[Status](docs/STATUS.md)** - Current implementation status with evidence-based assessment
- **[Roadmap](docs/ROADMAP.md)** - Phased development priorities and timeline

### User Documentation
- **[User Guide](docs/user/guide.md)** - Complete usage instructions and features
- **[Installation](docs/user/installation.md)** - Installation and setup guide
- **[Configuration](docs/user/configuration.md)** - Settings and customization

### Developer Documentation
- **[Developer Guide](docs/developer/guide.md)** - Development workflow and practices
- **[Architecture](docs/developer/architecture.md)** - System design and components
- **[Modern C++ Guide](docs/developer/modern-cpp-guide.md)** - C++17 best practices
- **[AI Coding Guide](docs/developer/ai-coding-guide.md)** - AI assistant usage
- **[Agents & Automation](docs/developer/agents-and-automation.md)** - Development tooling

### Contributing
- **[Contributing Guide](docs/contributing/guide.md)** - How to contribute
- **[Build Instructions](docs/contributing/build.md)** - Exact build steps and troubleshooting
- **[Code Standards](docs/contributing/standards.md)** - Coding conventions and rules

### Additional Resources
- **[Changelog](CHANGELOG.md)** - Version history and changes
- **[Testing](tests/README.md)** - Unit testing documentation (framework ready, no tests implemented)

## 🎯 Modernization Status

### Phase 1: Critical Infrastructure Updates (In Progress)

**Completed:**
- ✅ Visual Studio 2022 (v145 toolset) migration
- ✅ CI/CD pipeline with GitHub Actions
- ✅ Code formatting tools (.clang-format) with CI validation
- ✅ Static analysis tools (.clang-tidy, .cppcheck-suppressions)
- ✅ HashLib CMake implementation
- ✅ Google Test framework scaffolding
- ✅ GitHub configuration (dependabot, issue templates, PR templates)

**In Progress:**
- 🔄 Complete CMake integration for main app/services/plugins
- 🔄 Implement actual unit tests (currently 0 tests)
- 🔄 Dependency updates and security audits

### Phase 2: P2P Protocol Modernization (Planned)

**Critical Protocol Fixes:**
- 🔴 Fix Kademlia XOR distance calculation bug
- 🔴 Complete CryptLayer obfuscation implementation (ED2K)
- 🔴 Implement SecureID system (ED2K)
- 🔴 Add BitTorrent v2 (BEP-52) support
- 🔴 Implement AICH hash tree verification (ED2K)
- 🔴 Add IPv6 support across all protocols

**Advanced Features:**
- 🟡 Complete Kad DHT indexing and nodes.dat import
- 🟡 Add modern BT extensions (Fast, DHT scrape)
- 🟡 Implement multipacket and SourceEx2 (ED2K)
- 🟡 Cross-protocol optimization features

See **[docs/STATUS.md](docs/STATUS.md)** for detailed current state assessment.

## 🧪 Testing

### Unit Tests

**Status:** Framework configured but no unit tests implemented yet.

**Build test framework:**
```powershell
cmake -B build -S . -DBUILD_TESTS=ON
cmake --build build --config Release
ctest --config Release  # Currently no tests to run
```

See **[tests/README.md](tests/README.md)** for testing documentation.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Format code using `.clang-format` (IDE tools or clang-format)
5. Run static analysis (IDE tools or CI/CD)
6. Test your changes
7. Submit a pull request

### Code Style

- 4 spaces indentation (no tabs)
- 120 character line limit
- Use `.clang-format` for formatting
- Follow existing naming conventions

## 📄 License

This project is licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0).

### License Notes

- **AGPLv3 Compliance**: Any resulting build or reuse must be AGPL 3+ compliant, including section 7 "Additional Terms"
- **Network Software**: As this is network server software affecting others, Affero REQUIRES PUBLIC AVAILABILITY OF MODIFIED CODE
- **Permissive Licenses**: Code contains files under several permissive licenses - read them carefully
- **Original Work**: Original work not covered by prior licenses is available as Persistent Public Domain license (PPD)
- **Visual Resources**: Creative Commons BY-NC-SA or PPD
- **Trademark**: "Envy" is a protected trademark

### Commercial Use Restrictions

**COMMERCIAL USE OF THIS SOURCEPACKAGE AS-IS IS NOT PERMITTED.**

Some non-GPL "aggregate" resources do not provide for normal GPL-compliant commercial usage. Most images and LibGFL.dll graphic library must be removed for commercial use.

See [AGPL-License.txt](Envy/AGPL-License.txt) for complete license details.

### Project History

Envy originated as a fork of **PeerProject**, which was itself derived from the **Shareaza** P2P client. The project represents a continuation of the open-source P2P file sharing tradition.

Copyright Envy Development Team (getenvy.com). All good-faith use is encouraged, no scams or misrepresentation will be tolerated. Proud to be Open Source.

## 🔗 Resources

- **Visual Studio 2026:** https://visualstudio.microsoft.com/
- **CMake:** https://cmake.org/
- **SQLite:** https://www.sqlite.org/
- **Modernization Plan:** [MODERNIZATION_PLAN.md](MODERNIZATION_PLAN.md)

## 📞 Support

- **Documentation:** [Complete Documentation](docs/)
- **User Guide:** [Getting Started](docs/user/guide.md)
- **Developer Guide:** [Contributing](docs/contributing/guide.md)
- **Issues:** [GitHub Issues](../../issues)
- **Discussions:** [GitHub Discussions](../../discussions)

---

**Last Updated:** January 15, 2026
**Build System:** Visual Studio 2022 (v145) primary, CMake 3.20+ (HashLib only)
**C++ Standard:** C++17
**Documentation:** See [docs/STATUS.md](docs/STATUS.md) and [docs/ROADMAP.md](docs/ROADMAP.md)
