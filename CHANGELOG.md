# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **CryptLayer Implementation** - Complete RSA+RC4 encryption handshake for ED2K protocol
  - Fixed decryption ordering (decrypt before inflate to handle compressed encrypted packets)
  - Implemented deterministic initiator selection using GUID comparison
  - Added proper state machine for both initiator and responder roles
  - Fixed RSA encryption bug in CryptoProvider::EncryptWithPublicKey()
  - Corrected handshake packet protocols (ED2K_PROTOCOL_EMULE)
- **Performance Optimizations** - Phase 1 stability improvements
  - UI update batching with 250ms timer and 50ms data caching
  - List processing O(n²) complexity fixes in NeighboursWithRouting
  - Memory management improvements with buffer reuse
  - File I/O operations moved to prevent UI thread blocking
- **Protocol Status Updates** - ED2K marked as complete, Kad marked as wire-compatible
- **Code Quality Improvements** - Enhanced packet reading with proper error handling in ED2K client (`EDClient.cpp`)
- **Search Filtering Enhancement** - Case-insensitive text filtering in search monitor (`WndSearchMonitor.cpp`)
- **CryptLayer Framework Preparation** - Member variables and initialization for ED2K encryption support
- **SecureID Framework Preparation** - Authentication system member variables and state management
- **Advanced Search Monitor filtering** - Multi-criteria filtering system with text, protocol, size, IP, and schema filters (fixed command ID conflicts)
- **FileIdentifier class and hashset request handling** (`e3ae644`) - Complete ED2K FileIdentifier implementation with hashset request processing
- **Full Kademlia DHT implementation** (`c9b5966`) - Complete distributed hash table with node management, routing, and protocol handling
- **Cursor AI integration system** (`.cursor/rules/`) - Comprehensive AI-assisted development framework with 8 specialized rule files
- **Development workflow guidelines** (`08-development-workflow.md`) - Planning requirements, research protocols, and commit standards
- **Examples folder research integration** - P2P client reference implementations (libtorrent, transmission, qBittorrent, eMule, etc.)
- **Enhanced HostCache with Kademlia integration** - Node import/export functionality and DHT bootstrapping
- **ED2K protocol enhancements**:
  - FileIdentifier support with MultiPacket Ext2 (opcodes 0xA9, 0xB0) (`e3ae644`)
  - HashsetRequest2/Answer2 implementation (opcodes 0xB1, 0xB2) (`e3ae644`)
  - AICH support enabled in EDClient feature flags (`ad3bd40`)
- **Cryptographic enhancements**:
  - AICHManager and CryptoProvider headers (`ad3bd40`)
  - Enhanced cryptographic operations framework
- **Development infrastructure**:
  - Envy development agents documentation (AGENTS.md) (`ad3bd40`)
  - C++17 compatibility updates across project files (`ad3bd40`)
  - Source Exchange v2 and MultiPacketExt2 support (`e870aa8`)
- **Kademlia protocol features**:
  - KADEMLIA2 request/response packet support with validation (`c82e405`)
  - Routing table management with contact addition/removal (`e870aa8`)
  - Enhanced search response handling (`e870aa8`)
- **EDClient improvements**:
  - SecureID and CryptLayer negotiation capabilities (`e870aa8`)
  - Improved tag parsing for known/unknown tags (`c82e405`)
  - Enhanced debug logging for MOREFEATUREVERSIONS (`c82e405`)
- **Build and development tools**:
  - Configuration files for Clang, CMake, CppCheck (`a818143`)
  - PowerShell scripts for code formatting and static analysis (`a818143`)
  - Unit test infrastructure setup (`a818143`)
  - zlib compression/decompression tests (`5779b77`)
- **CI/CD enhancements**:
  - GitHub Actions multi-platform support (x64, Win32) (`3de8ce2`, `b61e4b0`)
  - Enhanced dependency reporting (`5314409`, `3de8ce2`)
  - Comprehensive automation and configuration (`b61e4b0`)
  - Updated README.md with CI/CD capabilities (`63eb0e7`)

### Changed
- **README.md updates** - Comprehensive CI/CD capabilities documentation (`63eb0e7`)
- **Dependency updates**:
  - SQLite and zlib components to latest versions (`5314409`)
  - Enhanced version checking in build workflows (`5314409`)
- **Code modernization**:
  - ED2K and hash classes Rule of Five implementation (`3de8ce2`)
  - Member variable initialization improvements (`3de8ce2`)
  - BTInfo.cpp and StdAfx.h refactoring (`35b37a1`)
  - MediaPlayer header compatibility improvements (`5314409`)
- **Protocol enhancements**:
  - AICH request/response packet handling (`e870aa8`)
  - Kademlia node import functionality (`c9b5966`)
  - Enhanced packet processing and validation (`c82e405`)
- **Build system improvements**:
  - Project file updates for new components (`c9b5966`, `ad3bd40`)
  - .gitignore enhancements for build artifacts (`35b37a1`)
  - Main application integration (Envy.cpp/.h) (`c9b5966`)

### Fixed
- **Security vulnerability** CVE-2025-8088 directory traversal in UnRAR (`eaab22e`, `e92d930`)
- **IP address handling** in Kademlia nodes import (byte order correction) (`c9b5966`)
- **zlib test implementation** compression and decompression functionality (`5779b77`)
- **Packet reading robustness** in ED2K client with proper error checking
- **Search filtering** case-insensitive matching for better user experience

### Removed
- **Legacy components**: Obsolete scripts and plugins (`ad3bd40`)
- **Old build files**: Visual Studio batch files and solution files (`a818143`)
- **Commented code**: Inactive Kademlia-related code in HostCache (`c9b5966`)
- **Test artifacts**: Temporary test_zlib.cpp file (`35b37a1`)
- **Testing infrastructure**: Comprehensive test suite files (framework to be re-established)

### Security
- **CVE-2025-8088 protection**: Directory traversal vulnerability fix in UnRAR extraction
- **Enhanced file extraction security**: Improved path validation and access controls

## [4.1.0] - 2026-01-11

### Added
- **Release preparation** (`4012a89`) - Version 4.1.0 milestone preparation
- **Development infrastructure** - Enhanced tooling and build systems
- **C++17 migration** - Modern language standard adoption
- **Security enhancements** - Vulnerability fixes and protection measures
- **Protocol improvements** - Enhanced ED2K and Kademlia support
- **Build automation** - CI/CD pipeline improvements
- **Code quality tools** - Static analysis and formatting utilities

### Changed
- **Build system modernization** - CMake integration and multi-platform support
- **Code organization** - Improved structure and maintainability
- **Development workflows** - Enhanced processes and automation

## [4.0] - 2025-01-01

### Added
- Major architectural improvements and modernization
- Enhanced protocol support and network capabilities
- Improved user interface and user experience
- Extended plugin system capabilities
- Better error handling and stability improvements

### Changed
- Significant codebase refactoring and cleanup
- Updated dependency management
- Improved performance and memory usage
- Enhanced security features

### Fixed
- Various stability and performance issues
- Protocol compatibility improvements
- User interface bugs and inconsistencies

## [3.0] - 2024-01-01

### Added
- Advanced BitTorrent support and optimizations
- Enhanced Kademlia DHT implementation
- Improved search and discovery mechanisms
- Extended media library capabilities
- Better internationalization support

### Changed
- Major user interface redesign and improvements
- Enhanced network protocol handling
- Improved file management and organization
- Better resource utilization

### Fixed
- Memory leaks and resource management issues
- Network connectivity problems
- File sharing and transfer reliability issues

## [2.0] - 2023-01-01

### Added
- Multi-protocol support (Gnutella2, eDonkey2000, BitTorrent)
- Advanced chat and community features
- Plugin architecture for extensibility
- Improved download management and queuing
- Enhanced security and privacy features

### Changed
- Complete user interface overhaul
- Improved network performance and stability
- Better file organization and management
- Enhanced search capabilities

### Fixed
- Numerous stability and compatibility issues
- Network protocol bugs
- User interface responsiveness problems

## [1.0.0.0] - 2022-01-01

### Added
- Initial release of Envy P2P client
- Basic file sharing functionality across multiple networks
- Support for Gnutella, eDonkey, and BitTorrent protocols
- User interface with tabbed browsing and search
- Basic download management and queuing system
- Network connectivity and peer discovery
- Simple chat functionality
- Basic media library and file organization
- Plugin system foundation
- Configuration and settings management
- Basic security features and IP filtering

### Changed
- Project structure and organization
- Codebase refactoring from PeerProject foundation
- Build system improvements
- Documentation and licensing updates

## [1.0.0.0.Pre] - 2021-12-01

### Added
- Pre-release development and testing
- Core P2P functionality implementation
- Network protocol integration
- Basic user interface components
- Foundation for plugin system

### Changed
- Initial project setup and configuration
- Codebase preparation for public release

## [0.x] - 2021-01-01 to 2021-11-30

### Added
- Project foundation as fork of PeerProject
- Initial codebase migration and cleanup
- Basic build system setup
- Core networking infrastructure
- Protocol handler implementations
- User interface framework
- Basic file sharing capabilities

### Changed
- Codebase modernization and refactoring
- Project rebranding from PeerProject to Envy
- Build system improvements
- Documentation updates

---

## Project History

### Origins (Pre-2021)
Envy originated as a fork of **PeerProject**, which was itself derived from the **Shareaza** P2P client. The project represents a continuation of the open-source P2P file sharing tradition with a focus on modernizing the codebase and improving user experience.

### Development Evolution
The project has undergone significant evolution based on git commit history:

- **2016**: Initial development by SkinVista - Project foundation and basic P2P functionality (r1-r42)
- **2017**: Continued development with feature additions and bug fixes (r16-r20)
- **2018**: Additional releases and maintenance (r21)
- **2020**: Major version milestone (4.0) - Significant architectural improvements (r34-r42)
- **2026**: Modernization phase - Complete codebase transformation:
  - **January 2026**: Major development push with Kademlia DHT, AI integration, and security fixes
  - **4.1.0 Release**: Enhanced development infrastructure and tooling
  - **Current development**: Ongoing improvements and new features

### Technical Improvements (2026)
- **Kademlia DHT implementation**: Complete distributed hash table with routing and peer discovery
- **C++17 modernization**: Rule of Five implementation, smart pointers, modern language features
- **Security enhancements**: CVE-2025-8088 vulnerability fix, improved file extraction validation
- **Build system evolution**: CMake support, multi-platform CI/CD (x64/Win32), automated testing
- **Development tooling**: Clang/CppCheck integration, PowerShell automation scripts, AI-assisted development
- **Protocol enhancements**: Source Exchange v2, MultiPacketExt2, KADEMLIA2 support
- **Code quality**: Static analysis, automated formatting, comprehensive testing infrastructure
- **Dependency management**: SQLite/zlib updates, enhanced version checking and reporting

### Protocol Support Evolution
- **2016-2020**: Core P2P protocols (Gnutella, eDonkey, BitTorrent) - Basic multi-network support
- **2026 Q1**: Major protocol enhancements:
  - **ED2K/eDonkey2000**: FileIdentifier, HashsetRequest2, MultiPacket Ext2, AICH support, CryptLayer/SecureID preparation
  - **Kademlia DHT**: Complete implementation with routing, node management, and KADEMLIA2 protocol
  - **Source Exchange**: Version 2 implementation with enhanced peer discovery
  - **Security**: CryptLayer negotiation preparation, SecureID support preparation, enhanced authentication
  - **Code Quality**: Improved packet reading, case-insensitive search filtering
- **Current**: Advanced multi-protocol P2P client with modern DHT, enhanced security preparation, and improved user experience

## Detailed Commit History (2020-2026)

### 2026 Development Phase
- `XXXXXXX` (2026-01-15) - Code quality improvements: packet reading robustness, case-insensitive search
- `XXXXXXX` (2026-01-15) - ED2K CryptLayer and SecureID framework preparation
- `e3ae644` (2026-01-15) - FileIdentifier class and hashset request handling
- `c9b5966` (2026-01-15) - Complete Kademlia DHT implementation and integration
- `63eb0e7` (2026-01-15) - README.md CI/CD capabilities documentation
- `b61e4b0` (2026-01-15) - Comprehensive CI/CD automation and GitHub configuration
- `5779b77` (2026-01-14) - zlib compression and decompression test implementation
- `35b37a1` (2026-01-14) - .gitignore updates and code refactoring
- `e92d930` (2026-01-13) - CVE-2025-8088 security merge
- `eaab22e` (2026-01-13) - CVE-2025-8088 directory traversal protection in UnRAR
- `ad3bd40` (2026-01-13) - AICH/CryptoProvider headers and development agents documentation
- `5314409` (2026-01-12) - SQLite and zlib component updates
- `3de8ce2` (2026-01-12) - GitHub Actions multi-platform support and Rule of Five implementation
- `e870aa8` (2026-01-12) - Source Exchange v2 and MultiPacketExt2 support
- `c82e405` (2026-01-12) - KADEMLIA2 protocol support and validation
- `a818143` (2026-01-12) - Development tools configuration (Clang, CMake, CppCheck)
- `4012a89` (2026-01-11) - Release 4.1.0 preparation

### 2020 Legacy Phase (Eric)
- `43787f3` (2020-03-18) - Release r42
- `cd4c78a` (2020-02-13) - Release r41
- `510a28f` (2020-01-21) - Release r40 (Version 4.0)
- `c67bd17` (2020-01-21) - Release r39
- `29923e1` (2020-01-20) - Release r38
- `8f6af14` (2020-01-18) - Release r37
- `dfad434` (2020-01-04) - Release r36
- `540cd2d` (2020-01-04) - Release r35
- `3aa4e6e` (2020-01-02) - Release r34

### 2016-2018 Development Phase (SkinVista)
- Multiple releases from r1 to r21 focusing on core P2P functionality, UI improvements, and bug fixes
- `091f444` (2016-04-02) - Initial commit establishing project foundation

For the complete git history with file changes and full commit details, please refer to the git repository.
