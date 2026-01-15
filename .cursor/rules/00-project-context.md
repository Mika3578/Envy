# Envy Project Context

## Project Overview

Envy is a comprehensive peer-to-peer file sharing application supporting multiple protocols including BitTorrent, Gnutella2 (G2), and eDonkey2000. Built with C++ using MFC (Microsoft Foundation Classes), it provides a feature-rich P2P client with extensive plugin support.

**Version:** 4.0+  
**License:** AGPL v3.0  
**Status:** Modernization in Progress

## Technology Stack

- **Language**: C++20 (target), C++17 minimum
- **Platform**: Windows (Win32/x64)
- **Framework**: Microsoft Foundation Classes (MFC)
- **Character Set**: Unicode (UTF-16)
- **Build System**: Visual Studio 2026 (or VS 2022 with v143 toolset)
- **MSBuild Path**: `C:\Program Files\Microsoft Visual Studio\18\Insiders\MSBuild\Current\Bin\amd64\MSBuild.exe`

## Project Structure

```
Envy/
├── Envy/          # Main application code
├── Services/      # Core services and protocols
├── Plugins/       # Plugin system
├── HashLib/       # Hashing library
├── Repository/    # Resources and schemas
├── Skins/         # UI skins
├── Languages/     # Localization files
└── docs/          # Documentation
```

## Key Features

- Multi-protocol support: BitTorrent/DHT, G2/Gnutella², Gnutella, ED2K/eMule, DC++, HTTP/FTP
- Highly skinnable interface
- Built-in blacklist support
- Cross-platform compatibility (Windows or Wine)

## Development Philosophy

- **Modernization**: Gradual adoption of modern C++ features while maintaining compatibility
- **Backward Compatibility**: Maintain compatibility with existing P2P networks
- **Performance**: Critical for large downloads and many peers
- **Network Resilience**: Essential for P2P operations
- **User Data Protection**: Security is paramount

## Important Notes

- This is a mature codebase with legacy components
- Comments must be in English
- Follow MFC conventions where applicable
- Balance modern C++ with MFC compatibility
- Research Examples folder for P2P client implementations
- Create plan before coding changes
