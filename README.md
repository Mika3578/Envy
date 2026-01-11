# Envy

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)](https://github.com/Mika3578/Envy)
[![Build Status](https://img.shields.io/github/actions/workflow/status/Mika3578/Envy/build.yml?branch=develop)](https://github.com/Mika3578/Envy/actions)

**Multi-Network P2P Filesharing and BitTorrent Client for Windows**

Envy is a powerful peer-to-peer file sharing application supporting multiple networks including BitTorrent, Gnutella, Gnutella2 (G2), eDonkey2000 (eD2k), and DC++.

## 🚀 Features

- **Multi-Network Support**: Connect to BitTorrent, Gnutella, Gnutella2, eDonkey2000, and DC++ networks simultaneously
- **BitTorrent**: Full DHT, PEX, magnet links, and µTP support
- **Library Management**: Organize and browse your media collection
- **Plugin Architecture**: Extensible through a robust plugin system
- **Skinnable UI**: Customize the appearance with skins
- **Media Preview**: Preview media files before download completes
- **Bandwidth Control**: Fine-grained control over upload/download speeds
- **UPnP Support**: Automatic port forwarding via MiniUPnP
- **GeoIP**: Geographic location of peers

## 📋 Requirements

- **Operating System**: Windows 10 or later (x86/x64)
- **Build Tools**: Microsoft Visual Studio 2022 (v143 toolset)

## 🛠️ Building from Source

### Prerequisites

1. Install [Visual Studio 2022 Community](https://visualstudio.microsoft.com/vs/community/) (free) with:
   - **Desktop development with C++** workload
   - **Windows 10/11 SDK**
   - **C++ MFC for latest v143 build tools (x86 & x64)**
   - **C++ ATL for latest v143 build tools (x86 & x64)**

### Build Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/Mika3578/Envy.git
   cd Envy
   ```

2. Open the solution:
   - Navigate to `Visual Studio` folder
   - Open `Envy.sln`

3. Build:
   - Select configuration (Debug/Release) and platform (Win32/x64)
   - Click **Build → Build Solution** (or press `Ctrl+Shift+B`)

> **Note**: This source package is self-contained with no external dependencies.

## 📁 Project Structure

```
Envy/
├── Envy/               # Main application source
├── HashLib/            # Cryptographic hash library
├── Installer/          # InnoSetup installer scripts
├── Languages/          # Localization files and tools
├── Plugins/            # Plugin projects
│   ├── 7ZipBuilder/    # 7-Zip archive support
│   ├── DocumentReader/ # Document metadata extraction
│   ├── GFLImageServices/
│   ├── ImageViewer/    # Built-in image viewer
│   ├── MediaPlayer/    # Built-in media player
│   ├── RARBuilder/     # RAR archive support
│   ├── VirusTotal/     # VirusTotal integration
│   ├── ZIPBuilder/     # ZIP archive support
│   └── ...
├── Remote/             # Web remote interface
├── Repository/         # Additional resources
├── Schemas/            # XML schemas
├── Services/           # Third-party libraries
│   ├── BugTrap/        # Crash reporting
│   ├── Bzlib/          # BZip2 compression
│   ├── GeoIP/          # Geographic IP lookup
│   ├── LibGFL/         # Graphics library
│   ├── LibUTP/         # µTP protocol
│   ├── MiniUPnP/       # UPnP client
│   ├── SQLite/         # Database engine
│   ├── UnRAR/          # RAR extraction
│   └── zlib/           # Zlib compression
├── SkinBuilder/        # Skin creation tool
├── Skins/              # Default skins
├── Templates/          # Torrent and metadata templates
├── TorrentEnvy/        # Torrent creation tool
├── Unpacker/           # Archive extraction utility
└── Visual Studio/      # Solution and project files
```

## 🔌 Plugin Development

Envy supports extensibility through COM-based plugins. See the `Plugins/PluginWizard` directory for templates:

- **Image Service Plugin**: Extract metadata/thumbnails from image formats
- **Library Builder Plugin**: Index custom file types

## 🌐 Networks Supported

| Network | Status | Description |
|---------|--------|-------------|
| BitTorrent | ✅ Full | DHT, PEX, Magnet, µTP |
| Gnutella2 (G2) | ✅ Full | Primary network |
| Gnutella | ✅ Full | Legacy support |
| eDonkey2000 | ✅ Full | ed2k links, Kad |
| DC++ | ✅ Full | Hub connections |

## 📜 License

This project is licensed under multiple licenses:

- **Code**: [GNU Affero General Public License v3.0](https://www.gnu.org/licenses/agpl-3.0.html) (AGPLv3)
  - Modified source code must be made publicly available
- **Visual Resources**: Creative Commons BY-NC-SA or Persistent Public Domain (PPD)
- **Trademark**: "Envy" is a protected trademark

> ⚠️ **Commercial use as-is is not permitted** due to certain non-GPL resources included.

See [ReadMe.txt](ReadMe.txt) for detailed license information.

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📖 History

Envy is developed by the Envy Development Team.

- Originally derived from **Shareaza** (shareaza.sourceforge.net)
- Previously developed as **PeerProject** (peerproject.org)

## 🔗 Links

- **Website**: [http://getenvy.com](http://getenvy.com)
- **GitHub**: [https://github.com/Mika3578/Envy](https://github.com/Mika3578/Envy)
- **Issues**: [GitHub Issues](https://github.com/Mika3578/Envy/issues)

## ⚖️ Disclaimer

This software is provided for legal file sharing purposes only. Users are responsible for ensuring their usage complies with applicable laws and regulations.

---

*Proud to be Open Source* 🌟
