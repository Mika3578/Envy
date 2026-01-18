# Developer Guide

This guide provides comprehensive information for developers working on the Envy P2P client project.

## 📋 Table of Contents

- [Getting Started](#getting-started)
- [Project Structure](#project-structure)
- [Development Workflow](#development-workflow)
- [Code Standards](#code-standards)
- [Testing](#testing)
- [Build System](#build-system)
- [Contributing](#contributing)

## 🚀 Getting Started

### Prerequisites

- **Visual Studio 2022** (v145 toolset)
- **Windows SDK** 10.0.19041.0 or later
- **CMake** 3.20+ (incomplete, HashLib only)
- **Git** 2.30+

### Initial Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Mika3578/Envy.git
   cd Envy
   ```

2. **Open in Visual Studio:**
   - Open `Visual Studio\Envy.sln`
   - Select your preferred configuration (Debug/Release, x64/Win32)

3. **Build the project:**
   - Build → Build Solution (Ctrl+Shift+B)

### Recommended Tools

- **ClangFormat**: For code formatting (`.clang-format` provided)
- **GitHub Copilot**: AI code completion (see [AI Coding Guide](ai-coding-guide.md))
- **Cursor AI**: Alternative AI assistant (see `.cursorrules`)

## 🏗️ Project Structure

```
Envy/
├── Envy/                    # Main application source
│   ├── Core components      # Network, library, UI
│   └── Protocol handlers    # BitTorrent, Gnutella2, eDonkey
├── HashLib/                 # Hash algorithm library
├── Services/                # Third-party libraries (SQLite, zlib, etc.)
├── Plugins/                 # Plugin implementations
├── Languages/               # Localization files
├── Skins/                   # UI themes and skins
├── Visual Studio/           # Build configurations
├── scripts/                 # Build and utility scripts
├── tests/                   # Unit tests (Google Test)
└── docs/                    # Documentation
```

### Key Components

- **Network Layer**: TCP/UDP sockets, protocol implementations
- **Library System**: File management, metadata, search
- **Download Manager**: Multi-source downloads, hash verification
- **UI Framework**: MFC-based with skinning support
- **Plugin System**: COM-based extensibility

## 🔄 Development Workflow

### Daily Development

1. **Pull latest changes:**
   ```bash
   git pull origin main
   ```

2. **Create feature branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make changes with frequent commits:**
   ```bash
   # Make small, focused changes
   git add specific-files
   git commit -m "Clear, descriptive commit message"
   ```

4. **Test your changes:**
   ```bash
   .\scripts\verify-build.ps1
   .\scripts\run-static-analysis.ps1
   ```

5. **Format code:**
   ```bash
   .\scripts\format-code.ps1
   ```

### Before Committing

- ✅ Code compiles without warnings
- ✅ All tests pass
- ✅ Code follows style guidelines
- ✅ Documentation updated if needed
- ✅ No memory leaks in debug builds

### Pull Request Process

1. **Push your branch:**
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Create Pull Request** on GitHub with:
   - Clear description of changes
   - Reference to any related issues
   - Screenshots for UI changes

3. **Address review feedback** and update as needed

## 📏 Code Standards

### Language Standards

- **C++ Standard**: C++20 (modern features encouraged)
- **Character Set**: Unicode (UTF-16)
- **Framework**: Microsoft Foundation Classes (MFC)

### Naming Conventions

#### Classes
```cpp
class CDownloadTask;        // PascalCase with C prefix (MFC convention)
class CLibraryFile;
```

#### Member Variables
```cpp
class CExample
{
private:
    CString m_strFileName;      // m_str prefix for strings
    int m_nCount;               // m_n prefix for numbers
    DWORD m_nFileSize;
    CFile* m_pFile;             // m_p prefix for pointers
    bool m_bIsActive;           // m_b prefix for booleans
};
```

#### Functions
```cpp
void OnDownload();              // PascalCase
bool GetFileSize();
void UpdateProgress();
```

### Modern C++ Features

**✅ Use:**
- Smart pointers (`std::unique_ptr`, `std::shared_ptr`)
- `nullptr` instead of `NULL`
- Range-based `for` loops
- `auto` for obvious types
- `constexpr` for compile-time constants
- `override` and `final` keywords

**❌ Avoid:**
- Raw `new`/`delete` (use smart pointers)
- `NULL` (use `nullptr`)
- C-style casts (use C++ casts)
- Manual memory management

See [Modern C++ Guide](modern-cpp-guide.md) for detailed examples.

### Code Organization

- **Header files**: Include guards, forward declarations, clear structure
- **Implementation files**: Logical function grouping, clear comments
- **Error handling**: Exceptions for exceptional cases, proper resource cleanup
- **Thread safety**: Document thread requirements, use appropriate synchronization

## 🧪 Testing

### Unit Tests

The project uses Google Test for unit testing. Tests are located in the `tests/` directory.

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

### Testing Guidelines

- Write tests for new functionality
- Test edge cases and error conditions
- Ensure tests are fast and reliable
- Use descriptive test names
- Follow the existing test structure

See [Testing Documentation](../tests/README.md) for details.

## 🔨 Build System

### Visual Studio Builds

- **Solution**: `Visual Studio\Envy.sln`
- **Configurations**: Debug, Release
- **Platforms**: Win32, x64 (x64 recommended)
- **Toolset**: v145 (VS2026)

### CMake Builds (Modern)

```powershell
# Configure
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build build --config Release --parallel

# Install
cmake --install build --config Release
```

### Build Verification

**Test all configurations:**
```powershell
.\scripts\verify-build.ps1 -Configuration All -Platform All
```

**Single configuration:**
```powershell
.\scripts\verify-build.ps1 -Configuration Release -Platform x64
```

### Static Analysis

**Run CppCheck:**
```powershell
.\scripts\run-static-analysis.ps1
```

## 🤝 Contributing

### Contribution Guidelines

1. **Understand the codebase** before making changes
2. **Follow existing patterns** and conventions
3. **Make minimal changes** that solve the specific problem
4. **Test thoroughly** before submitting
5. **Update documentation** as needed

### Areas for Contribution

- **Protocol improvements**: BitTorrent, Gnutella2, eDonkey
- **Performance optimization**: Memory usage, CPU efficiency
- **UI enhancements**: Modern Windows features, accessibility
- **Testing**: Additional test coverage, integration tests
- **Documentation**: User guides, API documentation

### Getting Help

- **Issues**: [GitHub Issues](../../issues)
- **Discussions**: [GitHub Discussions](../../discussions)
- **Documentation**: Check this guide and related docs
- **Code**: Look for similar implementations in the codebase

## 📚 Additional Resources

- [Architecture Overview](architecture.md) - System design and components
- [AI Coding Guide](ai-coding-guide.md) - AI assistant best practices
- [Modern C++ Guide](modern-cpp-guide.md) - C++20 feature examples
- [Agents and Automation](agents-and-automation.md) - Development tooling
- [Modernization Summary](modernization-summary.md) - Recent improvements
- [Contributing Guide](contributing.md) - Detailed contribution process
- [Code Standards](standards.md) - Complete style guidelines

---

**Last Updated:** January 15, 2026
