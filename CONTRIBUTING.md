# Contributing to Envy

Thank you for your interest in contributing to Envy! This document provides guidelines and information for contributors.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Pull Request Process](#pull-request-process)
- [Reporting Bugs](#reporting-bugs)
- [Feature Requests](#feature-requests)

## 📜 Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. Please:

- Be respectful and considerate in all interactions
- Focus on constructive feedback
- Accept differing viewpoints gracefully
- Report any unacceptable behavior to the maintainers

## 🚀 Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/Envy.git
   cd Envy
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/Mika3578/Envy.git
   ```
4. **Create a branch** for your work:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## 💡 How to Contribute

### Types of Contributions

- **Bug Fixes**: Fix issues and improve stability
- **Features**: Add new functionality
- **Documentation**: Improve README, comments, and docs
- **Translations**: Add or improve language translations
- **Plugins**: Create new plugins or improve existing ones
- **Skins**: Design new visual themes
- **Testing**: Write tests or help test releases

## 🛠️ Development Setup

### Prerequisites

- **Visual Studio 2022** with:
  - Desktop development with C++
  - Windows 10/11 SDK
  - C++ MFC for latest v143 build tools (x86 & x64)
  - C++ ATL for latest v143 build tools (x86 & x64)

### Building

1. Open `Visual Studio\Envy.sln`
2. Select configuration (Debug/Release) and platform (Win32/x64)
3. Build Solution (`Ctrl+Shift+B`)

### Project Organization

| Directory | Purpose |
|-----------|---------|
| `Envy/` | Main application |
| `Plugins/` | Plugin projects |
| `Services/` | Third-party libraries |
| `Languages/` | Localization files |
| `Skins/` | Visual themes |

## 📐 Coding Standards

### General Guidelines

- Follow the existing code style in the file you're modifying
- Use meaningful variable and function names
- Comment complex logic
- Keep functions focused and reasonably sized

### C++ Style

```cpp
// Class naming: PascalCase
class CMyClass
{
public:
    // Member functions: PascalCase
    void DoSomething();
    
protected:
    // Member variables: m_ prefix with PascalCase
    int m_nValue;
    CString m_sName;
    bool m_bEnabled;
};

// Constants: ALL_CAPS with underscores
const int MAX_BUFFER_SIZE = 1024;

// Indentation: Tabs (not spaces)
// Braces: Allman style (on new line)
```

### File Headers

New source files should include appropriate copyright and license headers consistent with existing files.

## 🔄 Pull Request Process

1. **Update your branch** with the latest upstream changes:
   ```bash
   git fetch upstream
   git rebase upstream/develop
   ```

2. **Test your changes** thoroughly:
   - Build in both Debug and Release configurations
   - Test on Win32 and x64 if applicable
   - Verify no regressions in existing functionality

3. **Commit your changes** with clear messages:
   ```bash
   git commit -m "Brief description of changes
   
   - Detailed point 1
   - Detailed point 2"
   ```

4. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

5. **Create a Pull Request** on GitHub:
   - Target the `develop` branch
   - Provide a clear description of changes
   - Reference any related issues

### PR Review Criteria

- Code compiles without warnings
- Changes follow project coding standards
- No unnecessary files included
- Clear commit messages
- Documentation updated if needed

## 🐛 Reporting Bugs

When reporting bugs, please include:

1. **Environment**:
   - Envy version
   - Windows version
   - 32-bit or 64-bit

2. **Steps to Reproduce**:
   - Detailed step-by-step instructions
   - Expected behavior
   - Actual behavior

3. **Additional Information**:
   - Screenshots if applicable
   - Crash logs from BugTrap if available
   - Network configuration if relevant

### Bug Report Template

```markdown
**Environment:**
- Envy Version: 
- Windows Version: 
- Architecture: x86/x64

**Description:**
Brief description of the bug.

**Steps to Reproduce:**
1. Step one
2. Step two
3. ...

**Expected Behavior:**
What should happen.

**Actual Behavior:**
What actually happens.

**Additional Information:**
Any other relevant details.
```

## ✨ Feature Requests

Feature requests are welcome! Please:

1. **Search existing issues** to avoid duplicates
2. **Describe the feature** clearly
3. **Explain the use case** - why is this needed?
4. **Consider the scope** - is it feasible?

### Feature Request Template

```markdown
**Feature Description:**
Clear description of the proposed feature.

**Use Case:**
Why is this feature needed? What problem does it solve?

**Proposed Implementation:**
(Optional) Ideas on how this could be implemented.

**Alternatives Considered:**
Other approaches you've considered.
```

## 📝 License

By contributing, you agree that your contributions will be licensed under the project's AGPLv3 license for code contributions.

## 🙏 Acknowledgments

Thank you to all contributors who help make Envy better!

---

Questions? Feel free to open an issue for discussion.
