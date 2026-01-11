# Changelog

All notable changes to Envy will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.1.0] - 2026-01-11

### Added
- GitHub repository files:
  - `.gitignore` - Comprehensive ignore rules for Visual Studio, C++, and build outputs
  - `.gitattributes` - Line ending normalization and binary file handling
  - `.editorconfig` - Consistent coding style settings across editors
  - `README.md` - Full project documentation with features and build instructions
  - `CONTRIBUTING.md` - Contribution guidelines and coding standards
  - `SECURITY.md` - Security policy for vulnerability reporting
  - `CHANGELOG.md` - This changelog file
  - `Directory.Build.props` - MSBuild properties for toolset configuration
- GitHub templates:
  - `.github/ISSUE_TEMPLATE/bug_report.md`
  - `.github/ISSUE_TEMPLATE/feature_request.md`
  - `.github/ISSUE_TEMPLATE/question.md`
  - `.github/PULL_REQUEST_TEMPLATE.md`
- GitHub Actions CI workflow (`.github/workflows/build.yml`)
- Dependabot configuration (`.github/dependabot.yml`)

### Changed
- Updated all Visual Studio project files (46 total) from legacy toolsets (`v141_xp`, `v145`) to `v143` (Visual Studio 2022)
- Modernized C++ code for C++17 compatibility:
  - `Strings.h`: Replaced deprecated `std::binary_function` with modern struct definition
  - `BTInfo.cpp`: Replaced `stdext::make_checked_array_iterator` with direct pointer operations

### Fixed
- Fixed compilation errors with modern Visual Studio 2022 and C++17 standard
- Fixed `std::binary_function` deprecation error in `Strings.h`
- Fixed `stdext::make_checked_array_iterator` not found error in `BTInfo.cpp`

### Removed
- Removed dependency on deprecated `std::binary_function` (C++17)
- Removed dependency on `stdext::make_checked_array_iterator` (MSVC extension)

## [Unreleased]

---



## Version History

For historical changes, see the commit history and previous release notes.

### Origins

- **Envy**: Current development
- **PeerProject**: Previous incarnation (peerproject.org)
- **Shareaza**: Original codebase (shareaza.sourceforge.net)

---

## Legend

- **Added**: New features
- **Changed**: Changes in existing functionality
- **Deprecated**: Soon-to-be removed features
- **Removed**: Removed features
- **Fixed**: Bug fixes
- **Security**: Security-related changes
