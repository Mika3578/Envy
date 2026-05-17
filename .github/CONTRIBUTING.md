# Contributing to Envy

Thanks for your interest in improving Envy. This file describes the
ground rules for contributing code, translations, skins, or docs.

## License agreement

Envy is licensed under **AGPL-3.0-or-later**. Some visual resources and
the `LibGFL` library carry additional CC-BY-NC-SA terms (see `ReadMe.txt`).
By submitting a pull request you confirm that your contribution can be
distributed under those terms.

## Quick start

1. Install **Visual Studio 2026 v18.0+** (Community is fine) with:
   - Workload "Desktop development with C++"
   - Components "MFC for v145", "ATL for v145", "C++ Spectre-mitigated libs (v145)"
   - "C++ CMake tools for Windows"
   - "Windows 10/11 SDK (latest)"
2. Clone with submodules and bootstrap vcpkg:
   ```
   git clone https://github.com/mika3578/envy.git
   cd envy
   git clone https://github.com/microsoft/vcpkg.git
   .\vcpkg\bootstrap-vcpkg.bat
   ```
3. Open `Visual Studio\Envy.sln` and build (Ctrl+Shift+B).

If you migrated from VS 2017/2019: run `Visual Studio\SetVS2026.bat` once
to retarget every project to v145.

## Branch model

- `main` - stable, releases tagged `v*` from here.
- `develop` - integration branch.
- `legacy` - frozen pre-modernization snapshot for historical builds.
- Feature branches : `feature/<short-name>` or `claude/<short-name>` for
  AI-assisted work.

## Pull request checklist

- [ ] Builds Release x64 and Release Win32 with toolset v145.
- [ ] No new compiler warnings (use the CI build log).
- [ ] CodeQL passes without new HIGH/CRITICAL findings.
- [ ] If you touched anything in `Services/` or `Plugins/`, ping a
      CODEOWNER for review.
- [ ] If you bumped a vcpkg dependency, note the version delta in the
      PR description.
- [ ] Translations stay in sync with the keys in `Envy.exe`
      (run `Languages\Tools\extract.bat`).

## Coding style

The codebase predates modern C++ conventions; please match the surrounding
code rather than introducing a new style island:

- Tabs for indentation, width 4.
- Allman braces (`{` on its own line).
- Hungarian-ish notation (`m_`, `p`, `n`, `b`, `str`).
- Prefer `CString` / `CAtlList` over `std::string` / `std::list` inside MFC code.
- Use `noexcept`, not `throw()`.
- Avoid `using namespace std;` at file scope.
- New code SHOULD compile with `/std:c++20`; legacy plugins may stay on
  `/std:c++17`.

`.clang-format` is provided for advisory checks. It is intentionally
conservative - do not bulk-reformat existing files.

## Reporting bugs

Use the bug report issue template. Include the BugTrap dump under
`%APPDATA%\Envy\` when relevant.

## Security

See `.github/SECURITY.md`. Never open public issues for security bugs.
