# Building Envy

Authoritative instructions: [docs/10_dev/build.md](https://github.com/Mika3578/Envy/blob/develop/docs/10_dev/build.md) and [.github/CONTRIBUTING.md](https://github.com/Mika3578/Envy/blob/develop/.github/CONTRIBUTING.md).

## Short path

1. Windows 10/11 + Visual Studio 2026 with MFC/ATL (v145).
2. Clone `https://github.com/Mika3578/Envy` and checkout `develop`.
3. Run `scripts/bootstrap-vcpkg.cmd -CloneVcpkg`.
4. Open `Visual Studio/Envy.sln` and build Release x64.

CMake covers a **partial** slice (HashLib/tests) only.

## Sources

- Main repository build docs (versioned on `develop`).
