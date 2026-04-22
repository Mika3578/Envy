# CLAUDE.md

## Project Snapshot
- Windows-first C++17/MFC monorepo for Envy P2P client.
- Canonical full build uses `Visual Studio/Envy.sln`.
- CMake is partial (mainly HashLib + tests).

## Key Commands
- Build solution (Windows): `msbuild /m /p:Configuration=Release /p:Platform=x64 "Visual Studio/Envy.sln"`
- Restore packages: `nuget restore "Visual Studio/Envy.sln"`
- CMake tests (limited):
  - `cmake -S . -B build -DBUILD_TESTS=ON`
  - `cmake --build build`
  - `ctest --test-dir build`

## Conventions
- Keep changes minimal and scoped.
- Do not assume CMake parity with Visual Studio.
- Prefer edits that preserve protocol compatibility behavior.
- Update docs and changelog when behavior/process changes.

## Architecture Hints
- `Envy/` mixes UI, protocol logic, and application state.
- `HashLib/` is a shared dependency used by tests and core code.
- `Services/` and `Plugins/` are high-impact areas for dependency/API stability.

## Do / Don't
- **Do** document assumptions and validation limits.
- **Do** call out security/performance implications of changes.
- **Don't** introduce broad refactors without explicit scope.
- **Don't** add new dependencies without update/ownership notes.
