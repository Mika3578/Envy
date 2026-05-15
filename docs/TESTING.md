# Testing Guide

## Current Test Surface
- Primary test project: `tests/EnvyTests.vcxproj`
- Additional standalone test executables exist in `tests/` (`test_runner.cpp`, simple integration binaries)
- Current coverage is strongest in hashing/crypto-related paths

## Running Tests (Visual Studio)
1. Build `EnvyTests` for chosen config/platform.
2. Run `tests/<Config> <Platform>/EnvyTests.exe`.

## Running Tests (CMake path)
```bash
cmake -S . -B build -DBUILD_TESTS=ON
cmake --build build
ctest --test-dir build
```

## Writing New Tests
- Place new test source files under `tests/`.
- Register test entry in the existing test framework/main.
- Prefer deterministic tests that avoid network flakiness.
- For protocol logic, isolate parser/state transitions from live network where possible.

## Coverage Targets (Proposed)
- Hashing/core utilities: maintain high coverage.
- Protocol handlers: add targeted unit tests for packet parse/serialize logic.
- Persistence/config migration: add regression tests for settings and schema changes.


## CI Authoritative Windows Builds (MSVC v145 Required)
- Authoritative CI builds require **PlatformToolset `v145`**.
- CI validates all required build variants:
  - `Release | Win32`
  - `Release | x64`
  - `Debug | Win32`
  - `Debug | x64`
- CI must never silently fall back to `v143`; jobs explicitly pass `/p:PlatformToolset=v145`.
- If `v145` is not present on the runner, workflows fail with a clear remediation message.
- Visual Studio 2022 / MSVC `v143` is **not** an acceptable fallback for authoritative builds.

## CI Scope and Fast Checks
- Fast pull request checks run without installing Visual Studio build tools.
- Path-based CI routing:
  - Docs-only changes skip full Windows C++ matrix.
  - Remote JavaScript-only changes run Remote JS tests only.
  - C++/solution/project/workflow changes run full Windows matrix.
- Remote JS tests use npm dependency caching.
- Windows jobs use NuGet cache for package restore speedups.


## CI Check Tiers
- **Fast PR checks**: documentation link checks, dependency review, Remote JS security tests (when `Remote/**` changes), and workflow YAML validation. These checks avoid full MSBuild/Visual Studio setup for responsiveness.
- **Heavy Windows checks**: authoritative Visual Studio solution builds run only when C++/solution/project/workflow files change.

## Authoritative Windows Build Policy
- The authoritative build path is `Visual Studio/Envy.sln`.
- Required matrix: `Release|Win32`, `Release|x64`, `Debug|Win32`, `Debug|x64`.
- CI explicitly uses `/p:PlatformToolset=v145` and validates installed VC tools.
- CI fails fast when v145 (or required ATL/MFC components) are unavailable.
- Visual Studio 2022 / MSVC `v143` is not an acceptable fallback for authoritative builds.

## Path-Filter Behavior
- Docs/Markdown-only changes skip the heavy Windows matrix and CodeQL C++ PR analysis.
- Remote JS-only changes run Remote JS security tests, but skip full C++ matrix and C++ CodeQL PR analysis.
- C++/solution/project/workflow changes trigger authoritative Windows matrix and related heavy checks.

## Future Required Check Candidates
- Fast checks: `Documentation Check`, `Workflow Validation`, `Dependency Review`, `Remote JS Security Tests`.
- Heavy checks: `Build Release (Win32/x64)`, `Build Debug (Win32/x64)`, and `Analyze C++` once runner/toolchain stability is consistently proven.

- Unit tests continue to run in Windows matrix jobs after both Release and Debug builds when `tests/<Config> <Platform>/EnvyTests.exe` exists; missing test binaries emit warnings and do not hard-fail the job.
- Build artifacts are uploaded for Release and Debug matrix jobs (Envy exe/pdb, HashLib dll/pdb where present, and Services/Plugins DLLs).
- Coverage capability is preserved as `Coverage (Debug x64)` and now runs on `workflow_dispatch`, scheduled runs, and C++/build-impacting pull requests.
