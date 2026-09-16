# Testing Guide

## Current Test Surface
- Primary test project: `tests/EnvyTests.vcxproj`
- Additional standalone test executables exist in `tests/` (`test_runner.cpp`, simple integration binaries)
- Current coverage is strongest in hashing/crypto-related paths

## Running Tests (Visual Studio / MSBuild)
1. Build `EnvyTests` (`tests/EnvyTests.vcxproj` via `Visual Studio/Envy.sln`).
2. Run the produced `EnvyTests.exe` for the chosen config/platform.

There is no CMake test entry point at the repository root.
## Writing New Tests
- Place new test source files under `tests/`.
- Register test entry in the existing test framework/main.
- Prefer deterministic tests that avoid network flakiness.
- For protocol logic, isolate parser/state transitions from live network where possible.

## Coverage Targets (Proposed)
- Hashing/core utilities: maintain high coverage.
- Protocol handlers: add targeted unit tests for packet parse/serialize logic.
- Persistence/config migration: add regression tests for settings and schema changes.

## Packet length validation smoke tests
- `tests/test_protocol_parser_smoke.cpp` exercises pure predicates in
  `Envy/EDSourcePacketValidate.h` and `Envy/PacketLengthValidate.h`
  (ED2K TCP length, BT extension length, G1 `{deflate}` bound, GGEP type
  byte, ED2K preview frame size). These mirror the guards used by the
  live parsers without linking the full MFC application.

## SecureIdent policy smoke tests
- `tests/test_secureident_policy_smoke.cpp` exercises `Envy/SecureIdentPolicy.h`
  for issue #75: null/empty/zero/non-zero/legacy-MD5 responses are rejected,
  SecureIdent is not advertised (`ED2K_VERSION_SECUREID == 0`), state never
  becomes verified, and ED2K transfer does not require SecureIdent.
