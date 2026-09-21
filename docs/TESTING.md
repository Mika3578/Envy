# Testing Guide

## Album folder collection mount (#300)
- Production fix is in `Envy/AlbumFolder.cpp` / `Envy/LibraryFolders.cpp`.
- `CAlbumFolder` requires the MFC library lock (`Library.m_pSection`) and the live library object graph, so EnvyTests cannot construct or call `MountCollection` directly.
- `tests/test_albumfolder_mountcollection_smoke.cpp` only checks the child-visit policy (skip null, visit valid, empty tree, nested visit).
- Manual: open Library, import or open a `.collection` while the album tree exists; confirm no access violation. Repeat before the library has finished creating the album root (should no-op, not crash).

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
- Live eMule/aMule runs belong in the opt-in harness (`tools/interop/`), not in EnvyTests.

## ED2K live interop harness (#160)
- Command: `python3 tools/interop/run.py --dry-run` (default) or `--self-test`.
- Live: `python3 tools/interop/run.py --live --envy-exe <path> [--emule-exe <path>|--amule-exe <path>]`.
- Results are PASS/FAIL/SKIP/NOT_IMPLEMENTED. Future compressed-transfer, LowID, and Kad rows stay NOT_IMPLEMENTED.
- Required CI never needs eMule/aMule binaries or the public P2P network.
- Optional `workflow_dispatch` workflow: `ED2K interop harness` (self-test + dry-run only on GitHub-hosted runners).
- Details: `tools/interop/README.md`. This is **not** a claim that ENVY is fully interoperable.

## HashLib Tiger/TTH regression
- `tests/test_hashlib.cpp` now also covers `CTigerTree`: default constructor
  (unavailable, height 0, no root), identical-input root stability,
  incremental vs single-buffer hashing, and empty-file root stability.
  There is no in-repo golden TTH digest; these tests do not invent one.
  HashLib/EnvyTests still require Windows MSVC.

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

## Kad TCP firewall-check smoke tests
- `tests/test_kad_firewall_check_smoke.cpp` exercises `Envy/KadFirewallCheck.h`:
  exact `FIREWALLED_REQ`/`RES` framing, endian golden vectors, state machine
  (Unknown/Testing/Open/Firewalled), unsolicited/stale/duplicate responses,
  public-IP consensus, inbound rate limits, and wrap-safe tick comparisons.
  No live network and no `Sleep()`.

## Kad SEARCH_SOURCE_REQ app-trigger smoke tests
- `tests/test_kad_search_source_request_smoke.cpp` exercises
  `Envy/KadSearchSourceRequest.h`: `<FileHash 16><FileSize 8>` encode/decode,
  legacy hash-only decode failure, and the EnableKad / initialized / ED2K /
  size-known / period policy for calling `SearchSource` from downloads.

## Skin engine P0 smoke tests
- `tests/test_skin_engine_p0_smoke.cpp` exercises `Envy/SkinEngineP0.h`:
  StatusbarHeight member targeting, strict metric parse/clamp (keeps current
  on non-numeric input), `point`+`size` rect parse, `.HDA` part-name truncate,
  roundRect size validation, and LoadFromXML success aggregation.
  LoadFromXML remains non-transactional (failed sections fail the file load
  without rolling back earlier mutations).

## Crash report policy smoke tests
- `tests/test_crash_report_policy_smoke.cpp` covers dump filenames, metadata
  privacy, GitHub URL trust, retention, and Crashpad UUID path safety. Live
  crash-class tests run in disposable `tools/crash-probe/CrashProbe.exe`
  processes (`av`, heap, stack, fast-fail, terminate, invalid parameter,
  multithread, missing handler, unwritable database). Log tails are omitted.
  See `docs/10_dev/crash-reporting.md`.
