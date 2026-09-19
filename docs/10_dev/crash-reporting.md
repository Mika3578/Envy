# Crash reporting (maintainers)

Status: current (#90)
Last updated: 2026-09-19

ENVY writes **local minidumps** with a small sanitized text sidecar. There is
no BugTrap, no crash-reporting SaaS, no automatic upload, and no registry
export.

This is a **Windows-only** application concern. It is not an EnvyCore API.

## Why not Crashpad / Breakpad / Sentry Native

| Criterion | Native WER + `MiniDumpWriteDump` | Crashpad / Breakpad / Sentry Native |
| --- | --- | --- |
| Maintenance | First-party, ~small surface | Extra handler process + vendored snapshot |
| Build complexity | Windows SDK `dbghelp.h`, no vcpkg | New third-party, CMake/GN, extra binaries |
| Processes | In-process dump, then normal WER | Crashpad handler process |
| x86/x64 | Same Envy Win32/x64 matrix | Extra handler builds |
| Privacy | Local files, user opt-in to share | Easy to grow into telemetry |
| Security surface | No network in the crash path | HTTP transport, extra parser code |
| Offline | Yes | Needs extra work to stay offline |
| Symbolication | Matching `Envy.exe` + `Envy.pdb` | Same PDBs, plus extra tooling |
| License | Windows SDK | Additional third-party license review |
| CI burden | Existing MSBuild + EnvyTests | Extra artifacts and test harnesses |

BugTrap was obsolete, Debug-only, attached HKCU settings, bundled old
`dbghelp.dll`, and is removed. A large crash SDK would be more complex than
the native path ENVY actually needs.

## Runtime

- Handlers install early in `CEnvyApp` construction (Debug and Release).
- Crash path: create `%LOCALAPPDATA%\Envy\CrashReports\`, `CREATE_NEW` dump,
  `MiniDumpWriteDump`, tiny UTF-8 metadata, return
  `EXCEPTION_CONTINUE_SEARCH` so Windows Error Reporting still runs.
- CRT `terminate` / invalid-parameter / purecall handlers write a dump
  without copying CRT strings (those strings can contain user paths).
- Next launch: TaskDialog (MessageBox fallback) to copy sanitized text, open
  the folder, or open GitHub’s new-issue page. The `.dmp` is never uploaded.
- Retention: keep up to 8 newest report groups or 50 MiB; never prune the
  newest report before the user has seen it.

## Dump type

`MiniDumpNormal | MiniDumpWithUnloadedModules |
MiniDumpWithIndirectlyReferencedMemory | MiniDumpWithThreadInfo`.

Not a full-memory dump. Indirectly referenced stack memory **can still contain
private fragments**. Treat dumps as sensitive.

## DbgHelp

Production and tests load **system** `dbghelp.dll` from `%SystemRoot%\System32`
(`LoadLibraryEx` + `LOAD_LIBRARY_SEARCH_SYSTEM32`). ENVY does not ship
DbgHelp. `MiniDumpWriteDump` is resolved at init, not during the crash.

## Symbols

Match a dump to:

1. ENVY version / revision from the `.txt` sidecar
2. The same architecture (`x64` or `Win32`)
3. `Envy.exe` and `Envy.pdb` from that build

Release CI on `develop` / `main` / dispatch uploads `Envy.exe` and `Envy.pdb`
together in the `envy-<platform>-Release` artifact (90-day PDB retention on
the explicit PDB upload). PDBs are **not** put in the end-user installer.

Private source paths in PDBs are a compiler default; do not publish extra
source indexes from crash reporting.

## Tests

`tests/test_crash_report_policy_smoke.cpp` covers filenames, metadata privacy,
GitHub URL trust, retention, dump failure, and a child-process dump smoke
(`EnvyTests.exe --crash-dump-child`). The child must not be the main test
process. Log-tail inclusion is omitted until a sanitizer can be proven.

The About dialog still has a Shift+Right-click-on-link hook that forces a
null-pointer crash after confirmation (Release asks first). That remains a
manual way to produce a local minidump.

## Wire format

Crash reporting does not touch ED2K, Kad, G1/G2, BitTorrent, or DC parsers.
`Wire-format impact: none`.
