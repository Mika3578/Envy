# Crash reporting (maintainers)

Status: current (#90, D-019)
Last updated: 2026-09-19

ENVY uses **Crashpad** (vcpkg `crashpad`, Apache-2.0) as the Windows capture
engine. `crashpad_handler.exe` snapshots the crashed process from **outside**
that process into a local database. There is no BugTrap, no Sentry Native
product dependency, no crash-reporting SaaS, no automatic upload, and no
registry export.

This is a **Windows-only** application concern. It is not an EnvyCore API.

Sentry Native is **not** shipped. It remains Option B in
`docs/10_dev/crashpad-vs-sentry-native.md` if ENVY later wants a consented
dashboard. This product path is Crashpad, not “Sentry wrapping Crashpad”.

## Why Crashpad instead of in-process `MiniDumpWriteDump`

PR #243 first prototyped `CrashDumpWin.h` (`MiniDumpWriteDump` in the faulting
process). That path is deleted. A successful `RaiseException` test does not
prove a handler survives heap corruption, stack overflow, CRT damage, or
loader-lock issues.

| Criterion | Homemade `MiniDumpWriteDump` | Crashpad (this tree) |
| --- | --- | --- |
| Crash-time work | In-process dump + sidecar write | Handler process snapshots the crashed process |
| Heap / stack / fast-fail | Weak (same damaged heap/stack) | Stronger; handler is a separate process |
| Build | Windows SDK `dbghelp.h` | vcpkg `crashpad` (GN wrapped by the port) |
| Extra binary | None | `crashpad_handler.exe` next to `Envy.exe` |
| Upload | None | Off: empty URL + `SetUploadsEnabled(false)` |
| Offline | Yes | Yes (local database) |
| License | Windows SDK | Apache-2.0 |

BugTrap was obsolete, Debug-only, attached HKCU settings, and bundled old
`dbghelp.dll`. It is removed.

## Runtime

```
Envy.exe
  └── CrashPadHost (init-time client; empty upload URL)
         └── crashpad_handler.exe
                ├── %LOCALAPPDATA%\Envy\CrashReports\  (Crashpad database)
                ├── UUID directory + minidump + metadata
                └── uploads disabled
```

- `CrashReporter::Initialize` runs from `CEnvyApp` construction and again in
  `InitInstance` (Debug and Release). It starts Crashpad and installs CRT
  `terminate` / invalid-parameter / purecall handlers that call
  `DumpWithoutCrash` then `abort`. Crashpad owns SEH; ENVY does **not**
  install `SetUnhandledExceptionFilter`.
- Crash-time work in `Envy.exe` is the Crashpad client stub. File I/O for the
  dump happens in `crashpad_handler.exe`.
- `SetIdentity` writes sanitized `identity.txt` in the database (version,
  revision, build type, arch). It does not copy CRT strings or user paths.
- Next launch: TaskDialog (MessageBox fallback) to copy sanitized text, open
  the folder, or open GitHub’s new-issue page. The minidump is never uploaded.
- Retention: keep up to 8 newest report groups or 50 MiB; never prune the
  newest report before the user has seen it. Crashpad UUID directories are
  pruned the same way as leftover `.dmp`/`.txt` pairs.
- If `crashpad_handler.exe` is missing or the database cannot be created,
  ENVY still starts. CRT handlers then no-op on `DumpNow`. Windows Error
  Reporting may still run. There is no second in-process dumper.

## Privacy

A Crashpad minidump is **not anonymous** and is **not** inherently
privacy-safe. Indirectly referenced stack memory can contain search queries,
filenames, peer IPs, tracker URLs with passkeys, usernames, or local paths.

ENVY does **not**:

- upload dumps, logs, or telemetry
- attach registry exports
- attach shared-file or download lists
- put dump bytes in a GitHub URL
- enable Crashpad HTTP upload (empty URL; `SetUploadsEnabled(false)`)

Sharing a minidump is an explicit user action after the next-launch dialog.

## Symbols

Match a dump to:

1. ENVY version / revision from `identity.txt` (and the executable module
   list inside the minidump)
2. Architecture (`x64` or `Win32`)
3. `Envy.exe` and `Envy.pdb` from **that same build** (PDB GUID / age)

Release CI on `develop` / `main` / dispatch uploads `Envy.exe`, `Envy.pdb`,
and `crashpad_handler.exe` in the `envy-<platform>-Release` artifact (90-day
PDB retention on the explicit PDB upload). PDBs are **not** in the installer.
PDBs can reveal source paths and build information; do not publish them
publicly as a symbol server without review.

Maintainer workflow: download the matching CI artifact, open the minidump in
WinDbg / Visual Studio with that `Envy.pdb` on the symbol path.

## Tests

- `tests/test_crash_report_policy_smoke.cpp` — filenames, metadata privacy,
  GitHub URL trust, retention, Crashpad UUID path safety. Does **not** link
  Crashpad and does not crash the test runner.
- `tools/crash-probe/` — disposable `CrashProbe.exe` child processes.
  Workflow: `.github/workflows/crash-probe.yml` (Crashpad × x64/Win32
  Release). Run `35470816399` on `00e06c1` (required `av` / `av-second`
  dumps present; consent `uploads_enabled=0` and empty `upload_url`):

  | Kind | x64 dump | Win32 dump |
  | --- | --- | --- |
  | access violation | yes (116 KiB) | yes (91 KiB) |
  | heap corruption `0xC0000374` | yes | yes |
  | stack overflow | yes (~1.1 MiB) | yes (~1.1 MiB) |
  | C++ `terminate` | yes | yes |
  | multithread AV | yes | yes |
  | `__fastfail` `0xC0000409` | **no** | **no** |
  | invalid parameter `0xC0000409` | **no** | **no** |
  | `--no-handler` | none (expected) | none |
  | unwritable database | init exit 2 | init exit 2 |

  Handler: `tools/crashpad_handler.exe` (x64 875 KiB, Win32 761 KiB).
  `crashpad_wer.dll` is not installed by this vcpkg port, so fast-fail /
  fail-fast CRT paths are not captured. The AV minidump CodeView RSDS GUID
  matched `CrashProbe.exe` / `CrashProbe.pdb` (x64
  `39FB374B-373C-4F58-818B-1051C567DD0F` age 1; Win32
  `59B4FB15-7F30-4EDE-AD8F-812F896CB620` age 1).
- About dialog Shift+Right-click on the web link still forces a null-pointer
  crash after confirmation (Release asks first). That is a manual way to
  produce a local Crashpad dump; it is not proof of heap/stack robustness.

## Installer and build

- Root `vcpkg.json` depends on `crashpad` (same `builtin-baseline` as the rest
  of ENVY). `Visual Studio/Envy.sln` remains the authoritative app build.
- `Envy/Envy.vcxproj` sets `VcpkgManifestRoot` to the repository root and adds
  `vcpkg_installed/<triplet>/include` (and `include/crashpad`) plus the matching
  `lib` / `debug/lib` directory. The project directory is `Envy/`, and
  `AdditionalIncludeDirectories` historically listed only `..\Services`, so
  MSBuild vcpkg integration does not see Crashpad headers unless the manifest
  root is explicit. Those properties do **not** restore `vcpkg_installed` before
  `PreBuildEvent`. Local builds must run `scripts/bootstrap-vcpkg.cmd` (CI
  already runs `vcpkg install --triplet=…` first). See `docs/10_dev/build.md`.
- `Envy/CopyCrashpadHandler.cmd` copies `crashpad_handler.exe` (and
  `crashpad_wer*.dll` if present next to that handler) beside `Envy.exe`.
  Release uses `vcpkg_installed/<triplet>/tools/crashpad_handler.exe`
  (`vcpkg_copy_tools`); Debug uses `debug/tools/crashpad_handler.exe`.
  A `tools/crashpad/` subdirectory is accepted as a fallback. A recursive
  first-match copy would ship the Debug handler with Release `Envy.exe`.
  The copy fails the build if the handler is missing.
- Inno Setup copies the handler into `{app}` (required). `crashpad_wer.dll` is
  optional (`skipifsourcedoesntexist`) because the current vcpkg port installs
  `handler:crashpad_handler` only. PDBs stay out of the installer.

## Wire format

Crash reporting does not touch ED2K, Kad, G1/G2, BitTorrent, or DC parsers.
`Wire-format impact: none`.
