# Crash probe (evaluation only)

Isolated Win32 console app used to compare **Crashpad** and **Sentry Native
(Crashpad backend, no HTTP transport)** on ENVY’s MSVC `v145` static
triplets. It is **not** part of `Visual Studio/Envy.sln` and must not be
copied into `Envy.exe` as-is.

Canonical decision: `docs/10_dev/crashpad-vs-sentry-native.md` (D-017, #90).

## What it does

- Starts the chosen backend with **upload/DSN empty** and uploads disabled
- Prints handler path, database path, and `uploads_enabled`
- Can crash on demand: `av`, `heap`, `stack`, `fastfail`, `terminate`,
  `invalid`, `multithread`, plus `--no-handler`
- Does not contain an ingest URL

## Local Windows build

From a VS 2026 + vcpkg machine, in this directory:

```bat
copy /Y vcpkg-crashpad.json vcpkg.json
msbuild CrashProbe.vcxproj /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v145 /p:CrashProbeBackend=crashpad /p:VcpkgEnableManifest=true /p:VcpkgTriplet=x64-windows-static
```

The project sets `VcpkgManifestRoot` and also adds
`vcpkg_installed/<triplet>/include` (and `include/crashpad`) plus the matching
lib directory explicitly. VS 2026 MSBuild vcpkg integration does not reliably
inject those paths for this standalone project. Link `zs.lib` (debug `zsd.lib`);
this vcpkg baseline does not install `zlib.lib` on `*-windows-static`.

Product Crashpad links `vcpkg_crashpad_*.lib`. Sentry Native Option B vendors
Crashpad as `crashpad_client.lib` / `crashpad_util.lib` / `mini_chromium.lib`
plus `synchronization.lib` (`WaitOnAddress`). Do not mix those import names.

Copy `crashpad_handler.exe` (and any `crashpad_wer*.dll`) next to
`CrashProbe.exe`, then:

```powershell
.\run-probe.ps1 -Exe .\out\Release-x64-crashpad\CrashProbe.exe -Backend crashpad
```

`run-probe.ps1` requires a dump for `av` (and a second `av`). Heap, stack,
fast-fail, terminate, invalid parameter, and multithread are recorded. Missing
handler and unwritable database are negative tests.

CI: `.github/workflows/crash-probe.yml`. Product wiring lives in
`Envy/CrashPadHost.cpp` (not this probe).
