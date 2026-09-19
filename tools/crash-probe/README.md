# Crash probe (evaluation only)

Isolated Win32 console app used to compare **Crashpad** and **Sentry Native
(Crashpad backend, no HTTP transport)** on ENVY’s MSVC `v145` static
triplets. It is **not** part of `Visual Studio/Envy.sln` and must not be
copied into `Envy.exe` as-is.

Canonical decision: `docs/10_dev/crashpad-vs-sentry-native.md` (D-017, #90).

## What it does

- Starts the chosen backend with **upload/DSN empty** and uploads disabled
- Prints handler path, database path, and `uploads_enabled`
- Can crash on demand: `av`, `heap`, `stack`, `fastfail`
- Does not contain an ingest URL

## Local Windows build

From a VS 2026 + vcpkg machine, in this directory:

```bat
copy /Y vcpkg-crashpad.json vcpkg.json
msbuild CrashProbe.vcxproj /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v145 /p:CrashProbeBackend=crashpad /p:VcpkgEnableManifest=true /p:VcpkgTriplet=x64-windows-static
```

Sentry cell: copy `vcpkg-sentry.json` to `vcpkg.json` and
`/p:CrashProbeBackend=sentry`. Win32 uses `Platform=Win32` and
`x86-windows-static`.

Copy `crashpad_handler.exe` (and any `crashpad_wer*.dll`) next to
`CrashProbe.exe`, then:

```powershell
.\run-probe.ps1 -Exe .\out\Release-x64-crashpad\CrashProbe.exe -Backend crashpad
```

CI: `.github/workflows/crash-probe.yml`.
