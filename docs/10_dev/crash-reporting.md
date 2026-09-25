# Crash reporting (maintainers)

Status: #353 / D-020 (hybrid migration)
Last updated: 2026-09-25

ENVY uses **two crash backends** during the BugSplat migration:

| Platform | Backend | User workflow |
| --- | --- | --- |
| **x64** (primary) | **BugSplat 7** (`/MT` static lib, out-of-process `BugSplatMonitor.exe`) | Native BugSplat crash dialog (Don't Send / Send Error Report); optional server symbolication when enabled |
| **Win32** (legacy Stage A) | **Crashpad** (vcpkg, local DB, upload off) | Unchanged next-launch TaskDialog from #90 |

Win32 lifecycle and D-014 are **out of scope** for the BugSplat PR; Win32 keeps Crashpad until separately decided.

## x64 — BugSplat

```
Envy.exe (x64)
  └── BugSplatHost
         ├── BugSplat.lib (/MT)
         ├── BugSplatMonitor.exe
         ├── BugSplatWer.dll
         └── BugSplatRc.dll
                └── BugSplat backend (when database configured + user sends)
```

- SDK slice: `ThirdParty/BugSplat/` (import via `scripts/import-bugsplat-sdk.ps1`).
- **No** Crashpad on x64: root `vcpkg.json` lists `crashpad` only for `windows & x86`.
- Official builds may pass `/p:EnvyBugSplatDatabase=<name>` (database name is not a secret). Forks leave it empty to compile without uploading.
- BugSplat is constructed in `SetIdentity` with `BugSplat(database, L"Envy", productVersion)` where `productVersion` is the same `major.minor` string as `m_sVersion` / `Envy.exe` file version. CI symbol upload uses that file version, not `github.sha` (revision stays in `envy_revision`).
- `CrashReporter::ShowStartupPromptIfNeeded` is skipped when BugSplat is active (no duplicate next-launch UI).
- CRT handlers for Crashpad are **not** installed on x64; BugSplat's `SetGlobalCRTExceptionBehavior` runs from `BugSplatHost`.

### Privacy (x64)

Do not attach registry exports, logs, share/download lists, torrent metadata, tracker passkeys, peer IPs, or screenshots by default. `BugSplatHost` sets small attributes only (version, revision, build type, arch, Windows version). Minidumps are **not** anonymous.

### WER

Some crash classes (fast-fail, stack overrun, etc.) require BugSplat WER registration (`BugSplatWer.dll` under `RuntimeExceptionHelperModules`). The installer runs at `PrivilegesRequired=poweruser`; HKLM registration may require elevation. Missing WER registration must not block startup — some crash types will not be captured.

### Symbols

Trusted `develop` / `main` pushes may upload symbols via `.github/workflows/bugsplat-symbols.yml` when `BUGSPLAT_CLIENT_ID`, `BUGSPLAT_CLIENT_SECRET`, and repository variable `ENVY_BUGSPLAT_DATABASE` are set. PRs and forks skip upload when secrets are absent.

## Win32 — Crashpad (unchanged)

See historical sections below and D-019 notes for local-database behavior.

- `CrashPadHost` + `crashpad_handler.exe` from vcpkg (`x86-windows-static`).
- `CopyCrashpadHandler.cmd` runs from `PreBuild.cmd` / post-build on Win32 only.
- Next-launch dialog and privacy helpers in `CrashReportPolicy.h` remain in use.

## Build

- x64: `scripts/bootstrap-vcpkg.cmd` restores manifest deps **without** Crashpad. Import BugSplat SDK into `ThirdParty/BugSplat` before building `Envy.vcxproj`.
- Win32: bootstrap `x86-windows-static` still requires `crashpad_handler.exe` in `vcpkg_installed`.

### Reproducible dependency probe (bugsplat-crashpad)

Official [BugSplat-Git/bugsplat-crashpad](https://github.com/BugSplat-Git/bugsplat-crashpad)
releases are public and pin-friendly, but they distribute **Crashpad** (`/MD`), not
the BugSplat 7 **Native** `/MT` SDK. They cannot replace
`scripts/import-bugsplat-sdk.ps1` for #354 without a product/CRT migration and a
new architecture review. Evidence and pinned hashes:
`ThirdParty/BugSplat/README.md` (section *Why not bugsplat-crashpad*).

## Tests

- `tools/bugsplat-mt-probe/` — `/MT` + `/MTd` link gate against official `lib/mt`.
- `tools/crash-probe/` — disposable Crashpad probes (Win32 + comparison); extend for BugSplat x64 in follow-up runs.
- `tests/test_crash_report_policy_smoke.cpp` — policy helpers (no live crash).

## Wire format

`Wire-format impact: none`
