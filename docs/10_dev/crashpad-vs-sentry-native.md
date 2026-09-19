# Crashpad vs Sentry Native (ENVY build evaluation)

Status: evaluation (#90, D-017)
Last updated: 2026-09-19
`Wire-format impact: none`

This is the comparative audit for replacing BugTrap. It is **not** a product
ship of Crashpad or Sentry. Root `vcpkg.json` stays unchanged until probe CI
evidence is reviewed.

## Capture engine vs receive/analyze service

| Layer | Job | ENVY requirement |
| --- | --- | --- |
| Capture | Snapshot the crashed process from **outside** that process | Must work in Debug and Release; survive heap corruption, stack overflow, and fast-fail better than in-process `MiniDumpWriteDump` |
| Store | Local reports + minidumps + build annotations | `%LOCALAPPDATA%\Envy\CrashReports\` (product path later); bounded retention |
| Share | Optional human step | Next-launch UI: open folder, copy summary, GitHub issue. **Upload only with explicit consent** |
| Analyze | Symbolicate, group, dashboard | Optional. Not required to ship a local reporter |

Do not pick a SaaS because the capture library is convenient. Do not write a
new in-process dumper because a SaaS is undesirable.

## Ranking (ENVY)

1. **Crashpad** (upstream via vcpkg `crashpad`) — preferred capture engine
2. **Sentry Native + Crashpad backend** — only if ENVY later wants a consented dashboard
3. BugSplat 7 — strong MFC/WER SDK; proprietary; not a fit for AGPL independence
4. Backtrace / Sauce Labs Crashpad fork — useful as a VS/CMake reference; vendor fork or SaaS if used as a product dependency
5. Homemade `MiniDumpWriteDump` (PR [#243](https://github.com/Mika3578/Envy/pull/243)) — salvage BugTrap deletion / next-launch UX / privacy tests; **do not merge as the product engine**

Excluded: Breakpad (predecessor), CrashRpt (archived 2026-01), WER LocalDumps
alone (HKLM / admin; no product UX).

## Current `develop` vs PR #243

| Tree | Crash reporter |
| --- | --- |
| `develop` | Vendored BugTrap (`Services/BugTrap`), Debug-oriented, bundled DbgHelp |
| PR #243 (closed, unmerged) | First-party `CrashDumpWin.h` + WER `EXCEPTION_CONTINUE_SEARCH` + next-launch TaskDialog |
| This evaluation | Isolated `tools/crash-probe/` + D-017. Does **not** retarget `Envy.sln` |

Salvage from #243 later: BugTrap removal, installer/PreBuild cleanup, privacy
policy helpers/tests, next-launch consent UI, PDB artifact retention. Drop
`CrashDumpWin.h` as the long-term dumper.

## Option A — Crashpad (preferred)

Architecture:

```
Envy.exe
  └── Crashpad client (in-process, small)
         └── crashpad_handler.exe (out-of-process)
                ├── local Crashpad database
                ├── minidump + annotations (version/build)
                └── upload OFF unless the client sets a URL and enables uploads
```

Why it matches ENVY:

- Official Breakpad successor; Chromium Windows client since 2015
- Out-of-process snapshot of the crashed process
- Local report database without a server
- Uploads are **off by default**; empty handler URL stores reports only
- Apache-2.0 (simpler next to AGPL than a proprietary SDK)
- Chromium treats Crashpad as security-critical shipped code

ENVY product shape after a later integration PR (not this evaluation):

```
Crash detected → next launch
  → show report
  → [Open folder] [Copy summary] [Create GitHub issue]
  → [Send] only after explicit consent (still no default URL)
```

Build facts for this repo:

| Item | Value |
| --- | --- |
| vcpkg port | `crashpad` (ENVY baseline `2026-07-02`) |
| Upstream build | GN + Ninja (wrapped by the port via `vcpkg-gn`) |
| MSBuild | Port mirrors `client/`, `util/`, `base/` headers into `include/` |
| Installed libs | `vcpkg_crashpad_client`, `vcpkg_crashpad_client_common`, `vcpkg_crashpad_util`, `vcpkg_crashpad_base` |
| Handler | `crashpad_handler.exe` (must be shipped next to `Envy.exe`) |
| WER helper | Port `TARGETS` currently install `handler:crashpad_handler` only — **probe CI must inventory** whether `crashpad_wer.dll` is produced |
| Triplet | Same as Envy: `x64-windows-static` / `x86-windows-static` |
| License | Apache-2.0 |

Main cost: first vcpkg compile is slow (GN). That is an evaluation/CI cost,
not a reason to keep BugTrap or a homemade dumper.

## Option B — Sentry Native (dashboard path)

On Windows the default backend **is Crashpad** (out-of-process). Sentry adds
events, breadcrumbs, sessions, metrics, HTTP transport, and optional WER glue.

Useful if ENVY later wants centralized grouping. Not required for a local
reporter.

| Item | Value |
| --- | --- |
| vcpkg port | `sentry-native` **0.16.0** on ENVY `builtin-baseline` `9e593bb1…` (newer 0.16.6 exists upstream; do not bump the repo baseline in this PR) |
| License | MIT AND Apache-2.0 AND BSD-3-Clause AND ICU |
| Default features | `backend` + `transport`; `wer` only for `windows & !static` |
| Envy triplet | `*-windows-static` → vcpkg **`wer` feature does not apply** |
| Offline compile | `"default-features": false, "features": ["backend"]` (no `transport`) |
| Standalone use | Sentry still describes native-only use as experimental / best-effort |

0.16.x Windows notes that matter for the probe (already in 0.16.0):

- Fast-fail / heap-corruption (`STATUS_HEAP_CORRUPTION` / `0xC0000374`) work
  in Sentry’s own tests via Crashpad + WER paths
- Stack guarantee applied in static builds so overflow handlers can run
- Configurable Windows minidump type; avoid allocations in the Crashpad
  crash path

Reservations:

- Large extra surface (breadcrumbs, sessions, HTTP) unless compiled and
  configured down
- Empty DSN and `SENTRY_TRANSPORT=none` are mandatory for ENVY privacy
- Fast-fail coverage on the **static** triplet is an evidence question for
  `tools/crash-probe`, not a brochure claim

## What the isolated probe measures

Project: `tools/crash-probe/` (not in `Visual Studio/Envy.sln`).

Workflow: `.github/workflows/crash-probe.yml` (matrix: Crashpad / Sentry
Native × x64 / Win32, Release, `v145`, static triplets).

Each matrix cell must record:

1. Binary inventory and sizes (`CrashProbe.exe`, `crashpad_handler.exe`,
   any DLL including `crashpad_wer*.dll`, PDBs)
2. Consent: empty upload URL / empty DSN; `uploads_enabled=0`; no
   `transport` feature on the Sentry manifest
3. Crash classes: access violation, real heap smash, stack overflow,
   `__fastfail`
4. Whether a `.dmp` (or Crashpad/Sentry report) appears in the local DB

Linux Cloud Agents cannot MSBuild this probe. Numbers come from the
Windows workflow artifacts (`crash-probe-<backend>-<platform>`).

## Consent rules (product and probe)

- No crash-time network
- No default DSN, ingest URL, or BugSplat/Backtrace/Sentry host
- Crashpad `SetUploadsEnabled(false)` + empty handler URL
- Sentry: empty DSN, auto-session off, `backend` only
- Product UI (later) may offer GitHub issue / folder / copy; upload stays
  a separate explicit action

`tools/crash-probe/check-consent.sh` greps the probe sources and manifests
for ingest hosts and for Sentry `transport`.

## Integration constraints (later product PR)

- Do **not** add `crashpad` or `sentry-native` to root `vcpkg.json` in this
  evaluation
- Do **not** expand CMake to replace `Envy.sln`
- Do **not** edit `Plugins/PluginWizard/**`
- Handler EXE must be copied by PreBuild/installer when the product PR lands
- PDBs stay in CI artifacts, not the end-user installer
- Windows-only; not an EnvyCore API (D-013)

## Decision

D-017: prefer Crashpad as the #90 capture engine. Keep Sentry Native as
Option B. Do not merge #243’s `CrashDumpWin.h` architecture. Revisit only
if probe CI shows Crashpad cannot be built or cannot capture the required
crash classes on Envy’s static MSVC triplets, while Sentry Native can.
