# Crashpad vs Sentry Native (ENVY build evaluation)

Status: evaluation (#90, D-019)
Last updated: 2026-09-19
`Wire-format impact: none`

This is the comparative audit for replacing BugTrap. Product capture is
**Crashpad** (`Envy/CrashPadHost.cpp`, root `vcpkg.json`). Sentry Native is
not a product dependency. Isolated `tools/crash-probe/` remains the
crash-class / binary-size harness.

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
5. Homemade `MiniDumpWriteDump` (early PR #243) — **deleted**; salvage was BugTrap removal, next-launch UX, privacy tests

Excluded: Breakpad (predecessor), CrashRpt (archived 2026-01), WER LocalDumps
alone (HKLM / admin; no product UX).

## Current `develop` vs PR #243

| Tree | Crash reporter |
| --- | --- |
| `develop` (until #243 merges) | Vendored BugTrap (`Services/BugTrap`), Debug-oriented, bundled DbgHelp |
| PR #243 (this work) | Crashpad out-of-process handler + local DB + next-launch TaskDialog. `CrashDumpWin.h` removed |
| `tools/crash-probe/` | Isolated Crashpad vs Sentry Native crash-class measurements |

Salvaged from the MiniDump prototype: BugTrap removal, installer/PreBuild
cleanup, privacy policy helpers/tests, next-launch consent UI, PDB artifact
retention. Capture engine is Crashpad, not `CrashDumpWin.h`.

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

ENVY product shape (this PR):

```
Crash detected → Crashpad handler writes a local minidump
Next launch
  → show report
  → [Open folder] [Copy summary] [Create GitHub issue]
  → no Send / no default URL
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

## Integration constraints

- Root `vcpkg.json` lists `crashpad` only (not `sentry-native`)
- Do **not** expand CMake to replace `Envy.sln`
- Do **not** edit `Plugins/PluginWizard/**`
- Handler EXE is copied by `Envy/CopyCrashpadHandler.cmd` and the installer
- PDBs stay in CI artifacts, not the end-user installer
- Windows-only; not an EnvyCore API (D-013)

## Decision

D-019: Crashpad is the #90 capture engine. Sentry Native stays Option B and is
not linked into `Envy.exe`. WER LocalDumps is not the product reporter.
Breakpad and CrashRpt are excluded. Homemade `MiniDumpWriteDump` is removed.

## Comparison matrix (ENVY, 2026-09-19)

Sources: Crashpad docs/repo; Chromium Crashpad integration; Sentry Native
0.16.x docs and vcpkg port; BugSplat Windows C++ docs; Sauce Labs Backtrace
Crashpad docs; Microsoft WER / LocalDumps; Breakpad README (maintenance
moved to Crashpad); CrashRpt GitHub archive notice (2026-01).

| Criterion | Crashpad (product) | Sentry Native (Option B) | BugSplat | Backtrace / Sauce Labs | WER LocalDumps | Breakpad | CrashRpt | Homemade MiniDump (#243 prototype) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Maintenance | Chromium-backed; vcpkg port `2026-07-02` | sentry-native 0.16.0 on this baseline (0.16.6 upstream) | Commercial SDK + service | Commercial; Crashpad fork | Windows 10 1809+ inbox | Predecessor; not for new integrations | Archived 2026-01 | First-party; we own every crash-state bug |
| Windows desktop C++ | Chromium client since 2015 | Windows default backend **is** Crashpad | Native C++ / ATL/MFC samples | Crashpad-based | OS component | Historical | Historical | `dbghelp` MiniDumpWriteDump |
| MFC compatibility | No MFC types required (ENVY wrapper is Win32) | C API; extra event/session surface | Explicit MFC/ATL samples | C/C++ | No in-process SDK | C/C++ | MFC-era | Header-only Win32 |
| Win32 + x64 | Yes (static triplets used by probe) | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Windows 10 1809+ | Yes | Yes | Yes | Yes | Yes | Yes | Untested | Yes |
| VS 2026 / v145 | Via vcpkg-gn, not a GN conversion of Envy.sln | CMake/vcpkg; not required in Envy.sln | Vendor binaries | Vendor/CMake fork | SDK | Dead for new VS | Dead | SDK only |
| Out-of-process collection | `crashpad_handler.exe` | Crashpad backend | Out-of-process + WER options | Crashpad | WER service | In-process / Breakpad helper | Mixed / dated | **In-process** |
| Heap corruption | Handler snapshots another process | Same Crashpad path; static triplet drops vcpkg `wer` | Claims WER/fast-fail coverage | Crashpad | OS | Weaker than Crashpad | Unknown/unmaintained | Same damaged heap as the crash |
| Stack overflow | Handler + optional stack guarantee | Documented stack guarantee in static builds | Documented | Crashpad | OS | Limited | Unknown | Same damaged stack |
| Fast-fail | Crashpad + optional WER helper DLL | Tests mention 0xC0000374; static `wer` feature off | WER integration | Crashpad/WER | OS | No | No | Unhandled / WER only |
| Double-fault | Handler already running; restartable client flag | Same Crashpad client | Vendor | Crashpad | OS | Limited | Unknown | Second dump blocked by `DumpOnce` |
| Local/offline | Local report DB; no server | Local cache if DSN empty; extra event DB | Service-oriented | Service-oriented | `%LOCALAPPDATA%\CrashDumps` if configured | Local dumps | Local | Local files |
| Mandatory networking | No | No if transport compiled out and DSN empty | Service dependency | Service dependency | Optional Microsoft upload via WER | No | No | No |
| Automatic upload | Off unless URL set **and** uploads enabled | Default product path is HTTP; must be compiled/configured off | Default is vendor ingest | Default is vendor ingest | User/OS WER consent | No | Optional | No |
| Explicit consent | ENVY next-launch UI; no Send button | Would require ENVY-owned transport | Vendor UI | Vendor UI | Windows WER UI | N/A | Optional UI | Next-launch UI (salvaged) |
| Minidump quality | Crashpad minidump + annotations | Crashpad minidump + Sentry event | Vendor minidump | Crashpad | Configurable dump type | Minidump | Minidump | MiniDumpNormal + unloaded + indirect + thread info |
| PDB / symbolication | Matching `Envy.exe`+`Envy.pdb` (CI artifact, 90-day) | Same PDBs + optional Sentry symbol upload | Vendor symbol store | Vendor | Local WinDbg | Local | Local | Same PDBs |
| Crash grouping | Local files; human GitHub title | Hosted grouping if DSN used | Hosted | Hosted | Watson grouping if uploaded | None | Limited | Filename + sidecar |
| Annotations / metadata | StartHandler map + `identity.txt` | Tags, contexts, breadcrumbs | Product version grouping | Attachments/annotations | Limited | Annotations | Custom | Sidecar `.txt` |
| Breadcrumbs | None (intentional) | Yes (compiled out / max 0 in probe) | Vendor | Vendor | No | No | No | No |
| Attachments | Crashpad attachments dir (unused) | Yes | Yes | Yes | Extra files via WER | Limited | Yes | Sidecar only |
| Local crash database | Crashpad DB under `%LOCALAPPDATA%\Envy\CrashReports\` | Sentry DB if used | Vendor cache | Vendor cache | LocalDumps folder | Dump dir | Dump dir | Flat `.dmp`/`.txt` |
| Retention | ENVY prunes 8 groups / 50 MiB | Configurable | Vendor quota | Vendor quota | DumpCount registry | Manual | Manual | Same 8 / 50 MiB policy |
| Crash UI | Next-launch TaskDialog | Would add Sentry UI or keep ours | Vendor dialogs | Vendor | WER dialog | None | CrashRpt UI | TaskDialog (kept) |
| Installer impact | Copy `crashpad_handler.exe` (+ optional `crashpad_wer.dll`) | Handler + sentry bits | Redistributable SDK files | Handler | None (registry) | Helper | Helper | None extra |
| Added binaries | 1 EXE required; WER DLL optional | Handler + sentry static lib | Multiple | Handler | 0 | Helper | Helper | 0 |
| Runtime footprint | Handler process + static client libs | Crashpad + Sentry event/session code | Vendor | Crashpad fork | 0 in-proc | Smaller, weaker | Unknown | dbghelp in-proc |
| Build-system impact | vcpkg GN wrapped; Envy.sln unchanged as authority | Extra CMake; static `wer` unavailable | Drop-in libs | CMake/MSVC fork | Registry only | Dead | Dead | None |
| CI complexity | First compile slow; then binary cache | Same Crashpad plus sentry | N/A (rejected) | N/A (rejected) | None | N/A | N/A | EnvyTests child `RaiseException` only |
| Dependency updates | vcpkg pin / Dependabot | vcpkg pin + Sentry API drift | Vendor | Vendor fork drift | OS | None | None | None |
| Security surface | Handler protocol, minidump parser in handler | + HTTP, envelope parser, DSN | Proprietary + network | Proprietary + network | OS | Dump writer | Unmaintained | dbghelp in crashed process |
| Privacy surface | Minidump memory fragments (documented) | Minidump + breadcrumbs/PII APIs | Hosted PII | Hosted PII | May upload to Microsoft if user consents | Minidump | Minidump | Minidump |
| License | Apache-2.0 | MIT AND Apache-2.0 AND BSD-3-Clause AND ICU | Proprietary | Proprietary | Windows | BSD-like | Historical | Windows SDK |
| AGPL compatibility | Apache-2.0 OK | OSI mix OK; not used | Poor fit for AGPL independence | Poor fit | Inbox | OK | Unclear | OK |
| Vendor lock-in | None (local DB) | High if DSN/transport used | High | High (fork + SaaS) | Microsoft | None | None | None |
| Long-term maintenance | vcpkg + thin `CrashPadHost` | Sentry API + Crashpad | Paid | Paid fork | Inbox, no product UX | Do not adopt | Do not adopt | ENVY owns Crashpad-hard problems |

WER as **primary** reporter: LocalDumps is HKLM for machine-wide dumps (admin), per-user is limited, no next-launch GitHub UX, no ENVY version sidecar. Keep WER as incidental OS behavior, not the product.

Backtrace’s Crashpad fork: useful as a VS/CMake reference; adopting it would add a vendor fork without a privacy/offline benefit over upstream Crashpad via vcpkg.
