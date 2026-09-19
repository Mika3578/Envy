# Crash reporting (maintainers)

Status: evaluation (#90, D-017)
Last updated: 2026-09-19

On **`develop` today**, ENVY still uses vendored **BugTrap**
(`Services/BugTrap`). That tree is legacy: Debug-oriented, HKCU settings,
bundled DbgHelp. Issue [#90](https://github.com/Mika3578/Envy/issues/90)
replaces it. There is no crash-reporting SaaS, no automatic upload, and no
silent telemetry in the intended design.

This is a **Windows-only** application concern. It is not an EnvyCore API.

## Product direction (D-017)

**Capture engine:** Crashpad (out-of-process `crashpad_handler.exe`, local
database, upload off by default).

**Service:** none required. Next launch shows a local report. Sharing is
opt-in (folder / copy / GitHub issue). A Sentry project would be Option B
only after an explicit dashboard decision.

Do **not** merge PR [#243](https://github.com/Mika3578/Envy/pull/243) as the
long-term engine. Its homemade `MiniDumpWriteDump` path is in-process and
weaker on heap-corruption / stack-overflow / fast-fail. Salvage from that
work: BugTrap deletion, next-launch UX, privacy tests, PDB artifacts — not
`CrashDumpWin.h`.

Comparative audit, vcpkg/MSVC constraints, and the isolated x64/Win32
prototype: [crashpad-vs-sentry-native.md](crashpad-vs-sentry-native.md).
Probe tree: `tools/crash-probe/`.

## Runtime (target, not shipped on `develop`)

```
Envy.exe → Crashpad client → crashpad_handler.exe
  → %LOCALAPPDATA%\Envy\CrashReports\  (local DB + minidump + annotations)
  → upload OFF
```

Until the product PR lands, Debug builds may still follow the BugTrap
dialog and `%APPDATA%\Envy\` dumps.

## Symbols

Match a dump to ENVY version/revision, architecture (x64 or Win32), and the
`Envy.exe` + `Envy.pdb` from that build. PDBs are **not** in the installer.

## Wire format

Crash reporting does not touch ED2K, Kad, G1/G2, BitTorrent, or DC parsers.
`Wire-format impact: none`.
