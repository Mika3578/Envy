# First-party warning baseline

A *ratchet* that stops new compiler warnings from creeping into code we own,
without forcing us to fix the existing backlog first.

## Why

The Envy core builds with `/Wall`, which produces thousands of warnings — but
the overwhelming majority are fired **inside the Windows SDK, MFC and STL
headers** that we include, not in our own source. A clean full-solution
`Release|x64` build shows only a handful of warnings located in first-party
`.cpp`/`.h` files. Those are the ones worth guarding.

`WarningBaseline.ps1` extracts the warnings whose **location** is a first-party
source file, ignoring:

- anything outside the repository (SDK / MSVC / MFC headers),
- vendored third-party trees under `Services/`,
- the `Plugins/PluginWizard/` templates.

Each warning is keyed as `<repo-relative-path>|<code>` (line/column dropped so
the baseline does not churn when code moves). Because system-header warnings
are excluded, the baseline is stable across MSVC point releases and CI runners.

## Files

- `WarningBaseline.ps1` — `-Mode generate` writes the baseline; `-Mode check`
  fails (exit 1) if a fresh build log contains a first-party warning not in it.
- `warnings-baseline.txt` — the committed accepted set.

## CI

`.github/workflows/build.yml` runs `-Mode check` on the `x64 Release` leg,
reusing `build-x64-Release.warnings.log` from the build step (no extra build).
It is **advisory** (`continue-on-error: true`) until one green run confirms the
baseline matches the runner's MSVC, then it can be promoted to a hard gate.

## Regenerating (ratchet down)

When warnings are fixed — or new accepted ones are introduced deliberately —
refresh the baseline from a clean build and commit the diff:

```pwsh
msbuild "Visual Studio\Envy.sln" /m /t:Rebuild /p:Configuration=Release /p:Platform=x64 `
  /p:PlatformToolset=v145 /p:WindowsTargetPlatformVersion=10.0 `
  /flp:"logfile=build-x64-Release.warnings.log;warningsonly;verbosity=normal;encoding=UTF-8"
pwsh Repository/Warnings/WarningBaseline.ps1 -Mode generate -LogPath build-x64-Release.warnings.log
```
