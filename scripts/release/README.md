# Release scripts

PowerShell 7 scripts used by `.github/workflows/release.yml` and the Windows
MSBuild composite action (`.github/actions/windows-msbuild`).

| Script | Role |
| --- | --- |
| `verify-version.ps1` | Tag vs `version.json` / `Envy.rc` / optional `Envy.exe` |
| `stage-portable.ps1` | Build `artifacts/portable` with installer-like runtime tree |
| `verify-runtime-dependencies.ps1` | Parse PE import tables; every non-system import must resolve inside the tree |
| `verify-artifacts.ps1` | Local asset set, SHA256, ZIP/setup sanity + runtime dirs |
| `publish-draft-release.ps1` | Idempotent draft create/reuse + sequential upload by `release_id` |
| `repair-draft-release.ps1` | Repair an existing draft from a folder or Actions artifact |

`verify-runtime-dependencies.ps1` ships with a self-test
(`verify-runtime-dependencies.selftest.ps1`) that runs in the Build workflow's
lint job without Windows or Visual Studio.

All scripts use `Set-StrictMode -Version Latest` and `$ErrorActionPreference = 'Stop'`.
They never log tokens and never set `draft=false`.
