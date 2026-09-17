# Release scripts

PowerShell 7 scripts used by `.github/workflows/release.yml`.

| Script | Role |
| --- | --- |
| `verify-version.ps1` | Tag vs `version.json` / `Envy.rc` / optional `Envy.exe` |
| `verify-artifacts.ps1` | Local asset set, SHA256, ZIP/setup sanity |
| `publish-draft-release.ps1` | Idempotent draft create/reuse + sequential upload by `release_id` |
| `repair-draft-release.ps1` | Repair an existing draft from a folder or Actions artifact |

All scripts use `Set-StrictMode -Version Latest` and `$ErrorActionPreference = 'Stop'`.
They never log tokens and never set `draft=false`.
