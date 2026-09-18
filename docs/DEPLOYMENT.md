# Deployment and Release

## Environments
- **Development:** local Windows builds via Visual Studio
- **CI validation:** GitHub Actions workflows for build, quality, security scans
- **Release packaging:** `.github/workflows/release.yml` (tag `v*` or workflow_dispatch)

## CI/CD
Current repository includes workflows for:
- Build and test
- Code quality/static checks
- CodeQL security scanning
- Release packaging (per-platform setup + ZIP + checksums)

## Preview 1 packaging (current)

Target tag: `v4.2.0-preview.1`

Published assets (draft + prerelease when the tag contains `preview` / `beta` / `rc` / `alpha`):

| Asset | Role |
| --- | --- |
| `Envy-4.2.0-preview.1-x64-setup.exe` | Recommended installer |
| `Envy-4.2.0-preview.1-win32-setup.exe` | 32-bit compatibility installer |
| `Envy-4.2.0-preview.1-x64.zip` | Portable package (full runtime tree) |
| `Envy-4.2.0-preview.1-win32.zip` | Portable package (full runtime tree) |
| `SHA256SUMS.txt` | Checksums for all of the above |

Notes:
- Matrix builds x64 and Win32 independently; Preview 1 ships **two** setups (unified universal installer is deferred).
- Inno writes each platform setup to repo-root `Builds/` (e.g. `Envy.4.2.0.1.64.Preview.exe` / `Envy.4.2.0.1.32.Preview.exe`); `release.yml` stages exactly one `.exe` from that directory per matrix job, then renames for GitHub Release assets.
- Inno channel is driven by MSBuild `/p:InstallerAlpha=…` (from the tag: `Preview` / `True` / `False`).
- Authenticode signing is **not** configured for Preview 1; SmartScreen may warn.
- Releases are created as **draft** so assets can be verified before publish.
- The automatic pipeline **never** publishes (`draft` stays `true`); a human publishes after smoke tests.
- `workflow_dispatch` dry-runs packaging into an Actions artifact; only a real `v*` tag push creates/updates the GitHub draft Release (unless `repair_release_id` is set — see below).

## Release Process (Current)
1. On the packaging branch (or `develop` after merge), run **workflow_dispatch** with `version=v4.2.0-preview.1` and leave `repair_release_id` empty. That path builds, packages, verifies checksums/ZIPs, and uploads Actions artifact `release-v4.2.0-preview.1` only — **no GitHub Release and no tag**.
2. Download that artifact; confirm the five expected files; smoke-test install / launch / uninstall (x64 and Win32).
3. Land packaging/version changes on `develop`.
4. Tag the exact `develop` commit (`v4.2.0-preview.1`). Do not move/retag an existing release tag.
5. The same `release.yml` on tag push creates or **reuses** the **draft** GitHub prerelease, then uploads the five assets **sequentially by `release_id`** (scripts under `scripts/release/`). Reruns are idempotent: matching assets are kept; mismatched assets are replaced; the job fails if the final remote set is incomplete.
6. Complete release notes (limitations + unsigned warning) and publish the prerelease manually in the GitHub UI.

### Repairing an existing draft (no retag)
If a draft already exists for the tag but is missing assets (example: Preview 1 release id `391048728`):

1. Prefer a full `workflow_dispatch` with `version=v4.2.0-preview.1` and `repair_release_id=<id>` so CI rebuilds, re-verifies, and uploads onto that draft only (`draft` remains true).
2. Or run locally / in a trusted shell:

```powershell
pwsh ./scripts/release/repair-draft-release.ps1 `
  -Tag v4.2.0-preview.1 `
  -ReleaseId 391048728 `
  -ArtifactRunId <run-id> `
  -ArtifactName release-v4.2.0-preview.1
```

Never delete, recreate, or move the tag to repair assets.

Notes:
- `workflow_dispatch` without `repair_release_id` is intentionally a dry-run. Do **not** treat it as a publish path.
- Draft upload no longer uses `softprops/action-gh-release` (parallel uploads raced on freshly created drafts). Publication uses `scripts/release/publish-draft-release.ps1` with `gh api` against the concrete `release_id`.
- Pre-upload gates: `verify-version.ps1` (tag / `version.json` / `Envy.rc` / built `Envy.exe`) and `verify-artifacts.ps1` (five assets, SHA256, ZIP extract with runtime tree `Data`/`Skins`/`Schemas`/`Plugins`/…, no `.pdb`/Debug paths).
- Portable ZIPs are staged by `scripts/release/stage-portable.ps1` to mirror `Installer/Scripts/Main.iss` (binaries at root, plugins under `Plugins\`, shared resources under `Data\`/`Skins\`/`Schemas\`/`Templates\`/`Remote\`). Flattened EXE/DLL-only ZIPs are rejected.

## Rollback Procedure (Recommended baseline)
1. Identify bad release tag/build.
2. Repoint distribution to last known good artifact (or unpublish / mark as prerelease only).
3. Publish rollback notice and known-issues update.
4. Open remediation issue with root cause and verification checklist.

## Operational Notes
- This repo is Windows-centric; reproducible release validation should occur on Windows runners/hosts.
- Version metadata lives in `version.json` and `Envy/Envy.rc` (Inno reads `FileVersion` from `Envy.exe`).
