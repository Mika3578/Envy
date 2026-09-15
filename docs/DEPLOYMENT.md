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
| `Envy-4.2.0-preview.1-x64.zip` | Portable / diagnostic |
| `Envy-4.2.0-preview.1-win32.zip` | Portable / diagnostic |
| `SHA256SUMS.txt` | Checksums for all of the above |

Notes:
- Matrix builds x64 and Win32 independently; Preview 1 ships **two** setups (unified universal installer is deferred).
- Inno channel is driven by MSBuild `/p:InstallerAlpha=…` (from the tag: `Preview` / `True` / `False`).
- Authenticode signing is **not** configured for Preview 1; SmartScreen may warn.
- Releases are created as **draft** so assets can be verified before publish.

## Release Process (Current)
1. Land packaging/version changes on `develop`.
2. Smoke-test installers from CI artifacts (install, launch, uninstall) on a clean Windows host.
3. Tag the exact `develop` commit (`v4.2.0-preview.1`).
4. Let `release.yml` create the draft prerelease; download and re-verify those assets.
5. Complete release notes (limitations + unsigned warning) and publish the prerelease.

## Rollback Procedure (Recommended baseline)
1. Identify bad release tag/build.
2. Repoint distribution to last known good artifact (or unpublish / mark as prerelease only).
3. Publish rollback notice and known-issues update.
4. Open remediation issue with root cause and verification checklist.

## Operational Notes
- This repo is Windows-centric; reproducible release validation should occur on Windows runners/hosts.
- Version metadata lives in `version.json` and `Envy/Envy.rc` (Inno reads `FileVersion` from `Envy.exe`).
