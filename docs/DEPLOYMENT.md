# Deployment and Release

## Environments
- **Development:** local Windows builds via Visual Studio
- **CI validation:** GitHub Actions workflows for build, quality, security scans
- **Version bump:** `.github/workflows/version-management.yml` (workflow_dispatch on `develop`, opens a Draft PR)
- **Release packaging:** `.github/workflows/release.yml` (tag `v*` or workflow_dispatch)

## CI/CD
Current repository includes workflows for:
- Build and test
- Code quality/static checks
- CodeQL security scanning
- Version bump PR preparation
- Release packaging (per-platform setup + ZIP + checksums)

## Version metadata

`version.json` and `Envy/Envy.rc` carry the product version; Inno reads
`FileVersion` from the built `Envy.exe`. The convention (release counter in
`build`, `M.m.p-<label>.N` tags, `M.m.p <Label> N` display strings) is
documented in [`scripts/README-version-management.md`](../scripts/README-version-management.md).
`scripts/release/verify-version.ps1` enforces it in `release.yml`.

In the examples below, `<tag>` is the release tag (for example
`v4.2.0-preview.3`), `<version>` is the tag without `v` (`4.2.0-preview.3`),
and `<M.m.p.b>` is the Windows file version (`4.2.0.3`).

## Release assets

Tags containing `preview`, `beta`, `rc` or `alpha` are created as **draft
prereleases**; other tags as **drafts**.

| Asset | Role |
| --- | --- |
| `Envy-<version>-x64-setup.exe` | Recommended installer |
| `Envy-<version>-win32-setup.exe` | 32-bit compatibility installer |
| `Envy-<version>-x64.zip` | Portable package (full runtime tree) |
| `Envy-<version>-win32.zip` | Portable package (full runtime tree) |
| `SHA256SUMS.txt` | Checksums for all of the above |

Notes:
- Matrix builds x64 and Win32 independently and ships **two** setups (a unified universal installer is deferred).
- Inno writes each platform setup to repo-root `Builds/` (e.g. `Envy.<M.m.p.b>.64.Preview.exe` / `Envy.<M.m.p.b>.32.Preview.exe`); `release.yml` stages exactly one `.exe` from that directory per matrix job, then renames it for the GitHub Release assets.
- The Inno channel is driven by MSBuild `/p:InstallerAlpha=…` (from the tag: `Preview` for `preview`/`beta`/`rc`, `True` for `alpha`, otherwise `False`).
- Authenticode signing is **not** configured; SmartScreen may warn.
- The automatic pipeline **never** publishes (`draft` stays `true`); a human publishes after smoke tests.
- `workflow_dispatch` dry-runs packaging into an Actions artifact; only a real `v*` tag push creates/updates the GitHub draft Release (unless `repair_release_id` is set — see below).

## Release Process
1. **Bump the version.** Run **Version Management** from `develop`:
   - `version_action=prerelease` for the next preview (`preview.N` → `preview.N+1`);
   - `final` to promote the current prerelease (`4.2.0-preview.N` → `4.2.0`);
   - `patch` / `minor` / `major` for a new line (with `as_prerelease=true` it starts at `<label>.1`).

   The workflow updates `version.json`, `Envy/Envy.rc` and `CHANGELOG.md`, runs
   `verify-version.ps1` against the intended tag, and opens a **Draft PR** on
   `chore/bump-version-<version>` with a GitHub-signed `github-actions[bot]`
   commit. It never pushes to `develop` and never tags. The same bump can be
   prepared locally with `pwsh ./scripts/auto-version.ps1 -PreRelease -UpdateFiles`
   on a `chore/` branch.
2. **Curate the bump PR.** Check out its branch, write the release summary under
   the new `CHANGELOG.md` heading, update the README release-target line if it
   names the version, and push. That push starts CI (PRs opened with
   `GITHUB_TOKEN` do not trigger `pull_request` workflows on their own).
3. **Dry run.** Run `release.yml` via **workflow_dispatch** with `version=<tag>`
   on the bump branch and leave `repair_release_id` empty. It builds, packages,
   verifies checksums/ZIPs and uploads Actions artifact `release-<tag>` only —
   **no GitHub Release and no tag**.
4. **Smoke test.** Download that artifact, confirm the five expected files, and
   smoke-test install / launch / uninstall (x64 and Win32).
5. **Merge.** Mark the PR Ready and squash-merge it into `develop` per `AGENTS.md`.
6. **Tag.** Create a signed tag on the exact squash commit on `develop` and push it:

   ```powershell
   git fetch origin
   git tag -s <tag> -m "Envy <displayVersion>" <squash-commit-sha>
   pwsh ./scripts/release/verify-version.ps1 -Tag <tag>
   git push origin <tag>
   ```

   Do not move or retag an existing release tag; if the version must change,
   bump again.
7. **Draft release.** `release.yml` on the tag push creates or **reuses** the
   **draft** GitHub Release, then uploads the five assets **sequentially by
   `release_id`** (scripts under `scripts/release/`). Reruns are idempotent:
   matching assets are kept, mismatched assets are replaced, and the job fails
   if the final remote set is incomplete.
8. **Publish.** Live-test the draft assets, complete the release notes
   (limitations + unsigned warning), and publish manually in the GitHub UI.

### Repairing an existing draft (no retag)
If a draft already exists for the tag but is missing assets:

1. Prefer a full `workflow_dispatch` with `version=<tag>` and `repair_release_id=<id>` so CI rebuilds, re-verifies, and uploads onto that draft only (`draft` remains true).
2. Or run locally / in a trusted shell:

```powershell
pwsh ./scripts/release/repair-draft-release.ps1 `
  -Tag <tag> `
  -ReleaseId <id> `
  -ArtifactRunId <run-id> `
  -ArtifactName release-<tag>
```

Never delete, recreate, or move the tag to repair assets.

Notes:
- `workflow_dispatch` without `repair_release_id` is intentionally a dry-run. Do **not** treat it as a publish path.
- Draft upload does not use `softprops/action-gh-release` (parallel uploads raced on freshly created drafts). Publication uses `scripts/release/publish-draft-release.ps1` with `gh api` against the concrete `release_id`.
- Pre-upload gates: `verify-version.ps1` (tag / `version.json` / `Envy.rc` / built `Envy.exe`) and `verify-artifacts.ps1` (five assets, SHA256, ZIP extract with runtime tree `Data`/`Skins`/`Schemas`/`Plugins`/…, no `.pdb`/Debug paths).
- Portable ZIPs are staged by `scripts/release/stage-portable.ps1` to mirror `Installer/Scripts/Main.iss` (binaries at root, plugins under `Plugins\`, shared resources under `Data\`/`Skins\`/`Schemas\`/`Templates\`/`Remote\`). Flattened EXE/DLL-only ZIPs are rejected.

## Rollback Procedure (Recommended baseline)
1. Identify bad release tag/build.
2. Repoint distribution to last known good artifact (or unpublish / mark as prerelease only).
3. Publish rollback notice and known-issues update.
4. Open remediation issue with root cause and verification checklist.

## Operational Notes
- This repo is Windows-centric; reproducible release validation should occur on Windows runners/hosts.
- Version Management needs the repository setting "Allow GitHub Actions to create and approve pull requests"; without it the PR step fails after the branch is created.
