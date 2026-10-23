# Version Management

Scripts that bump the Envy product version. The release procedure that uses
them is in [`docs/DEPLOYMENT.md`](../docs/DEPLOYMENT.md).

## Files

- `auto-version.ps1` - core bump logic (PowerShell 7)
- `bump-version.ps1` - local wrapper with an interactive menu
- `release/verify-version.ps1` - release gate that checks the result
- `.github/workflows/version-management.yml` - opens the bump as a Draft PR

## Version convention

| Field | Meaning | Example |
| --- | --- | --- |
| `major` / `minor` / `patch` | Semantic version | `4` / `2` / `0` |
| `build` | Release counter within `M.m.p`: `1` for the first release of a new `M.m.p`, `+1` for each following prerelease or final | `3` |
| `preRelease` | `<label>.N` or `null` | `preview.3` |
| `fullVersion` | `M.m.p[-<label>.N]` | `4.2.0-preview.3` |
| `displayVersion` | `M.m.p[ <Label> N]` | `4.2.0 Preview 3` |
| `git.intendedTag` | `v<fullVersion>` | `v4.2.0-preview.3` |
| `git.lastTag` | Previous release tag | `v4.2.0-preview.2` |
| `git.branch` | Branch that carried the bump | `chore/bump-version-4-2-0-preview-3` |

`Envy/Envy.rc` mirrors it: `FILEVERSION` / `PRODUCTVERSION` `M,m,p,build`,
`FileVersion` string `M.m.p.build`, `ProductVersion` string = `displayVersion`.
`scripts/release/verify-version.ps1 -Tag <tag>` fails if any of these disagree.

## Actions

| `auto-version.ps1` | `bump-version.ps1 -Type` | Result from `4.2.0-preview.2` (build 2) |
| --- | --- | --- |
| `-PreRelease` | `prerelease` | `4.2.0-preview.3`, build 3 |
| `-PreRelease -PreReleaseLabel rc` | `prerelease -PreReleaseLabel rc` | `4.2.0-rc.1`, build 3 |
| `-Final` | `final` | `4.2.0`, build 3 |
| `-IncrementMinor -PreRelease` | - | `4.3.0-preview.1`, build 1 |
| `-IncrementPatch` | `patch` | `4.2.1`, build 1 |

`-IncrementMajor` / `-IncrementMinor` / `-IncrementPatch` reset `build` to 1
and start a final version unless `-PreRelease` is also given. `-PreRelease`
alone requires a current prerelease. The default label is `preview`.

`-UpdateFiles` also rewrites `Envy/Envy.rc` and inserts a
`## [<fullVersion>] - TBD` heading under `## [Unreleased]` in `CHANGELOG.md`
(the pending entries move into that release). `CMakeLists.txt` and
`Visual Studio\SetReleaseVersion.bat` are not touched.

The scripts never tag or push; `bump-version.ps1 -Interactive` can commit
locally on the current branch.

## Usage

```powershell
# Next preview, all version files
pwsh ./scripts/auto-version.ps1 -PreRelease -UpdateFiles

# Check the result against the tag you intend to push
pwsh ./scripts/release/verify-version.ps1 -Tag v4.2.0-preview.3

# Interactive
pwsh ./scripts/bump-version.ps1 -Interactive
```

In GitHub Actions, run **Version Management** from `develop`
(`version_action`, `prerelease_label`, `as_prerelease`). It opens a Draft PR
on `chore/bump-version-<version>`; see `docs/DEPLOYMENT.md` for the rest.
