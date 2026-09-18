# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **DevSecOps tooling (local + PR advisors)** — `scripts/ci-fast.ps1` / `scripts/ci-verify.ps1` for a Windows-local gate approximating MSVC/tests; Renovate (`renovate.json5`) owns GitHub Actions updates with grouping/digests while Dependabot keeps **vcpkg only**; CodeRabbit (`.coderabbit.yaml`) and clang-tidy→reviewdog (`.github/workflows/clang-tidy-pr.yml`) are advisory PR reviewers. See `docs/10_dev/devsecops-envy.md`.
- **4.2.0 Preview 1 release packaging** — Unified product version metadata (`version.json` `4.2.0-preview.1`, Windows `FILEVERSION`/`PRODUCTVERSION` `4.2.0.1`, display `4.2.0 Preview 1`). Release workflow builds per-platform Inno Setup installers (`InstallerAlpha=Preview` from tags containing `preview`), publishes `Envy-<version>-{x64|win32}-{setup.exe|.zip}` plus `SHA256SUMS.txt`, and creates a **draft** GitHub Release marked **prerelease** when the tag contains `preview`/`beta`/`rc`/`alpha`. Preview 1 uses separate x64 and Win32 setups (unified universal installer deferred).
- **Release pipeline validation scripts** — `scripts/release/verify-version.ps1`, `stage-portable.ps1`, `verify-artifacts.ps1`, `publish-draft-release.ps1`, and `repair-draft-release.ps1` gate tag/`version.json`/`Envy.rc`/`Envy.exe` consistency, stage a full portable runtime tree, verify SHA256 + ZIP/setup sanity, and support idempotent draft asset repair.

### Fixed
- **Portable ZIP incomplete runtime tree** — Release packaging no longer flattens only `*.exe`/`*.dll` into the ZIP. `stage-portable.ps1` mirrors the Inno install layout (`Envy.exe` + service DLLs at root, plugins under `Plugins\`, plus `Data\`/`Schemas\`/`Skins\`/`Skins\Languages\`/`Templates\`/`Remote\`). `verify-artifacts.ps1` fails flattened or resource-less ZIPs.
- **Release draft asset upload race** — Tag-push packaging no longer uses parallel `softprops/action-gh-release` uploads against a freshly created draft (that failed mid-upload with `Error saving asset` and left Preview 1 missing x64 assets). Uploads now run sequentially via GitHub API against the concrete `release_id`, skip/replace assets idempotently, verify the final remote set, and never auto-publish (`draft` stays true). `workflow_dispatch` remains a dry-run unless `repair_release_id` is set explicitly.
- **ED2K preview frame cap + bulk write (#120)** — `OnPreviewAnswer` rejects empty or >4 MiB peer-advertised preview frames (`Ed2kPreviewFrameAcceptable`) and writes the first accepted frame with a single bounded `Write`/`Seek` instead of a per-byte loop. Follow-up to the #74/#109 unsigned remaining-bytes check.
