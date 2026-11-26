# Cloud-agent verification on Linux

Status: active
Last updated: 2026-11-26
Scope: what AI/cloud agents can and cannot verify on a Linux VM for this repository, with exact commands.
Source of truth: `.github/workflows/*`, `.github/scripts/*`, `.cursor/environment.json`, `docs/10_dev/build.md`.

Envy's product build is Windows-only (MSVC `v145`, MFC). A Linux agent cannot
compile the application or run its C++ test binaries. It **can** run every
deterministic Linux check that CI itself runs on `ubuntu-latest`, and it must
record the Windows validation it could not perform instead of claiming it.

## What runs on a Linux VM

All commands verified on the reference cloud VM (`clang-format-18`, Node 24,
Python 3). Run them from the repository root.

### Format check (same as CI's `Format Check` job)

```bash
BASE_SHA=<base-commit> HEAD_SHA=<head-commit> bash .github/scripts/format-check.sh
```

Requires `clang-format-18` and `clang-format-diff-18` (installed by
`.cursor/environment.json`). Differential: only changed hunks are checked, so
legacy off-diff lines never fail the run.

### Repository self-tests (a Linux-runnable subset of CI's `Lint build files` job)

The `Lint build files` job additionally runs inline checks an agent can also
replicate by hand (every `.vcxproj` uses toolset `v145`, `Envy.sln` is
`Format Version 12.00`, no `_ATL_XP_TARGETING` in first-party project files)
plus BugSplat SDK/runtime and compile-commands/portable-runner self-tests; the
script-based commands below are the subset agents normally need.

```bash
bash .github/scripts/classify-changes.selftest.sh
bash .github/scripts/check-agent-attribution.selftest.sh
bash .github/scripts/check-installer-main-iss-encoding.selftest.sh
bash .github/scripts/check-source-encoding.selftest.sh
bash .github/scripts/format-check.selftest.sh
python3 .github/scripts/pr-phase.selftest.py
python3 .github/scripts/audit-ruleset.selftest.py
python3 .github/scripts/review-digest.selftest.py
python3 .github/scripts/compile-changelog.selftest.py
```

### Remote web security tests

```bash
npm ci --prefix Remote/tests --no-audit --no-fund
npm test --prefix Remote/tests
```

Requires **Node 24** (CI pins `node-version: "24"` in
`.github/workflows/code-quality.yml`). Both commands below run under whatever
`node` is first on `PATH`, so the Node 24 `PATH` fix shown after them applies
to `npm ci` as well. On cloud VMs the `node` first on
`PATH` can be a v22 shim provided by the exec daemon, and a glob in a `PATH`
assignment is not expanded by the shell; Jest 30 then fails with
`Must use import to load ES Module: .../@exodus/bytes/encoding-lite.js`. Put
the real binary first:

```bash
PATH="$(ls -d "$HOME"/.nvm/versions/node/v24.*/bin | sort -V | tail -n1):$PATH" npm test --prefix Remote/tests
```

### Diff hygiene before pushing

```bash
git diff --check
BASE_SHA=<base> HEAD_SHA=<head> bash .github/scripts/check-source-encoding.sh
```

The encoding guard catches new U+FFFD bytes, C1 controls and mojibake in
changed lines — mandatory for any edit touching legacy-encoded sources.

## What cannot be verified on Linux

- `Visual Studio/Envy.sln` / any `.vcxproj` build (MSVC v145, MFC/ATL,
  Windows SDK). `tools/dev/run-msbuild.ps1` and `.vscode/tasks.json` targets
  are Windows-only.
- `EnvyTests`, `PeerXmlTests`, `UnpackerTests` (MSBuild test projects).
  Canonical Windows commands: build
  `msbuild tests\EnvyTests.vcxproj /p:Configuration=Release /p:Platform=x64`
  (EnvyTests is a solution member; `PeerXmlTests` and `UnpackerTests` are
  standalone projects), then run
  `tests\Release x64\EnvyTests.exe` (and the matching Win32 binary).
- CMake targets: `CMakeLists.txt` and `HashLib/CMakeLists.txt` are MSVC-only
  (`/W4`, MASM, `/LARGEADDRESSAWARE`); they do not configure for GCC/Clang.
- The installer (Inno Setup / bundled ISCC), BugSplat SDK import, and any
  runtime/interop validation of the Windows client.

## Required agent behavior

1. Run the Linux checks above and paste their real output into the PR
   template **Validation** section.
2. Record what could **not** be verified under "Runtime / interoperability"
   (`Tested HEAD / artifact` and the manual-validation checkbox). Never
   present a Draft-lane CI pass as Windows build evidence: on Draft PRs the
   Windows steps are deferred by design (`build.yml` prints a DEFERRED notice).
3. Do not apply `stage:live-test`, do not mark the PR Ready, and do not
   request any review product while the PR is Draft — those are maintainer
   actions (`AGENTS.md` PR workflow).
4. Branches use `type/short-kebab-summary` (`feat/`, `fix/`, `docs/`, `ci/`,
   `build/`, `chore/`, …) — never tool/agent prefixes (`cursor/`, `claude/`,
   `copilot/`, …), per `AGENTS.md` hard rule 11.

## Check → workflow map

| Check | Workflow / job | Runs on Linux CI? |
| --- | --- | --- |
| `Lint build files` (incl. all self-tests above) | `build.yml` → `lint-build-files` | yes |
| `Format Check` | `code-quality.yml` → `lint-check` | yes |
| `Vcpkg manifest sanity` | `dependency-review.yml` | yes |
| `secret-scan` (gitleaks) | `security.yml` | yes |
| `Analyze (c-cpp)` | `codeql.yml` (PRs use `build-mode: none`) | yes |
| `Build x64 Release` / `Build Win32 Release` | `build.yml` (Windows steps deferred in Draft) | no (Windows runners) |
| `Static Analysis` (MSVC `/analyze`) | `code-quality.yml` | no |
| Sonar / Gitleaks scans | external / `code_scanning` ruleset | n/a |
