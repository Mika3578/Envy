# DEV_TRACKER.md - Living progress log

This file is the single living source of truth for what is in flight
and what has shipped in the Envy modernization effort.

**Rules** (also in `AGENTS.md`):

1. Before starting a task, move it from **Backlog** to **In progress**
   and add your handle / agent name + start date.
2. When done, move it to **Done** with date, commit hash, short outcome.
3. If blocked, leave it in **In progress**, add a `Blockers:` line, and
   stop. Don't invent workarounds.
4. Keep entries terse. One line per task is the norm; sub-bullets only
   if there is something a reader genuinely needs to know.
5. Reverse-chronological inside each section (newest on top).

For the strategic plan, see [`MODERNIZATION.md`](./MODERNIZATION.md).
For the canonical AI rules, see [`AGENTS.md`](./AGENTS.md).

---

## In progress

- **2026-05-19** | claude/review-ci-workflow-twgeE / PR #47
  -> Apply PR review thread fixes in CI workflows (`release.yml`,
  `security.yml`): pin vcpkg clone source + cache key hardening,
  keep release publication gated as draft, and add gitleaks integrity
  verification + SARIF upload.

- **2026-05-19** | claude/review-ci-workflow-twgeE
  -> CI workflow audit + refactor. Phase 1 (quick wins) in flight:
  aligning `release.yml` on `build.yml` (v145 verification, C1083 PCH
  workaround, vcpkg cache + pinning, action versions, draft logic).
  VS 2026 / v145 / `windows-2025-vs2026` confirmed real & GA
  (Microsoft Nov 2025 + Actions May 4 2026). Migration of
  `windows-latest` to VS 2026 starts June 8 2026 -> `code-quality.yml`
  must be removed before then (Phase 2).

- **2026-05-17** | claude/code-audit-modernization-nJcTT / PR #35
  -> Rebased onto `origin/develop` (base retargeted from `main`).
  Fixed second-wave C++20 errors: C7626 (`TOOLBAR_RES`,
  `TCPBandwidthMeter`), remaining `std::binary_function` /
  `std::unary_function` in HostCache, FragmentedFile, DownloadSource,
  CtrlLibraryTileView. Pushed; awaiting green `windows-2025-vs2026`
  matrix. Operational status: `docs/DEV_TRACKER.md` §6.

---

## Blockers

_(none right now)_

---

## Done

- **2026-05-18** | fix/startup-skin-toolbar-icons | follow-up PR #43
  -> Closed the residual real miss: `CLibraryTree.Physical` was the
  only built-in toolbar name actually absent from `Default.xml`.
  Added an empty `<toolbar name="CLibraryTree.Physical"/>` next to
  its `CLibraryTree.Virtual` counterpart; `CLibraryFrame::OnSkinChange`
  requests this name when `Settings.Library.ShowVirtual` is false and
  then hides `m_wndTreeBottom`, so an empty definition resolves the
  lookup with zero visible UI change. Extended `CSkin::ValidateLoaded`
  critical-toolbar list to cover the library frame names so a future
  regression surfaces immediately. Files: `Envy/Res/Default.xml`,
  `Envy/Skin.cpp`, `CHANGELOG.md`, `DEV_TRACKER.md`,
  `docs/DEV_TRACKER.md`.

- **2026-05-17** | fix/startup-skin-toolbar-icons | _(uncommitted)_
  -> Fixed startup `Skin load error: Toolbar Lookup` and
  `Failed to load icon` debug-log noise for built-in panel windows
  (`CDownloadsWnd`, `CUploadsWnd`, `CNeighboursWnd`, `CIRCFrame`,
  `CLibraryTree.Top`, `CLibraryHeaderBar.Physical`,
  `CLibraryTileView.Physical`, `CLibraryTree.Physical`) and command
  IDs 40156, 40158, 40320-40328, 40340, 40345. Root cause:
  `CChildWnd::OnCreate` invokes virtual `OnSkinChange()` (via
  `LoadState`) before `CMainWnd::OnSkinChanged` calls the first
  `Skin.Apply()`, so `CSkin::m_pToolbars` / `CCoolInterface` image
  maps were still empty when children requested them. Minimal fix:
  lazy `CSkin::EnsureLoaded()` from toolbar / image lookups; once-
  per-session dedup in `CSkin::CreateToolBar` and
  `CCoolInterface::ExtractIcon`; debug-only `CSkin::ValidateLoaded()`
  called at end of `Skin.Apply()`. No toolbar buttons removed, no
  network behaviour changed. Validation: `git diff --check` clean;
  MSBuild Debug x64 + Release x64 (toolset v145) on
  `Visual Studio\Envy.sln` both succeed with 0 errors.
  Files: `Envy/Skin.h`, `Envy/Skin.cpp`, `Envy/CoolInterface.cpp`,
  `CHANGELOG.md`, `DEV_TRACKER.md`, `docs/DEV_TRACKER.md`.

- **2026-05-17** | PR #35 Node.js runtime follow-up | _(this commit)_
  -> Upgraded workflow `actions/checkout` from `v4` to `v5` across
  `.github/workflows/*` for Node.js 24 readiness; no runtime/source/docs
  changes besides this tracker note.

### Phase 0 - Infrastructure bootstrap

- **2026-05-16** | claude/code-audit-modernization-nJcTT | commit `a2ee3ec`
  -> `chore: modernize for Visual Studio 2026 (toolset v145) + CI infrastructure`
  - 142 `<PlatformToolset>` rewritten v141_xp/v142 -> v145 across 45 vcxproj
  - 66 `_ATL_XP_TARGETING` and 2 `ENVY_USE_ASM` preprocessor defines removed
  - 44 projects gained `<WindowsTargetPlatformVersion>10.0</...>`
  - 12 first-party projects gained `<LanguageStandard>stdcpp20</...>`
  - 19 plugins gained `<LanguageStandard>stdcpp17</...>`
  - `Envy.sln` header bumped to "Visual Studio Version 18"
  - `Envy/StdAfx.h`: Win 10 baseline (_WIN32_WINNT 0x0A00,
    NTDDI_WIN10_RS5), MSVC 14.50 guard, dropped XPSUPPORT auto-detect
  - `Envy/Buffer.{h,cpp}` + `Envy/Connection.h`: 32 `throw()` -> `noexcept`
  - `Envy/Buffer.cpp`: removed reserved `register` keyword
  - `vcpkg.json` + `vcpkg-configuration.json` seeded
  - 10 GitHub Actions workflows added (build, codeql,
    dependency-review, clang-tidy, format-check, release, stale,
    labeler, copilot-setup-steps, dependabot-auto-merge)
  - Dependabot config (vcpkg + github-actions, weekly)
  - `.github/{CODEOWNERS, SECURITY.md, CONTRIBUTING.md, FUNDING.yml,
    pull_request_template.md, ISSUE_TEMPLATE/*.yml, labeler.yml}`
  - `.gitignore`, `.editorconfig`, `.clang-format`,
    `.clang-format-ignore`
  - `Visual Studio/SetVS2026.{bat,ps1}` retarget scripts
  - `CMakePresets.json` scaffold (Phase 5)
  - `CITATION.cff`
  - `MODERNIZATION.md` (full audit + 5-phase plan)

- **2026-05-16** | claude/code-audit-modernization-nJcTT | commit `ac6474c`
  -> Translate `MODERNIZATION.md` to English, add AI rules
  - `AGENTS.md` (canonical AI ruleset)
  - `CLAUDE.md`, `.cursorrules`, `.cursor/rules/envy.mdc`,
    `.clinerules`, `.aider.conf.yml`, `.windsurfrules`,
    `.continue/rules/envy.md`,
    `.github/copilot-instructions.md`
  - `DEV_TRACKER.md` (this file)

- **2026-05-16** | PR #35 tenth CI feedback | _(this commit)_
  -> First **v145 build** confirmed (MSVC 14.50.35717,
  PlatformToolset reported correctly). 52 real C++20 errors
  surfaced. Three distinct fixes landed:
  - `Envy/StdAfx.h:939` (`CTimeAverage`): replaced
    `for (CAverageList::const_iterator i = ...)` with a
    range-based for. Two-phase lookup couldn't see the
    `CAverageList` typedef that was declared later in the same
    template class body.
  - `Envy/StdAfx.h:1007` (`GetFileSize`): C++20 ternary type
    deduction rejects `CString` vs `LPCTSTR` ambiguity. Rewrote
    the call so both branches produce `CString`.
  - `Envy/Envy.vcxproj`, `HashLib/*`, `TorrentEnvy/*`,
    `Unpacker/Unpacker.vcxproj`: added
    `<ConformanceMode>false</ConformanceMode>` (= `/permissive`,
    not `/permissive-`). v145 with `/std:c++20` defaults to
    `/permissive-`, which enforces strict two-phase name lookup
    against the templated `Envy/Hashes/{Hash,StoragePolicies,
    CheckingPolicies,ValidationPolicies}.hpp` policy chain. The
    proper Phase 2 fix is `this->name` annotations everywhere;
    keeping `/permissive` unblocks Phase 0 builds.

- **2026-05-16** | PR #35 ninth CI feedback | commit `80d73b7`
  -> First `windows-2025-vs2026` run failed in 27-43 s in the
  "Verify Visual Studio 2026 with v145 is installed" step. The
  image exposes v145 under the generic
  `Microsoft.VisualStudio.Component.VC.Tools.x86.x64` component
  (no `.14.50` suffix) and ships the v143 fallback as
  `VC.14.44.17.14.x86.x64`. Replaced the package-name check with
  a filesystem probe: look for `VC\Tools\MSVC\14.5*` under the
  install path, and confirm the VS major version is 18.x.

- **2026-05-16** | PR #35 eighth CI feedback | commit `1699b8d`
  -> Switch the hosted runner from `windows-2025` (VS 2022 / v143)
  to `windows-2025-vs2026` (public-preview image with VS 2026 /
  v145 / MSVC 14.50). Microsoft made this image GA-track in March
  2026; it carries the right toolset out of the box.
  - All four workflows that ran on `windows-2025` re-pinned:
    `build.yml`, `release.yml`, `codeql.yml`,
    `copilot-setup-steps.yml`.
  - `build.yml` is now strict: no `continue-on-error`, no toolset
    fallback. Added a `Verify Visual Studio 2026 with v145 is
    installed` step that fails fast if the runner image regresses.
  - Removed the best-effort `Install VS 2026 build tools` step
    (no longer needed) and the multi-toolset detection / fallback
    matrix in `Resolve effective PlatformToolset`.
  - Reinstated the hard `#error` guard in `Envy/StdAfx.h` when
    `_MSC_VER < 1950`.

- **2026-05-16** | PR #35 seventh CI feedback | commit `22897da`
  -> The previous fix commit (`cc9f5e2`) cleared the
  binary_function / for_each_if / D9035 errors as expected. The
  only remaining failure in the next run was my own toolset guard
  in `Envy/StdAfx.h:32`, which hard-errors when `_MSC_VER < 1950`.
  Hosted runners are still at MSVC 14.4x (v143). Downgraded the
  v145 requirement to a `#pragma message` warning so the build
  proceeds on v143; only pre-VS 2017 toolsets still hard-error.
  Will be restored to a hard error once the runner image carries
  v145 reliably.

- **2026-05-16** | PR #35 sixth CI feedback | commit `cc9f5e2`
  -> First real C++20 build errors from MSBuild (toolset v143).
  Only two distinct errors in the entire matrix, both trivial:
  - `HashLib/Utility.hpp:288`: missing semicolon after
    `f( *first )` in `for_each_if`. Pre-existing typo that v141/v142
    never complained about; v143's C++20 parser is stricter.
  - `Envy/Strings.h:166`: `std::binary_function` was removed in
    C++17. Dropped the empty base class from `CompareWordEntries`
    (nothing in the codebase relies on the inherited typedefs).
  - Same `std::binary_function` pattern also in
    `Envy/StdAfx.h:872` (`std::less<CLSID>`) and
    `Envy/StdAfx.h:884` (`std::less<CString>`). Both swept.
    `throw()` exception specs in those two struct operators
    converted to `noexcept` while we were there.
  - Bonus: removed `<MinimalRebuild>true</...>` (=`/Gm`) from 6
    projects - the flag is deprecated and emits D9035 in v143+.

- **2026-05-16** | PR #35 fifth CI feedback | commit `bd3917d`
  -> Set a real vcpkg baseline. The previous commit removed the
  placeholder from `vcpkg.json` but `vcpkg-configuration.json`
  still had `baseline: "000...0"`, which is what produced
  `fatal: remote error: upload-pack: not our ref 000...` during
  the vcpkg install step (confirmed by Copilot's diagnosis of
  the failure log).
  - Set `builtin-baseline` in both `vcpkg.json` and
    `vcpkg-configuration.json` to
    `2b65c20fc66eda893aa15a15a453c3cf09500b19` (current vcpkg
    master tip).
  - Dependabot will continue to bump this baseline weekly.

- **2026-05-16** | PR #35 fourth CI feedback | commit `b459a75`
  -> Fix the build-blocker hypothesis (round 1) plus toolset
  output propagation:
  - `vcpkg.json`: removed placeholder `builtin-baseline: "000...0"`
    that made vcpkg reject the manifest before MSBuild started.
    Also dropped `version>=` constraints (they require a real
    baseline) and the `libgeoip` dep (not in vcpkg under that
    name; libmaxminddb replaces it in Phase 3).
  - Toolset detection step now writes to `$GITHUB_OUTPUT` and
    `$GITHUB_ENV` via `[System.IO.File]::AppendAllText` with a
    BOM-less UTF-8 encoding, so the output is parseable. Previous
    `Out-File -Encoding utf8` was adding a BOM that confused
    GitHub Actions' parser, leaving the failure comment showing
    `Effective PlatformToolset: ``` (empty).
  - Failure-comment step now distinguishes "reached MSBuild" vs
    "died earlier", reads vcpkg buildtree logs when MSBuild logs
    are absent, and lists workspace files for diagnosis.

- **2026-05-16** | PR #35 third CI feedback | commit `a8ba22e`
  -> Auto-publish failing build details back as a PR comment so
  the failure log can be read via `pull_request_read get_comments`
  (the runner log archives need GitHub auth which isn't reachable
  from this session). 200 error lines + 80 warning lines wrapped
  in `<details>` blocks per matrix cell.

- **2026-05-16** | PR #35 second CI feedback | commit `a9d1d72`
  -> Fix three CI failures from run #2:
  - `Vcpkg manifest sanity`: jq parsed `.version-string` as `.version
    - string` (subtraction) because of the dash. Switched to bracket
    notation `.["version-string"]` and added an explicit type check
    on `.dependencies`.
  - `Build x64/Win32 Debug/Release`: the toolset fallback was emitting
    `v1444` instead of the actual MSBuild toolset name `v143`. Rewrote
    the mapping with the right MSVC -> toolset table
    (14.50+ -> v145, 14.30-14.49 -> v143, 14.20-14.29 -> v142,
    14.10-14.16 -> v141). Builds are still expected to fail until v145
    is on the runner or Phase 1 source fixes land.
  - `clang-tidy diff`: moved to ubuntu-latest, made it strictly
    advisory (always exits 0), surfaces findings as `::warning::`
    lines instead of failing the check. clang-tidy without a real
    compile_commands.json against MFC code was producing tons of
    false positives and a non-zero exit.

- **2026-05-16** | PR #35 first CI feedback | commit `a4eb463`
  -> Fix two CI failures surfaced by the first PR run:
  - `Lint build files` was matching `_ATL_XP_TARGETING` inside the
    `Plugins/PluginWizard/**` templates (which are intentionally
    left untouched). Added `--exclude-dir=PluginWizard` to the
    grep so first-party projects are checked correctly.
  - `Build Win32 Debug` failed at `Add MSBuild to PATH` with
    "Unable to find MSBuild" because the strict
    `vs-version: "[18.0,)"` requires VS 2026, which the hosted
    `windows-2025` image does not yet ship by default. Dropped the
    constraint (same change in `build.yml`, `codeql.yml`,
    `release.yml`, `copilot-setup-steps.yml`), added a best-effort
    step that asks the VS Installer to add the v145 toolset, and a
    fallback that selects the newest installed v14x toolset if
    v145 is still absent. Build matrix marked
    `continue-on-error: true` for Phase 0; Phase 1 will flip it
    off once the runner reliably provides v145.

---

## Backlog

Snapshot of the next things to do. Ordered roughly by sequence. Move
items into **In progress** as you pick them up.

### Phase 1 - First green build

- [ ] Trigger CI on the modernization branch and capture the first
      build log. Open one issue per distinct error class observed.
- [ ] Resolve C++20 fallout in `Envy/`: any remaining
      `std::auto_ptr`/`std::random_shuffle`/`std::iterator` (audit
      reported only `augment::auto_ptr` so far - confirm).
- [ ] Update `WinSDK` include paths if any project hard-codes a
      specific version.
- [ ] Decide on RatDVD / SWF plugins: keep with conditional build,
      or drop from `Envy.sln`?
- [ ] Smoke-test: launch `Envy.exe` post-build, confirm Gnutella
      neighbor connection.

### Phase 2 - Warning cleanup + /permissive-

- [ ] Enable `<ConformanceMode>true</ConformanceMode>` (`/permissive-`)
      one project at a time; track per-project state here.
- [ ] Audit and prune the 70 `#pragma warning(disable: ...)` directives
      in `Envy/StdAfx.h`.
- [ ] Enable `<SDLCheck>true</SDLCheck>` (`/sdl`).
- [ ] Enable `<ControlFlowGuard>Guard</ControlFlowGuard>` (`/guard:cf`).
- [ ] Enable `<SpectreMitigation>Spectre</SpectreMitigation>` in
      Release configs.
- [ ] Phase out repo-wide `_CRT_SECURE_NO_WARNINGS`; document the
      remaining unsafe call sites that are blocked.

### Phase 3 - Dependency modernization (vcpkg cutover)

- [ ] Move each bundled lib to vcpkg, project by project:
      - [ ] `Services/zlib` -> `vcpkg install zlib`
      - [ ] `Services/Bzlib` -> `vcpkg install bzip2`
      - [ ] `Services/SQLite` -> `vcpkg install sqlite3`
      - [ ] `Services/MiniUPnP` -> `vcpkg install miniupnpc`
      - [ ] `Services/GeoIP` -> `vcpkg install libmaxminddb` (modern
            replacement for legacy MaxMind)
      - [ ] `Services/LibUTP` -> evaluate `libutp` from vcpkg or vendor
            an up-to-date fork
- [ ] Once each lib is removed: delete the `Services/<lib>/` subtree
      and the corresponding `.vcxproj`.
- [ ] `Services/BugTrap` -> replace with Windows Error Reporting (WER)
      or `crashpad`. Spike first.
- [ ] `LibGFL` (non-free, AGPL conflict): track an issue. Likely
      removed from the default build, kept as opt-in.

### Phase 4 - Runtime robustness

- [ ] Wire `HashLib/HashTest` into `build.yml` and fail on test
      regression.
- [ ] Add AddressSanitizer build config
      (`<EnableASAN>true</EnableASAN>` on Debug).
- [ ] Publish `.pdb` symbols as build artifacts on tagged releases.

### Phase 5 - ARM64 + signing

- [ ] Add `Release|ARM64` configurations to `Envy.sln` and every
      first-party `.vcxproj`.
- [ ] Set up Azure Trusted Signing in `release.yml` (secrets
      `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`).
- [ ] Decide on WiX/MSIX alongside Inno Setup for Microsoft Store.

### Cross-cutting / ops

- [ ] Push branch, open draft PR.
- [ ] Enable Dependency graph / Dependabot alerts / Code scanning /
      Secret scanning in repo Settings.
- [ ] Configure branch protection on `main` (CI + CodeQL + dependency
      review status checks required, CODEOWNERS review for
      `.github/` and `Visual Studio/`).
- [ ] First Dependabot run replaces the placeholder `builtin-baseline`
      in `vcpkg.json`. Verify the PR opens and merges cleanly.

---

## Architectural decisions log

Append entries here when an irreversible choice is made.

- **2026-05-16** Drop Windows XP / Vista / 7 / 8 support. VS 2026 v145
  ships no XP-targeting toolset; trying to keep it forces a
  side-by-side v141_xp install. The `legacy` branch keeps the old
  build for users who need a pre-modernization snapshot.
- **2026-05-16** Move third-party dependencies to vcpkg manifest mode.
  Removes ~9 vendored libs (some up to 22 years old) and unlocks
  Dependabot automation. Static triplets (`x64-windows-static`) keep
  the distributable shape unchanged.
- **2026-05-16** Use C++20 for first-party, C++17 for legacy plugins.
  Plugins touch DirectShow / Shell extensions where the historical
  binary signatures matter; first-party code can adopt modern
  features (concepts, ranges, `<format>`) without the same churn.
- **2026-05-16** Keep `<ConformanceMode>` (`/permissive-`) **off** in
  Phase 0. The legacy MFC code likely needs warning cleanup before
  `/permissive-` can be required; flipping it on alongside the
  toolset migration would conflate two error modes.
- **2026-05-16** Auto-merge Dependabot **only** for GitHub Actions
  minor/patch updates. Vcpkg baseline bumps can change native lib
  ABI; require human review.
