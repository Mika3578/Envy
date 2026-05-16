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

_(none right now)_

---

## Blockers

_(none right now)_

---

## Done

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

- **2026-05-16** | claude/code-audit-modernization-nJcTT | _(this commit)_
  -> Translate `MODERNIZATION.md` to English, add AI rules
  - `AGENTS.md` (canonical AI ruleset)
  - `CLAUDE.md`, `.cursorrules`, `.cursor/rules/envy.mdc`,
    `.clinerules`, `.aider.conf.yml`, `.windsurfrules`,
    `.continue/rules/envy.md`,
    `.github/copilot-instructions.md`
  - `DEV_TRACKER.md` (this file)

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
