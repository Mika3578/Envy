# Contributing to Envy

Thanks for your interest in improving Envy. This file describes the
ground rules for contributing code, translations, skins, or docs.

## License agreement

Envy is licensed under **AGPL-3.0-or-later**. Some visual resources and
the `LibGFL` library carry additional CC-BY-NC-SA terms (see `ReadMe.txt`).
By submitting a pull request you confirm that your contribution can be
distributed under those terms.

## Quick start

1. Install **Visual Studio 2026 v18.0+** (Community is fine) with:
   - Workload "Desktop development with C++"
   - Components "MFC for v145", "ATL for v145", "C++ Spectre-mitigated libs (v145)"
   - "C++ CMake tools for Windows"
   - "Windows 10/11 SDK (latest)"
2. Clone, bootstrap vcpkg **and restore the root manifest** (Crashpad):
   ```
   git clone https://github.com/mika3578/envy.git
   cd envy
   git clone https://github.com/microsoft/vcpkg.git
   .\vcpkg\bootstrap-vcpkg.bat -disableMetrics
   .\scripts\bootstrap-vcpkg.cmd
   ```
   `bootstrap-vcpkg.cmd` is the local equivalent of CI’s
   `vcpkg install --triplet=…` step (default `x64-windows-static`). For Win32
   use `-Triplet x86-windows-static`; for both platforms / `build_all.ps1` use
   `-All`. Visual Studio does **not** restore `vcpkg_installed\` before
   `PreBuildEvent`. See `docs/10_dev/build.md`.
3. Open `Visual Studio\Envy.sln` and build (Ctrl+Shift+B).

If you migrated from VS 2017/2019: run `Visual Studio\SetVS2026.bat` once
to retarget every project to v145.

## Branch model

- `main` - stable, releases tagged `v*` from here.
- `develop` - integration branch (default).
- `legacy` - frozen pre-modernization snapshot for historical builds.
- Feature branches: `type/short-kebab-summary` only (`feat/`, `fix/`,
  `docs/`, `ci/`, …). See `AGENTS.md` hard rule 11. **Never** tool/agent
  prefixes (`claude/`, `cursor/`, `copilot/`, …) — including AI/Cloud Agent
  runs.

## Git workflow (linear history)

`develop` keeps a **linear history** with no merge commits. Keep local pulls
fast-forward-only and rebase feature branches before opening or updating PRs.

### Repository merge settings (GitHub)

- Merge commits: **disabled**
- Squash merge: **enabled** (required path onto `develop`)
- Squash merge title: **PR title** (target in `.github/settings.yml`; confirm live GitHub settings)
- Squash merge body: **blank** by default (no agent trailers or bot summaries on `develop`)
- Rebase merge: **enabled globally**, but **prohibited** when merging into
  `develop` by the Protect develop ruleset (squash-only)
- Require linear history on `develop`: **enabled** via the active `Protect develop` ruleset
- Force pushes and branch deletions on `develop`: **blocked**

### Local settings

Configure fast-forward-only pulls so a plain `git pull` never creates merge
commits:

```bash
git config pull.ff only
```

This configures fast-forward-only pulls for this local clone. To apply
it globally across all your repositories instead, run
`git config --global pull.ff only`.

### Sync `develop` locally

```bash
git fetch origin
git checkout develop
git pull --ff-only origin develop
```

If `git pull --ff-only` fails, your local `develop` has diverged. Reset it
to the remote (**ensure your working tree is clean first — `git reset --hard`
discards all uncommitted changes**; stash or commit any work in progress):

```bash
git fetch origin
git checkout develop
git reset --hard origin/develop
```

Never commit directly on `develop`; always use a feature branch and PR.

## Authorship, privacy, and comments

See `AGENTS.md` hard rule 16. In short: no assistant `Co-authored-by`, no
`Generated with` signatures in commits or contributor PR text, no personal
emails in repository content, technical PR titles (`type(scope): …`), and
source comments that explain the software—not the review process. Bot
comments and auto-generated PR summaries on GitHub are fine.

```bash
./scripts/configure-git-noreply.sh
git config user.useConfigOnly true
```

Review lifecycle / final Copilot orchestration is tracked separately (for
example PR #349), not in authorship hygiene PRs.

### Feature branch workflow (before opening or updating a PR)

```bash
git fetch origin
git checkout your-feature-branch
git rebase origin/develop
git push --force-with-lease
```

Use `--force-with-lease`, not `--force`, so you do not overwrite someone
else's pushed work.

### Protected branch policy (`Protect develop`)

Before a pull request can merge into `develop`, **all** of the following must
hold (enforced by the live GitHub ruleset, not by CI alone):

1. The PR is **not a draft**.
2. **At least one** GitHub review with state **APPROVED** from a reviewer other
   than the PR author. In this solo-maintainer repository, GitHub Copilot Code
   Review may satisfy this requirement only when repository settings allow
   Copilot to approve **and** count toward merge requirements, any path
   allowlist matches every changed file, and GitHub records an actual
   `APPROVED` review. CodeRabbit/advisory comments and Copilot's approval
   assessment alone do not satisfy the gate.
3. That approval remains valid for the **current** head: stale approvals are
   **dismissed on new pushes**. `Require approval of the most recent
   reviewable push` is **off** (intentional for the solo-maintainer +
   final-reviewer workflow).
4. **All review conversations / threads are resolved**.
5. There is no outstanding **CHANGES_REQUESTED** review.
6. All **required status checks** are green and the branch is **up to date**
   with `develop` (strict checks).
7. Merge method on `develop` is **squash** only; history stays **linear**;
   commits must be **signed**; force pushes are blocked.
8. **No bypass actors** — do not use admin merge, `--admin`, or a PAT to
   override the ruleset.

The declarative template in `.github/settings.yml` mirrors the Probot-capable
subset of this policy. Ruleset-only knobs (thread resolution, squash-only on
`develop`, signed commits, code scanning, block force pushes) are documented
there and must match the live ruleset. Global `allow_rebase_merge` may stay
enabled for other branches; Protect develop still forces squash-only.

## Pull request checklist

- [ ] Builds Release x64 and Release Win32 with toolset v145.
- [ ] No new compiler warnings (use the CI build log).
- [ ] CodeQL passes without new HIGH/CRITICAL findings.
- [ ] At least one GitHub **APPROVED** review from a reviewer other than the
      PR author (Copilot may count when enabled); all review threads resolved.
- [ ] If you touched anything in `Services/` or `Plugins/`, ping a
      CODEOWNER for review.
- [ ] If you bumped a vcpkg dependency, note the version delta in the
      PR description.
- [ ] Translations stay in sync with the keys in `Envy.exe`
      (run `Languages\Tools\extract.bat`).

## Coding style

The codebase predates modern C++ conventions; please match the surrounding
code rather than introducing a new style island:

- Tabs for indentation, width 4.
- Allman braces (`{` on its own line).
- Hungarian-ish notation (`m_`, `p`, `n`, `b`, `str`).
- Prefer `CString` / `CAtlList` over `std::string` / `std::list` inside MFC code.
- Use `noexcept`, not `throw()`.
- Avoid `using namespace std;` at file scope.
- New code SHOULD compile with `/std:c++20`; legacy plugins may stay on
  `/std:c++17`.

`.clang-format` is provided for advisory checks. It is intentionally
conservative - do not bulk-reformat existing files.

## Reporting bugs

Use the bug report issue template. If ENVY created a crash report, copy the
sanitized `.txt` from `%LOCALAPPDATA%\Envy\CrashReports\`. Attach the `.dmp`
only if you choose to share it (minidumps can contain private memory).
See `docs/50_user/crash-reports.md`.

## Security

See `.github/SECURITY.md`. Never open public issues for security bugs.
