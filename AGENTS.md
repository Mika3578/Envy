# AGENTS.md - Rules for AI coding assistants on the Envy repository

Single source of truth for GitHub Copilot, Claude Code, Cursor, Cline, Aider,
Windsurf, Continue, and similar tools. Tool-specific config files are thin
pointers to this document.

Keep this file concise. Durable details belong in `MODERNIZATION.md`, `docs/`,
or linked guides — link here, do not duplicate.

---

## 1. Project overview

Envy is a multi-network peer-to-peer client for Windows.

- **C++** (MFC + ATL) — ~677 `.cpp` / 709 `.h` files
- **MSBuild** — 46 `.vcxproj` projects under `Visual Studio/Envy.sln`
- **Toolchain** — Visual Studio 2026, toolset **v145**, MSVC 14.50;
  C++20 first-party, C++17 legacy plugins
- **OS target** — Windows 10 1809+ (XP/Vista/7/8 dropped)
- **Dependencies** — vcpkg manifest (`vcpkg.json`)
- **License** — AGPL-3.0-or-later (`Envy/AGPL-License.txt`)

Branch model: **`develop`** is the default integration branch (linear history).
Create work branches from **`origin/develop`**. Never push directly to
`develop`, `main`, or `legacy`. Land changes through PRs to `develop`.

---

## 2. Hard rules

1. **Language** — English for all repository artifacts (code, comments,
   commits, PRs, issues, docs). Chat replies may follow the user's language.
2. **No XP support** — Do not reintroduce `_ATL_XP_TARGETING`, `v141_xp`,
   `XPSUPPORT`, or `_WIN32_WINNT < 0x0A00`.
3. **No edits under `Plugins/PluginWizard/**`** — VS project templates.
4. **Third-party trees are read-only** unless deliberately upgrading via vcpkg:
   `Services/{zlib,SQLite,Bzlib,UnRAR,MiniUPnP,GeoIP,LibUTP,BugTrap}`,
   `Plugins/{RatDVDPlugin,SWFPlugin}`, `HashLib/HashLib/*`.
5. **No bulk reformat** — `.clang-format` is advisory.
6. **No `using namespace std;`** at file scope. Prefer `CString`, `CAtlList`,
   `CMap` over `std::` containers in MFC code.
7. **`noexcept`, not `throw()`** — removed in C++20.
8. **No `register` keyword** — removed in C++17.
9. **No GPL-2.0 or GPL-3.0 dependencies** — AGPL-3.0 is fine.
10. **Never skip git hooks** (`--no-verify`, `--no-gpg-sign`) or force-push
    to `main`/`develop`. Create new commits; do not amend pushed commits.
11. **Branch naming** — `type/short-kebab-summary` off `develop`
    (`feat/`, `fix/`, `docs/`, `chore/`, `ci/`, …). Never use tool- or
    agent-prefixed names (`claude/`, `cursor/`, `codex/`, `agent/`, …).
12. **Merge gate** — May create branches, commit, push, and open **draft** PRs.
    Do not mark ready-for-review, enable auto-merge, or merge without explicit
    maintainer approval.
13. **No AI attribution** — Do not add `Co-authored-by`, Cursor, Copilot,
    Claude, or similar trailers to commits or PRs unless the user explicitly
    requests them.
14. **No secrets or local paths** — Do not commit credentials, tokens, or
    machine-specific absolute paths.

---

## 3. Build and test

```cmd
msbuild "Visual Studio\Envy.sln" /m /p:Configuration=Release /p:Platform=x64 ^
  /p:PlatformToolset=v145 /p:WindowsTargetPlatformVersion=10.0 ^
  /p:VcpkgEnableManifest=true /p:VcpkgTriplet=x64-windows-static
```

CI mirrors this — see `.github/workflows/build.yml`.

HashLib tests:

```cmd
msbuild HashLib\HashTest\HashTest.vcxproj /p:Configuration=Release /p:Platform=x64
.\HashLib\HashTest\x64\Release\HashTest.exe
```

**Build authority:** `Visual Studio/Envy.sln` is authoritative. CMake files
are auxiliary until Phase 5 migration completes. Do not modify the solution
solely to satisfy CMake, or add CMake changes outside a PR dedicated to CMake.

---

## 4. Code conventions

Match the surrounding MFC style:

- Tabs, width 4; Allman braces
- Naming: `m_` members; `m_s` strings; `p`, `n`, `b`, `dw`, `lp` locals
- `#include "StdAfx.h"` first in every `.cpp`
- `CString` in MFC code; `CCriticalSection` / `CSingleLock` for concurrency
- Comments explain **why**, not **what**; keep existing copyright blocks

---

## 5. Git, PRs, and work tracking

### Shared tracking (canonical)

Use GitHub for shared work state:

- **Issues** — actionable bugs, features, and tasks
- **Projects** — backlog, status, and prioritization
- **Milestones** — release scope
- **Pull Requests** — implementation, review, and validation
- **Discussions** — exploratory proposals when appropriate

Do not create committed Markdown trackers for session work or duplicate GitHub
status in versioned docs.

### Local workspace (gitignored)

Volatile material stays local:

| Path | Purpose |
| --- | --- |
| `.local/` | Session notes, personal backlogs, prompts, audits, research drafts |
| `references/` | Local clones or extracts of external P2P clients for comparison |
| `.envy.local.*` | Local environment overrides |

Do not commit contents of these paths. Do not edit third-party trees under
`references/` as if they were part of this repository.

### PR expectations

- Push only to your feature branch (`git push -u origin <branch>`).
- Open a draft PR using `.github/pull_request_template.md`.
- Keep PRs small and focused; tick template checkboxes that genuinely apply.
- Cite code as `path/file.cpp:line` in chat when discussing implementation.

---

## 6. Documentation policy

### Version in Git (durable knowledge)

Architecture, build/setup, protocols, conventions, security policy, release
procedure, contribution workflow, stable modernization decisions, ADRs
(`docs/DECISIONS.md`), and documentation required to understand delivered
behavior.

### Do not commit as normal repository documentation

Daily task lists, personal backlogs, session trackers, agent scratchpads,
temporary implementation plans, prompt collections, exploratory notes,
unvalidated research, intermediate audit reports, external source trees,
local reference repositories, or duplicated GitHub Issue/Project status.

### When to update committed docs

Only when a change affects durable documented behavior, setup, architecture,
security, compatibility, or release procedures. User-visible changes belong in
`CHANGELOG.md` under `[Unreleased]`. No mandatory tracker update at task
start or end.

---

## 7. Repository map

| Path | What's there |
| --- | --- |
| `Envy/` | Main MFC application (UI, networking, DB, search) |
| `TorrentEnvy/` | BitTorrent-only standalone variant |
| `HashLib/` | First-party hashing (Tiger, ED2K, SHA1, MD4) |
| `Unpacker/` | Archive extraction harness |
| `SkinBuilder/` | Skin authoring tool |
| `Installer/` | Inno Setup scripts (`.iss`) |
| `Plugins/` | 24 plugins |
| `Services/` | Vendored third-party libs (moving to vcpkg) |
| `Languages/` | 62 XML translation files |
| `Skins/`, `Data/` | Runtime resources — do not delete |
| `Visual Studio/` | `Envy.sln`, retarget scripts |
| `docs/` | Architecture, protocols, setup, quality docs |

---

## 8. Specific don'ts

- Do not add `#pragma warning(disable: ...)` to silence new warnings.
- Do not add vcpkg dependencies without an architectural decision recorded in
  `docs/DECISIONS.md` or a GitHub issue.
- Do not expand CMake beyond its auxiliary role.
- Do not rewrite `MODERNIZATION.md` from scratch.
- Do not translate files in `Languages/` unless fluent in the target language.
- Do not hand-edit vendored third-party files to suppress warnings — fix
  upstream, add per-project `/wd`, or leave the warning.
- Cluster mechanical edits via a script; do not hand-edit dozens of files.

---

## 9. Escalation

If blocked:

1. Open or update a GitHub issue (use the `build_failure.yml` template for
   build errors).
2. Record consequential architectural decisions in `docs/DECISIONS.md`.
3. Stop — do not invent silent workarounds (`/* TODO */`, dummy returns).

---

## 10. Tool pointers

Change rules here; keep pointers thin:

- `.github/copilot-instructions.md`
- `.cursorrules` and `.cursor/rules/*.mdc`
- `.clinerules`, `.windsurfrules`, `.aider.conf.yml`
- `CLAUDE.md`, `.continue/rules/*.md`

See also: `MODERNIZATION.md`, `.github/CONTRIBUTING.md`, `docs/PR_PLAYBOOK.md`.
