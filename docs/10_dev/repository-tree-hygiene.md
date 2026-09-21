# Repository tree hygiene (live baseline)

Status: active inventory (not a migration plan)
Last verified: 2026-09-21 against `develop` `0f39cd3`
Scope: tracked files only. No directory rename. No Git LFS. No mass delete.

This document is the canonical **tree-hygiene** record. Protocol/status remains
`docs/10_dev/status.md`. Strategic sequence remains `docs/DEVELOPMENT_PLAN.md`.

## Live baseline

| Item | Value |
|------|--------|
| Files | 3344 |
| Directories | 164 |
| Open development PRs at audit | 3 (#298, #299, #303) — under the soft target of 5 |
| Related open issue | [#85](https://github.com/Mika3578/Envy/issues/85) (status/roadmap drift; not this inventory) |
| Overlap | #303 edits contributor/agent policy; do not duplicate that work here |
| Git pack size | ~59 MiB |
| Git LFS | **not** recommended (largest blob `sqlite3.c` ~9.0 MiB; GitHub warn threshold 50 MiB) |

## Top-level size

| Path | Files | Bytes (approx.) | Classification |
|------|------:|----------------:|----------------|
| `Envy/` | 1006 | 11.4 MiB | KEEP |
| `Languages/` | 169 | 16.8 MiB | KEEP — LEGACY (XML + Poedit + committed tools) |
| `Services/` | 324 | 15.3 MiB | KEEP — LEGACY / REPLACE via vcpkg later |
| `Repository/` | 243 | 7.3 MiB | MOVE LATER (name is historical) |
| `Installer/` | 112 | 4.6 MiB | KEEP |
| `Plugins/` | 412 | 3.0 MiB | KEEP — LEGACY |
| `Skins/` | 355 | 2.5 MiB | KEEP |
| `Data/` | 18 | 2.1 MiB | KEEP |
| `Schemas/` | 145 | 1.8 MiB | KEEP |
| `SkinBuilder/` | 79 | 1.4 MiB | KEEP |
| `docs/` | 78 | 0.6 MiB | CONSOLIDATE (this track) |
| others | — | — | KEEP |

Do **not** rename `Envy/`, `Services/`, `Plugins/`, `Repository/`, `Visual Studio/`,
`Languages/`, `Schemas/`, `Skins/`, or `Templates/` in this track.

## Canonical documentation map

| Role | Canonical file | Pointers to keep |
|------|----------------|------------------|
| GitHub contributor entry | `.github/CONTRIBUTING.md` | `docs/CONTRIBUTING.md` |
| Agent policy | `AGENTS.md` | `CLAUDE.md`, `.clinerules`, `.windsurfrules`, `.github/copilot-instructions.md` |
| Strategic sequence | `docs/DEVELOPMENT_PLAN.md` | — |
| Technical roadmap | `docs/10_dev/roadmap.md` | `docs/ROADMAP.md`, `.github/ROADMAP.md` |
| Evidence/status | `docs/10_dev/status.md` | `docs/STATUS.md` |
| ADR table | `docs/DECISIONS.md` | `docs/00_index/DECISIONS.md` (summaries + template) |
| Architecture | `docs/ARCHITECTURE.md` + `docs/20_arch/architecture.md` | numbered tree is the detailed map |
| Docs index | `docs/00_index/README.md` | `docs/00_index/README_old.md` is historical (broken old paths) |
| Tree hygiene | this file | — |

`docs/10_dev/contributing.md` still repeats workflow prose from
`.github/CONTRIBUTING.md`. Trim it in a follow-up that does **not** collide with
#303.

## Confirmed problems (evidence)

1. **Duplicate Current State bullets in `docs/10_dev/roadmap.md`.** Four near-identical
   G1/G2/NMDC lines plus two Build/UI lines (fixed in the documentation hygiene PR).
2. **`.gitignore` extension ignores hide future COM sources.** `git check-ignore --no-index`
   reports `*.idl`, `*.rgs`, `*.def`, `*.exe`, `*.dll`, `*.lib` would ignore new
   untracked files. Already-tracked files remain visible. Directory ignores
   (`x64/`, `Debug/`, `build/`, `vcpkg_installed/`) already work.
3. **Legacy `.vcproj` beside authoritative `.vcxproj`.** 43 `.vcproj`, 45 `.vcxproj`,
   10 `.sln`. `Visual Studio/Envy.sln` references `.vcxproj` only (34 project
   entries). Textual `.vcproj` mentions outside the files themselves:
   `docs/DEVELOPMENT_PLAN.md` (archive later) and `Services/UnRAR/ReadMe.txt`
   (upstream). Exception: `Plugins/PluginWizard/**` templates must stay.
4. **`Plugins/Preview/Preview.sln` still points at `Preview.vcproj`** (VS 2008)
   while `Preview.vcxproj` exists and is not in `Envy.sln`.
5. **Exact duplicate blobs:** 50 groups, ~404 KiB extra. Highest-value source pair:
   `Envy/Envy.idl` ≡ `Plugins/Common/Envy.idl` (plugins MIDL `..\Common\Envy.idl`;
   Envy MIDL `Envy.idl`). FictionBookReader trees share `.csproj` / `AssemblyInfo.cs` /
   `reg.bat`. Do not collapse icons/skins by SHA.
6. **vcpkg vs vendored:** `vcpkg.json` lists zlib, bzip2, sqlite3, miniupnpc, openssl,
   crashpad while `Services/` still vendors zlib/Bzlib/SQLite/MiniUPnP/UnRAR/GeoIP/LibUTP/LibGFL.
   LibUTP is unused by Envy code (`docs/DEPENDENCIES.md`). Replacement needs dedicated PRs.
7. **Protect develop vs older docs:** live ruleset `16457466` on 2026-09-21 still
   has `required_approving_review_count: 0`. `docs/00_index/KNOWN_INCONSISTENCIES.md`
   previously claimed the live target of 1 approval was already matched.

## Safe now vs later

| Action | Risk | PR |
|--------|------|----|
| Deduplicate roadmap Current State; record this inventory; canonical map | Very low | docs hygiene |
| Do not rewrite `.github/CONTRIBUTING.md` while #303 is open | Conflict | wait |
| Tighten `.gitignore` with `git check-ignore` matrix | Low | `chore/tighten-gitignore-rules` |
| Delete unused `.vcproj` after per-file matrix + PluginWizard keep | Low/medium | `chore/remove-unused-legacy-vcproj` |
| Single IDL source of truth | Medium (MIDL include paths) | later |
| vcpkg replace `Services/` | Medium/high | issue #83 |
| Rename historical top-level dirs | High | future only |

## Files safe to remove (this PR)

None of the binary/project files. Documentation: only duplicated *paragraphs*,
not files (redirects stay).

## Not safe to remove

- PluginWizard `.vcproj` / `.vcxproj` templates
- Tracked `.exe`/`.dll`/`.lib` under Installer, Languages/Tools, Services/LibGFL, Plugins
- Skin/schema/resource SHA duplicates
- `Preview.vcproj` until `Preview.sln` is retargeted or retired
- `TextViewer` (has `.vcxproj` but is not in `Envy.sln` — UNKNOWN consumer path)
- `Services/LibUTP` until BitTorrent uTP (#88)

## Long-term tree (direction only)

CURRENT: historical MFC layout + `tests/` + `tools/` + `scripts/` + numbered `docs/`.

NEAR-TERM: keep paths; new portable code may land under a dedicated `EnvyCore`
(or similar) **when that work exists**.

FUTURE: `src/core` + `app/windows` + `third_party` + `packaging` as described in
the modernization plan — only after real extraction (#161), never as an empty
rename of `Envy/`.
