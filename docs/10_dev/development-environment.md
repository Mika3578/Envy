# Development environment (authoritative)

**Last updated:** September 2026

This document is the single source of truth for how to set up a Windows
development machine for Envy, which repository files define editor/build
policy, and what must stay local. Agent workflow rules live in [`AGENTS.md`](../../AGENTS.md); build commands are detailed in [build.md](build.md).

## Configuration hierarchy

| Layer | Owns |
| --- | --- |
| [`AGENTS.md`](../../AGENTS.md) | Mandatory assistant/contributor workflow |
| [`.editorconfig`](../../.editorconfig) | Portable editor conventions per file type |
| [`.gitattributes`](../../.gitattributes) | Git binary/text rules (minimal; no legacy C++ charset) |
| [`.clang-format`](../../.clang-format) / CI | Mechanical C++ formatting on changed hunks |
| [`.vscode/settings.json`](../../.vscode/settings.json) | Small portable VS Code/Cursor workspace safety defaults |
| [`.vscode/extensions.json`](../../.vscode/extensions.json) | Recommended extensions only |
| This document | Human setup, encoding warnings, troubleshooting |
| [`tools/dev/`](../../tools/dev/) | Windows bootstrap and `compile_commands.json` generation |
| GitHub Actions | Enforcement (format, encoding guard, security scans) |

Do not commit machine-specific paths, generated compilation databases, or personal UI/AI settings.

## Fresh clone (Windows)

```powershell
git clone https://github.com/Mika3578/Envy.git
cd Envy
.\tools\dev\setup-windows.ps1 -Check
scripts\bootstrap-vcpkg.cmd
```

Open `Visual Studio\Envy.sln` in **Visual Studio 2026** (toolset **v145**, Windows 10 SDK **10.0**). Build **Release \| x64** (or Debug) at least once before generating clangd data.

Authoritative MSBuild command (see [build.md](build.md)):

```cmd
msbuild "Visual Studio\Envy.sln" /m /p:Configuration=Release /p:Platform=x64 ^
  /p:PlatformToolset=v145 /p:WindowsTargetPlatformVersion=10.0 ^
  /p:VcpkgEnableManifest=true /p:VcpkgTriplet=x64-windows-static
```

## Visual Studio

- **Build and debug:** Visual Studio remains the authoritative MSVC environment.
- **Do not commit:** `.vs/`, `*.user`, `*.suo`, per-user options.
- **vcpkg:** `vcpkg_installed/` is gitignored; restore via `scripts\bootstrap-vcpkg.cmd`.

## Cursor / VS Code

The repository versions a **minimal** `.vscode/` policy:

- `files.autoSave`: off (avoid silent saves on legacy encodings)
- `editor.formatOnSave`: false (formatting is clang-format / CI on changed hunks)
- `editorconfig.enable`: true (with a safe `.editorconfig`; see encoding below)

Recommended extensions (see `.vscode/extensions.json`):

- **EditorConfig** — applies repository editor rules
- **clangd** — C++ navigation when `compile_commands.json` exists

Use **one** C++ language service: prefer **clangd** for IntelliSense/navigation. Disable duplicate MSVC IntelliSense in personal settings if both are active. The repo lists `ms-vscode.cpptools` under `unwantedRecommendations` only to reduce accidental dual-IntelliSense installs; you may still install it for MSVC debugging if your workflow needs it.

### clangd and `compile_commands.json`

`compile_commands.json` at the repository root is **generated** and **gitignored**. After a successful VS/MSBuild build:

```powershell
.\tools\dev\setup-windows.ps1 -GenerateCompileCommands
# or
.\tools\dev\generate-compile-commands.ps1 -Configuration 'Release|x64'
```

clangd needs MSVC as the query driver. Set this in **personal** (gitignored) settings or user settings, not in the repo — paths vary by machine:

```json
"clangd.arguments": [
  "--compile-commands-dir=${workspaceFolder}",
  "--query-driver=**/cl.exe"
]
```

Install LLVM **clangd** via the clangd extension or a system LLVM build.

## Source encoding (#350)

Tracked in [issue #350](https://github.com/Mika3578/Envy/issues/350).

**Current tree (first-party `Envy/`, `HashLib/`, `TorrentEnvy/`, `Unpacker/`, `SkinBuilder/`, ~1006 files audited on develop):**

- ~770 files are **not** valid UTF-8 (historical single-byte header/comments)
- ~74 files already contain **U+FFFD** (`EF BF BD`) in the committed blob
- ~236 files are valid UTF-8 without new replacement debt

**Rules:**

- Do **not** mass-convert encodings or declare all C++ CP1252/Latin-1 globally.
- `.editorconfig` does **not** set `charset = utf-8` on legacy C/C++; it uses `charset = unset` for `*.cpp`/`*.h` and UTF-8 only where content is genuinely UTF-8 (YAML, JSON, XML, docs, scripts).
- Prefer **Visual Studio** to edit/save legacy sources until a file is explicitly migrated under #350.
- CI runs [`.github/scripts/check-source-encoding.sh`](../../.github/scripts/check-source-encoding.sh): it **fails only when a PR increases** `EF BF BD` counts in changed first-party C/C++ files (baseline debt on `develop` is allowed).

**Before you finish a change**, inspect files you **actually modified** (not merely opened) for unintended encoding conversion, new `U+FFFD`, EOL-only churn, secrets, or local paths.

## Project-owned vs local

| Versioned | Local / gitignored |
| --- | --- |
| `.editorconfig`, `.gitattributes` | Personal VS/Cursor user settings |
| `.vscode/settings.json`, `extensions.json` | Other `.vscode/*` files |
| `tools/dev/*.ps1` | `compile_commands.json` |
| CI scripts | `vcpkg_installed/`, build outputs, `.vs/` |

## Verification

```powershell
.\tools\dev\setup-windows.ps1 -Check
```

On Linux CI, encoding self-test: `bash .github/scripts/check-source-encoding.selftest.sh`

## Security

Secret scanning and gitleaks run in existing workflows (see `.github/workflows/security.yml`). This document does not duplicate those controls.

## Troubleshooting

| Symptom | Likely cause | Action |
| --- | --- | --- |
| Unicode replacement character (U+FFFD) or mojibake in copyright line after save | UTF-8 forced on legacy bytes | Restore from git; edit in VS; see #350 |
| clangd no compile flags | Missing `compile_commands.json` | Build in VS, run `generate-compile-commands.ps1` |
| Format CI fails | Changed hunk not clang-format clean | Format **modified lines only** |
| Encoding CI fails | New `EF BF BD` in diff | Revert corruption; do not commit replacement bytes |

## Related

- [build.md](build.md) — MSBuild, vcpkg, CI parity
- [standards.md](standards.md) — C++ style and tooling overview
- [contributing.md](contributing.md) — PR process
