# Repository Labels

This documents the live label inventory (verified 2026-11-26 against the
Labels API). The declarative source is `.github/settings.yml` (`labels:`),
which mirrors the live inventory so a Probot Settings apply is a no-op.
Do not add labels here that neither file declares and no automation consumes.

## Automation consumers

| Label(s) | Consumer |
| --- | --- |
| `build`, `ci`, `core`, `bittorrent`, `plugins`, `installer`, `translations`, `skins`, `third-party`, `documentation`, `dependencies`, `npm`, `vcpkg`, `github-actions` | `.github/labeler.yml` (changed-file detection on PRs) |
| `stage:live-test` | `.github/scripts/pr-phase.py` and `.github/workflows/build.yml` — switches a PR from the cheap Draft lane onto full x64 + Win32 Release builds and EnvyTests |
| `priority: P0` / `P1` / `P2` | Manual triage (P0 blocks Preview 1 / security / crash; P1 important soon after; P2 later) |
| `stale` | `.github/workflows/stale.yml` |
| `renovate`, `codex`, `Amazon Q development agent` | Legacy / bot-applied markers; keep for historical filtering |

## PR lifecycle: `stage:live-test`

Maintainer-only. Agents must not apply it (PR workflow in `AGENTS.md`);
it is the switch the maintainer uses to run real Windows validation on a
stabilized PR before marking it Ready.

## Not currently defined

The following labels were previously recommended but do not exist in the
repository and no automation reads them: `risk: low|medium|high`,
`needs: local-vs-build`, `blocked: toolchain`, `area: ci`, `area: protocols`,
`area: security`, `area: docs`, `work-in-progress`, `blocked`,
`ready-for-review`, `needs-triage`, `breaking-change`. If one is needed,
add it to `.github/settings.yml` first (with a color and description), then
reference it here.
