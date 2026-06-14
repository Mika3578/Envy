# Envy Development Tracker

_Last updated: 2026-06-14_

Operational dashboard for day-to-day work. Strategic scope lives in
[`docs/DEVELOPMENT_PLAN.md`](DEVELOPMENT_PLAN.md); technical sequencing in
[`MODERNIZATION.md`](../MODERNIZATION.md).

## Repository baseline

| Item | Value |
|---|---|
| Default branch | `develop` |
| Authoritative build | `Visual Studio/Envy.sln` |
| Toolset | `v145` (Visual Studio 2026 / MSVC 14.50) |
| Dependencies | vcpkg manifest (`vcpkg.json`) |

## Pull request status

| PR | State | Notes |
|---|---|---|
| #51 | Merged | vcpkg baseline group bump (Dependabot) |
| #48 | Closed | Superseded — CI changes will land as smaller PRs |
| #55 | Closed | Superseded — governance/docs changes will land as smaller PRs |

## Done (merged on `develop`)

- **2026-06-14** — `docs/align-development-rules` @ `b423c07` — aligned branch
  naming, merge gates, and build-authority rules in `AGENTS.md`, `CLAUDE.md`,
  and governance pointer files (draft PR opened; not merged in this pass).
- **#35** — Visual Studio 2026 (`v145`) toolset migration, CI infrastructure,
  AI rules (`AGENTS.md` and tool pointers).
- **#43** — Lazy-load default skin; silence startup toolbar/icon debug noise.
- **#44** — ED2K protocol parser smoke tests (Source Exchange).
- **#46** — Reduce PR check warnings on hosted runners.
- **#47** — Align `release.yml` on `build.yml` safety guards.
- **#50** — Document linear history workflow.
- **#51** — Bump vcpkg baseline group (2 updates).

## In progress

_(none)_

## Next

1. **CI: PR Quick Checks** — Extract from superseded #48; fast validation
   workflow separate from full build matrix.
2. **CI: Full pipeline triggers** — Extract from superseded #48; narrow
   trigger and policy changes only.
3. **CI: vcpkg workspace/cache** — Extract from superseded #48.
4. **CI: build logs and artifacts** — Extract from superseded #48.
5. **Docs: agent and branch governance** — Extract from superseded #55.
6. **Docs: roadmap and PR template cleanup** — Extract from superseded #55.
7. **Build: dependency ownership pass** — Seed owners and update cadence in
   `docs/DEPENDENCIES.md`.
8. **Tests: protocol parser smoke coverage** — Expand high-risk packet paths
   beyond ED2K.

## Blockers

_(none)_
