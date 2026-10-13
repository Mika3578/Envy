# Recommended GitHub Labels

These labels improve triage, risk signaling, and planning.

## Area Labels
- `area: ci`
- `area: protocols`
- `area: security`
- `area: docs`

## Automation Labels (Do Not Remove)
- `dependencies`
- `ci`
- `vcpkg` — Dependabot vcpkg baseline PRs
- `npm` — Dependabot npm PRs for `Remote/tests`
- `github-actions` — Dependabot GitHub Actions PRs
- `major` — major dependency bumps (manual review)

## Risk Labels
- `risk: low`
- `risk: medium`
- `risk: high`

## Needs / Blocker Labels
- `needs: local-vs-build`
- `blocked: toolchain`

## Usage Guidance
- Apply at least one `area:*` and one `risk:*` label to each PR.
- Keep `dependencies`, `ci`, `vcpkg`, `npm`, and `github-actions` available for Dependabot automation.
- Use `blocked:*` only when the blocker prevents meaningful progress.
- Use `needs:*` for explicit human or environment validation needs.
