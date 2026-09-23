# Dependency Automation

**Last Updated:** 2026-09-23

Envy uses automated dependency updates to shorten the time between a newly
published advisory and a reviewed remediation PR. This does not mean dependency
PRs are trusted automatically: normal review, required checks, CodeQL,
Dependency Review, and the live `Protect develop` ruleset still decide whether
a change can merge.

## Ownership

| Area | Owner | Scope |
| --- | --- | --- |
| vcpkg | Dependabot | Root `vcpkg.json` manifest and `builtin-baseline` updates |
| Remote tests npm | Dependabot | `Remote/tests/package.json` and `Remote/tests/package-lock.json` |
| GitHub Actions | Dependabot | Workflows and composite actions under `.github/` |
| PR dependency gate | Dependency Review | Fails pull requests that introduce vulnerable or blocked-license dependencies |
| Code scanning | CodeQL and Gitleaks | Code and secret scanning; not a dependency updater |
| Additional scanners | Evaluated separately | OSV-Scanner, vcpkg SBOM scanning, and zizmor/Scorecard need dedicated measured rollout before becoming required |

Renovate is intentionally inactive. Do not add a second bot for an ecosystem
already owned by Dependabot unless a dedicated PR documents the missing
Dependabot capability and proves that the ownership boundary cannot create
competing PRs.

## Dependabot Policy

Dependabot runs weekly on Monday morning in the `Europe/Paris` timezone.

Non-major updates are grouped per ecosystem to reduce CI noise:

- `vcpkg-baseline` for vcpkg baseline updates.
- `remote-tests-npm` for npm minor and patch updates under `Remote/tests`.
- `github-actions-non-major` for GitHub Actions minor and patch updates.

Major updates remain ungrouped by default and need normal review. Security
updates must not be dismissed or ignored to make the alert count look clean. An
alert is fixed only when the vulnerable version leaves the affected dependency
graph or when a technical non-applicability conclusion is documented.

GitHub Actions remain pinned to full commit SHAs with human-readable version
comments. Dependabot is allowed to update those pinned references; do not replace
them with floating `@main`, `@master`, or mutable `@vN` references.

## Pull Request Gates

Dependency Review runs on every pull request so classifier failures cannot
silently remove the security check. It blocks moderate, high, and critical
vulnerabilities and denies GPL-2.0, GPL-3.0, and AGPL-1.0. Envy's own
AGPL-3.0-or-later license is intentionally allowed.

The repository does not use dependency auto-approval. The previous Dependabot
auto-merge workflow was removed so dependency PR creation is automated, but
merging still requires the live branch protection, required status checks,
thread resolution, and an approved GitHub review.

## vcpkg Baseline

The root `vcpkg.json` is the single source of truth for the official vcpkg
registry baseline. A separate `vcpkg-configuration.json` is only needed when
Envy adds custom registries, overlays, or an explicit non-default registry.

vcpkg can generate SPDX SBOM files during package installation. That is useful
for a future independent C/C++ dependency scan, but making those SBOMs a
required gate should be done in a separate measured PR so it can reuse existing
Windows vcpkg restore and avoid adding unnecessary minutes to every pull
request.

## Independent Scanning

OSV-Scanner is a good candidate for an independent dependency scanner because
the official GitHub Action supports PR, scheduled, and manual scanning with
SARIF output. zizmor is a good candidate for GitHub Actions workflow static
analysis. OpenSSF Scorecard overlaps with several existing checks and can be
noisy for a small Windows-first repository, so it should be evaluated after
zizmor rather than enabled by default.

Any workflow that adds OSV-Scanner, vcpkg SBOM scanning, zizmor, or Scorecard
must use current official documentation, minimal permissions, bounded runtime,
and immutable GitHub Action references.
