# Dependency Automation

**Last Updated:** 2026-09-29

Envy uses automated dependency updates to shorten the time between a newly
published advisory and a reviewed remediation PR. This does not mean dependency
PRs are trusted automatically: normal review, required checks, CodeQL,
Dependency Review, and the live `Protect develop` ruleset still decide whether
a change can merge.

## Ownership

This table matches the live automation config and `MODERNIZATION.md` §3
(dependency inventory). Removed artifacts such as `vcpkg-configuration.json` and
`.github/workflows/dependabot-auto-merge.yml` are retired; do not document them
as active.

| Area | Owner | Scope |
| --- | --- | --- |
| vcpkg | Dependabot | Root `vcpkg.json` manifest and `builtin-baseline` updates |
| `Remote/tests` npm | Dependabot | Directory `/Remote/tests` (group `remote-tests-npm`) |
| GitHub Actions | Dependabot | Workflows and composite actions under `.github/` (group `github-actions-non-major`) |
| PR dependency gate | Dependency Review | Workflow job `Dependency review` fails moderate+ vulnerabilities and blocked licenses; merge blocking requires it in Protect develop |
| Code scanning | CodeQL and Gitleaks | Code and secret scanning; not a dependency updater |
| Additional scanners | Evaluated separately | OSV-Scanner, vcpkg SBOM scanning, and zizmor/Scorecard need dedicated measured rollout before becoming required |

Dependabot owns vcpkg, `Remote/tests` npm, and GitHub Actions. Do not reintroduce
Renovate (or a second bot) for an ecosystem already listed in `.github/dependabot.yml`
unless a dedicated PR documents the missing capability and proves non-overlapping ownership.

## Dependabot Policy

Dependabot runs weekly on Monday morning in the `Europe/Paris` timezone.

Non-major updates are grouped per ecosystem to reduce CI noise:

- `vcpkg-baseline` for vcpkg baseline updates.
- `github-actions-non-major` for GitHub Actions minor and patch updates.
- `remote-tests-npm` for `Remote/tests` npm minor and patch updates.

Major updates remain ungrouped by default and need normal review. Security
updates must not be dismissed or ignored to make the alert count look clean. An
alert is fixed only when the vulnerable version leaves the affected dependency
graph or when a technical non-applicability conclusion is documented.

GitHub Actions remain pinned to full commit SHAs with human-readable version
comments. Dependabot is allowed to update those pinned references; do not replace
them with floating `@main`, `@master`, or mutable `@vN` references.

## Pull Request Gates

Dependency Review runs on every pull request targeting `main`, `master`, or `develop` (independent of change
classification) so a classifier outage cannot silently skip the check. The
workflow uses `fail-on-severity: moderate`, denies GPL-2.0, GPL-3.0, and
AGPL-1.0, and allows Envy's own AGPL-3.0-or-later license. A finding fails
the `Dependency review` job; it blocks merge only when that exact context is
present on the live **Protect develop** ruleset (tracked in
`.github/settings.yml` alongside the other required checks).

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
