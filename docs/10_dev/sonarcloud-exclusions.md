# SonarCloud analysis scope

Canonical exclusions and `sonar.projectVersion` live in
[`.sonarcloud.properties`](../../.sonarcloud.properties) for SonarCloud
Automatic Analysis.

## Why exclude

Envy vendors large third-party trees under `Services/` and some `Plugins/`
paths (see `AGENTS.md` §2 rule 4). Those trees dominate duplicated-line and
issue volume on the New Code period when the leak baseline is broad
(`previous_version`), which made `SonarCloud Code Analysis` fail on `develop`
(#234) even when first-party PR gates were green.

## New Code version marker

Develop uses SonarCloud **Previous version** as the New Code definition.
While `sonar.projectVersion` was unset (`not provided`), a VERSION event from
2026-05 made essentially the entire modernization window New Code (hundreds of
thousands of lines, first-party + vendored). PR Quality Gates stayed green
because they measure only the PR diff.

`.sonarcloud.properties` therefore publishes `sonar.projectVersion` matching
the product version in `Envy/Envy.rc` (`ProductVersion` / `FILEVERSION`
family, currently **4.2.0**).

Two-step reset (do not skip the second step):

1. **Marker analysis** — merge a change that sets or refreshes
   `sonar.projectVersion` so Automatic Analysis records a VERSION event on
   `develop`. That analysis may still fail the gate (New Code still reaches
   back to the prior version).
2. **Post-marker bump** — merge a follow-up that bumps
   `sonar.projectVersion` (patch or build, still aligned with `Envy.rc` when
   the product version changes) so Previous version starts at the marker.
   New Code then covers only post-marker commits; exclusions from this doc
   still apply.

Do **not** change SonarCloud Quality Gate thresholds. Prefer a transparent
version marker (or an admin New Code setting such as a dated reference
analysis) over excluding first-party trees.

## Rules

- Exclude only vendored / template / cloned third-party paths listed in
  `.sonarcloud.properties`.
- Do **not** exclude first-party `Envy/`, `TorrentEnvy/`, `Remote/`, or
  first-party tests to silence ratings.
- Do **not** relax Quality Gate thresholds (duplication ≤ 3%, Reliability /
  Security rating A on New Code) merely to pass.
- Keep `sonar.projectVersion` aligned with the shipped product version
  metadata; bump it when `Envy.rc` / `version.json` change, and use an
  explicit post-marker bump when restoring a leaked Previous-version baseline.
- If New Code baseline/`previous_version` is demonstrably wrong, fix the
  SonarCloud New Code definition (or publish a transparent version marker)
  instead of weakening the gate.

## Related

- Issue #234 — restore green SonarCloud Quality Gate on `develop`
- `docs/10_dev/devsecops-envy.md` — required checks including SonarCloud
