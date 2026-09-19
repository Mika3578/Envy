# SonarCloud analysis scope

Canonical exclusions live in [`.sonarcloud.properties`](../../.sonarcloud.properties)
for SonarCloud Automatic Analysis.

## Why exclude

Envy vendors large third-party trees under `Services/` and some `Plugins/`
paths (see `AGENTS.md` §2 rule 4). Those trees dominate duplicated-line and
issue volume on the New Code period when the leak baseline is broad
(`previous_version`), which made `SonarCloud Code Analysis` fail on `develop`
(#234) even when first-party PR gates were green.

## Rules

- Exclude only vendored / template / cloned third-party paths listed in
  `.sonarcloud.properties`.
- Do **not** exclude first-party `Envy/`, `TorrentEnvy/`, `Remote/`, or
  first-party tests to silence ratings.
- Do **not** relax Quality Gate thresholds (duplication ≤ 3%, Reliability /
  Security rating A on New Code) merely to pass.
- If New Code baseline/`previous_version` is demonstrably wrong, fix the
  SonarCloud New Code definition (or publish a transparent version marker)
  instead of weakening the gate.

## Related

- Issue #234 — restore green SonarCloud Quality Gate on `develop`
- PR #253 / #160 — interop isolation `python:S5443` (world-writable `Path("/tmp")` denylist literals) is fixed by path-component matching, not by excluding `tools/interop/`
- `docs/10_dev/devsecops-envy.md` — required checks including SonarCloud
