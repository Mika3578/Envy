# Envy Documentation

**Quick links:** [Status](../10_dev/status.md) · [Roadmap](../10_dev/roadmap.md) · [References](../30_protocols/REFERENCE_IMPLEMENTATIONS.md) · [Build](../10_dev/build.md)

## Start here
| Doc | Purpose |
|-----|---------|
| [DEVELOPMENT_PLAN](../DEVELOPMENT_PLAN.md) | Strategic roadmap (canonical) |
| [DECISIONS](../DECISIONS.md) | ADR-lite decisions (single register) |
| [.github/CONTRIBUTING](../../.github/CONTRIBUTING.md) | How to contribute |

## Map

| Section | Location | Notes |
|---------|----------|-------|
| **User** | `docs/50_user/` | Guide, installation, configuration, [crash reports](../50_user/crash-reports.md), [transfer settings](../50_user/transfer-settings.md), [settings reference](../50_user/reference/COMPLETE_SETTINGS_REFERENCE.md) |
| **Developer** | `docs/10_dev/` | [Build](../10_dev/build.md), [guide](../10_dev/guide.md), [standards](../10_dev/standards.md), [status](../10_dev/status.md), [roadmap](../10_dev/roadmap.md), [crash reporting](../10_dev/crash-reporting.md), [DevSecOps map](../10_dev/devsecops-envy.md) |
| **Architecture** | [architecture](../20_arch/architecture.md) · [PORTABILITY_PLAN](../20_arch/PORTABILITY_PLAN.md) · [UI modernization](../20_arch/UI_MODERNIZATION.md) · [remote API](../20_arch/remote-api.md) | System design, portability, MFC UI plan, automation API |
| **Protocols** | `docs/30_protocols/` | [ED2K](../30_protocols/ed2k/README.md), [Kad](../30_protocols/kad/README.md) ([kad2 compatibility report](../30_protocols/kad/kad2-compatibility-report.md)), [BitTorrent](../30_protocols/bittorrent/README.md), [bootstrap sources](../30_protocols/bootstrap-sources.md), [reference implementations](../30_protocols/REFERENCE_IMPLEMENTATIONS.md) |
| **Quality** | `docs/40_quality/` | Security, performance, testing; [CI/CD audit 2026-09](../10_dev/CI_AUDIT_2026-09.md) |
| **Remote** | `Remote/` | [README](../../Remote/README.md), [API specification](../../Remote/api-specification.md), [testing guide](../../Remote/testing-guide.md) |

## Root compatibility pointers

These short files under `docs/` preserve old links; prefer the numbered targets:

| Pointer | Canonical target |
|---------|------------------|
| [`docs/ROADMAP.md`](../ROADMAP.md) | [`10_dev/roadmap.md`](../10_dev/roadmap.md) |
| [`docs/STATUS.md`](../STATUS.md) | [`10_dev/status.md`](../10_dev/status.md) |
| [`docs/KAD2_COMPATIBILITY_REPORT.md`](../KAD2_COMPATIBILITY_REPORT.md) | [`30_protocols/kad/kad2-compatibility-report.md`](../30_protocols/kad/kad2-compatibility-report.md) |
| [`docs/CONTRIBUTING.md`](../CONTRIBUTING.md) | [`.github/CONTRIBUTING.md`](../../.github/CONTRIBUTING.md) |

## Historical archives

| Archive | Notes |
|---------|-------|
| [`10_dev/archive/roadmap-product-2024-2025.md`](../10_dev/archive/roadmap-product-2024-2025.md) | 2024–2025 product roadmap sketch; IPv6 claims superseded by status matrix |
| [`10_dev/archive/upgrade-summary-2024-11.md`](../10_dev/archive/upgrade-summary-2024-11.md) | November 2024 modernization snapshot |
| [`10_dev/archive/decision-log-2026.md`](../10_dev/archive/decision-log-2026.md) | Chronological working decision log (folded into `docs/DECISIONS.md`) |
| [`10_dev/archive/development-plan-journal-2026.md`](../10_dev/archive/development-plan-journal-2026.md) | Per-PR journal formerly appended to `DEVELOPMENT_PLAN.md` |

## Documentation conventions

Write for one of four needs (Diátaxis): **tutorial** (learning), **how-to**
(task), **reference** (facts), **explanation** (why/design). One canonical
location per topic; extend an existing doc instead of creating a near-duplicate.

- Developer docs start with `Status`, `Last updated`, `Scope` and
  `Source of truth` lines; update `Last updated` on substantive edits.
  The authoritative checklist lives in `.cursor/rules/07-documentation.mdc`.
- Protocol docs include: packet layout, bounds/caps, unknown-field strategy,
  and a "When it breaks" section with example log patterns; link to
  fixtures/tests.
- Link claims to code paths, specs or fixtures. English, short sections,
  plain Markdown.

## Maintenance
- One doc = one responsibility; avoid overlaps.
- Link new docs from this README and from the relevant section (e.g. protocol README).
- Keep ad-hoc investigations under `docs/40_quality/analysis/`.
- Keep historical snapshots under `docs/**/archive/`; do not present them as current status.
