# Envy Documentation

**Quick links:** [Cursor Index](CURSOR_INDEX.md) · [Status](../10_dev/status.md) · [Roadmap](../10_dev/roadmap.md) · [References](../30_protocols/REFERENCE_IMPLEMENTATIONS.md) · [Build](../10_dev/build.md)

## Start here
| Doc | Purpose |
|-----|---------|
| [CURSOR_INDEX](CURSOR_INDEX.md) | Quick entry points for development |
| [DEVELOPMENT_PLAN](../DEVELOPMENT_PLAN.md) | Strategic roadmap (canonical) |
| [DECISIONS](../DECISIONS.md) | ADR-lite decisions |
| [STYLE_GUIDE](STYLE_GUIDE.md) | Writing and formatting |

## Map

| Section | Location | Notes |
|---------|----------|-------|
| **User** | `docs/50_user/` | Guide, installation, configuration, [settings reference](../50_user/reference/COMPLETE_SETTINGS_REFERENCE.md) |
| **Developer** | `docs/10_dev/` | Build, guide, standards, contributing, status, roadmap |
| **Architecture** | [architecture](../20_arch/architecture.md) | System design |
| **Protocols** | `docs/30_protocols/` | ED2K, Kad, BitTorrent, [reference implementations](../30_protocols/REFERENCE_IMPLEMENTATIONS.md) |
| **Quality** | `docs/40_quality/` | Analysis, performance, security, testing |

## Root compatibility pointers

These short files under `docs/` preserve old links; prefer the numbered targets:

| Pointer | Canonical target |
|---------|------------------|
| [`docs/ROADMAP.md`](../ROADMAP.md) | [`10_dev/roadmap.md`](../10_dev/roadmap.md) |
| [`docs/STATUS.md`](../STATUS.md) | [`10_dev/status.md`](../10_dev/status.md) |
| [`docs/KAD2_COMPATIBILITY_REPORT.md`](../KAD2_COMPATIBILITY_REPORT.md) | [`30_protocols/kad/kad2-compatibility-report.md`](../30_protocols/kad/kad2-compatibility-report.md) |
| [`docs/CONTRIBUTING.md`](../CONTRIBUTING.md) | [`.github/CONTRIBUTING.md`](../../.github/CONTRIBUTING.md) |

GitHub-side pointers (not live status): `.github/ROADMAP.md`, `.github/UPGRADE_SUMMARY.md`, `.github/MODERN_CPP_GUIDE.md` → see `docs/10_dev/` and `docs/10_dev/archive/`.

## Historical archives

| Archive | Notes |
|---------|-------|
| [`10_dev/archive/roadmap-product-2024-2025.md`](../10_dev/archive/roadmap-product-2024-2025.md) | 2024–2025 product roadmap sketch; IPv6 claims superseded by status matrix |
| [`10_dev/archive/upgrade-summary-2024-11.md`](../10_dev/archive/upgrade-summary-2024-11.md) | November 2024 modernization snapshot |

## Maintenance
- One doc = one responsibility; avoid overlaps.
- Link new docs from this README and from the relevant section (e.g. protocol README).
- Keep ad‑hoc investigations under `docs/40_quality/analysis/` or `docs/99_wip/`.
- Keep historical snapshots under `docs/**/archive/`; do not present them as current status.
