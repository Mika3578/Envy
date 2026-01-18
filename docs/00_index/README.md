# Envy Documentation

## Start here
- **Developer quick entry:** `docs/00_index/CURSOR_INDEX.md`
- **Modernisation master plan:** `docs/00_index/MASTER_PLAN.md`
- **Decisions (ADR-lite):** `docs/00_index/DECISIONS.md`
- **Style guide:** `docs/00_index/STYLE_GUIDE.md`

## Documentation map

### User documentation
- `docs/50_user/guide.md`
- `docs/50_user/installation.md`
- `docs/50_user/configuration.md`
- `docs/50_user/ed2k-settings-guide.md`
- `docs/50_user/reference/COMPLETE_SETTINGS_REFERENCE.md`

### Developer documentation
- **Dev workflow / build / standards:** `docs/10_dev/`
- **Architecture:** `docs/20_arch/architecture.md`
- **Protocols:** `docs/30_protocols/`
- **Quality (analysis, perf, security, tests):** `docs/40_quality/`

## Maintenance rules
- One doc = one responsibility (avoid overlaps)
- Every new doc must be linked from this README and, if relevant, from the protocol folder README
- Prefer stable docs over WIP notes; keep raw investigations under `docs/40_quality/analysis/` (or create an explicit `docs/99_wip/`)
