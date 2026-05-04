# Dependency Audit

- **Date:** 2026-04-22
- **Scope:** In-repo vendored libraries, GitHub Actions dependencies, language/runtime dependencies
- **Method:** Static version macro inspection and workflow review
- **Dependency Register:** See the living register at [`docs/DEPENDENCIES.md`](../DEPENDENCIES.md).

## Dependency Inventory (Observed)

| Component | Source Location | Observed Version Signal | Status |
|---|---|---|---|
| SQLite | `Services/SQLite/sqlite3.h` | `3.51.1` | Current/newer snapshot present |
| zlib | `Services/zlib/zlib.h` | `1.3` | Current baseline |
| MiniUPnPc | `Services/MiniUPnP/miniupnpc.h` | `2.0` (2016 header metadata) | Likely outdated |
| UnRAR | `Services/UnRAR/version.hpp` | `5.30` / 2015 date fields | Outdated lineage |
| HashLib | `HashLib/*` | Internal project `1.0.0` (CMake) | Internal |
| GitHub Actions | `.github/workflows/*.yml` | `actions/*@v5`, `codeql@v4` etc. | Generally modern |

## Severity-Ranked Findings

### High
1. **Outdated vendored dependencies (MiniUPnP, UnRAR) with elevated vulnerability exposure window.**
2. **No centralized machine-readable dependency manifest for native vendored code (SBOM missing).**

### Medium
1. **Dependabot currently covers GitHub Actions only; native C/C++ vendored libraries are not auto-tracked.**
2. **License inventory is implicit, not consolidated into a single license matrix.**

### Low
1. **Dependency upgrade policy (cadence, owner, validation checklist) is not explicitly documented.**

## License Check Notes
- Repository license is AGPLv3, but bundled third-party license obligations are spread across service subdirectories.
- Recommendation: generate and maintain a `THIRD_PARTY_LICENSES.md` + attribution table.

## Upgrade Path Recommendations
1. Create dependency register (name, version, source URL, owner, last-reviewed date).
2. Prioritize MiniUPnP and UnRAR refresh with regression testing around NAT traversal and archive extraction.
3. Add periodic CVE review issue template and automation reminders.
4. Produce SBOM (CycloneDX/SPDX) as CI artifact on each release branch.
