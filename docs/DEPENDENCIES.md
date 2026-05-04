# Dependency Register

This register is the living dependency inventory and ownership map for Envy's vendored native components and CI automation dependencies.

| Component | Kind (vendored C/C++, Action, internal) | Source Location | Pinned Version | Upstream URL | License | Owner | Last Reviewed | Upgrade Risk | Notes |
|---|---|---|---|---|---|---|---|---|---|
| SQLite | vendored C/C++ | `Services/SQLite/` | 3.51.1 (`sqlite3.h`) | https://www.sqlite.org/ | Public Domain | @Mika3578 | 2026-05-04 | Medium | Audit marks snapshot as current/newer. |
| zlib | vendored C/C++ | `Services/zlib/` | **Version drift:** `zlib.h` reports 1.3; `Version.txt` and `zlib.rc` still say 1.2.10. | https://zlib.net/ | zlib License | @Mika3578 | 2026-05-04 | Low | Conflicting in-tree version signals; Version.txt/zlib.rc not yet updated to match header. |
| MiniUPnPc | vendored C/C++ | `Services/MiniUPnP/` | 2.0 (header metadata, 2016) | https://miniupnp.tuxfamily.org/ | BSD-3-Clause | @Mika3578 | 2026-05-04 | High | Audit flags as likely outdated; NAT traversal regression risk when upgrading. |
| UnRAR | vendored C/C++ | `Services/UnRAR/` | **Version drift:** `version.hpp`/`dll.rc` report 5.30; `Version.txt` says 5.3.8 (Nov.2015 lineage). | https://www.rarlab.com/rar_add.htm | UnRAR License | @Mika3578 | 2026-05-04 | High | Conflicting in-tree version signals; audit flags as outdated; security-sensitive extraction component. |
| HashLib | internal | `HashLib/` | 1.0.0 (project/CMake metadata) | N/A (in-repo internal project lineage) | GPLv3-or-later (project headers) with mixed upstream copyright notices | @Mika3578 | 2026-05-04 | Medium | Internal dependency shared across core + tests. |
| GitHub Actions (grouped) | Action | `.github/workflows/*.yml` | Moving major tags (`actions/checkout@v5`, `github/codeql-action@v4`, etc.) — not immutable pins | https://github.com/marketplace?type=actions | Per-action upstream licenses | @Mika3578 | 2026-05-04 | Medium | Not pinned to SHA; review changelogs before major bumps. |
| Dependabot scope | Action | `.github/dependabot.yml` | GitHub Actions ecosystem only (`weekly`) | https://docs.github.com/code-security/dependabot | GitHub platform terms | @Mika3578 | 2026-05-04 | Medium | Native vendored C/C++ dependencies are not auto-tracked by Dependabot. |

## Update Cadence & Process

- **Cadence**
  - Vendored C/C++ dependencies: **quarterly** review cadence.
  - GitHub Actions dependencies: **monthly** review cadence.
- **Review ownership**
  - Primary owner: **@Mika3578** (repository maintainer). Update this field when additional co-maintainers are assigned.
- **Validation steps before merging dependency upgrades**
  1. Verify upstream release notes/changelog and security advisories (CVE impact).
  2. Validate version signal in-tree (headers/version files) and update this register.
  3. Run targeted regression checks for impacted areas (for example: NAT traversal for MiniUPnP; archive extraction safety for UnRAR; CI dry-run for Actions updates).
  4. Update `docs/THIRD_PARTY_LICENSES.md` and `CHANGELOG.md` if license/version attribution changes.

## Open Items

- **MiniUPnPc (High finding #1)**
  - Create a scoped upgrade plan from observed `2.0` baseline to current supported upstream release.
  - Define regression checklist focused on UPnP/NAT traversal behavior and fallback paths.
- **UnRAR (High finding #1)**
  - Prepare staged refresh plan from `5.30` lineage, including security regression checks for extraction path validation and archive parsing behavior.
  - Confirm license obligations and re-validate in-tree attribution during upgrade PR.
