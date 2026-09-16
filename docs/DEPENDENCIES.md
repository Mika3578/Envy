# Dependency Register (Initial Seed)

> Status: **Incomplete baseline**. This is a starting register, not a full audited SBOM.

## Package managers

| Source | Role | Notes |
|---|---|---|
| `vcpkg.json` | Intended manifest for zlib, bzip2, sqlite3, miniupnpc, openssl, gtest (feature) | `version-string` must track `version.json`. **openssl** is declared once; no second-party first-party `.vcxproj` consumer was found in a quick 2026-09 scan — confirm before removing (may still be pulled transitively or for future crypto). |
| `Services/*` | Legacy vendored trees (zlib, SQLite, MiniUPnP, …) overlapping vcpkg | Phase 3: migrate consumers to vcpkg, then delete unused vendor trees. Do not relocate wholesale in a hygiene PR. |

## In-tree / vendored

| Dependency / Component | Location | Purpose | Owner / Status | Risk | Update Strategy | Notes |
|---|---|---|---|---|---|---|
| HashLib (in-repo) | `HashLib/` | Hashing primitives used by core/tests | Owner TBD / Active | Medium | Manual review + targeted tests | Core crypto-adjacent library, high correctness sensitivity |
| SQLite (vendored) | `Services/` | Data persistence | Owner TBD / Active | Medium | Periodic vendor sync + CVE review | Confirm exact version mapping in follow-up PR |
| zlib (vendored) | `Services/` | Compression support | Owner TBD / Active | Medium | Periodic vendor sync + CVE review | Common attack surface in parser/decompression flows |
| MiniUPnP (vendored) | `Services/` | NAT traversal / port mapping | Owner TBD / Active | Medium | Vendor security review cadence | Version/patch tracking still incomplete |
| UnRAR-related code | `Envy/` + vendor paths | Archive extraction support | Owner TBD / Active | High | Security-first updates with regression tests | Prior traversal-class vulnerabilities require continued scrutiny |

## Follow-up Required
- Assign explicit owners for top dependencies.
- Add exact version identifiers and upstream source links.
- Add update cadence and validation checklist per dependency.
- Decide openssl keep/drop after a consumer audit (separate PR).
- Unify release versioning: `version.json` → headers / installer / vcpkg (`scripts/auto-version.ps1` vs `SetReleaseVersion.bat`).
