# Dependency Register (Initial Seed)

> Status: **Incomplete baseline**. This is a starting register, not a full audited SBOM.

| Dependency / Component | Location | Purpose | Owner / Status | Risk | Update Strategy | Notes |
|---|---|---|---|---|---|---|
| HashLib (in-repo) | `HashLib/` | Hashing primitives used by core/tests | Owner TBD / Active | Medium | Manual review + targeted tests | Core crypto-adjacent library, high correctness sensitivity |
| SQLite (vendored) | `Services/` | Data persistence | Owner TBD / Active | Medium | Periodic vendor sync + CVE review | Confirm exact version mapping in follow-up PR |
| zlib (vendored) | `Services/` | Compression support | Owner TBD / Active | Medium | Periodic vendor sync + CVE review | Common attack surface in parser/decompression flows |
| MiniUPnP (vendored) | `Services/MiniUPnP` | NAT traversal / port mapping | Owner TBD / Active | Medium | Vendored sync to MiniUPnPc 2.3.x + absolute SSDP/HTTP timeout bounding (D-009 / #142); not vcpkg-only for now | Currently 2.0 (2016); SSDP interface selection uses `NetworkInterfaceSelector` (`GetAdaptersAddresses` / `GetBestRoute2`); 2.0 receive loop is not a strict wall-clock SSDP deadline |
| UnRAR-related code | `Envy/` + vendor paths | Archive extraction support | Owner TBD / Active | High | Security-first updates with regression tests | Prior traversal-class vulnerabilities require continued scrutiny |

## Follow-up Required
- Assign explicit owners for top dependencies.
- Add exact version identifiers and upstream source links.
- Add update cadence and validation checklist per dependency.
