# 📦 Dependencies Audit - Envy

**Date:** January 16, 2026
**Version:** 1.0
**Objective:** Inventory of bundled libraries, versions, licenses and update plan

---

## 📋 Bundled Libraries (Services/)

### 1. UnRAR

**Path:** `Services/UnRAR/`
**Current Version:** 5.3.8 (November 2015)
**Upstream Version:** 6.2.12 (December 2023)
**License:** Freeware (see `Services/UnRAR/License.txt`)

**Usage:**
- `Plugins/RARBuilder/RARBuilder.cpp` - RAR archive extraction
- `Plugins/RARBuilder/Unrar.h` - DLL interface

**Identified Issues:**
1. **Outdated Version:** 8+ years behind, unpatched security vulnerabilities
2. **License:** Freeware only - commercial use requires separate license
3. **Path Traversal:** No validation of extracted paths (see `SECURITY_AUDIT.md`)

**Risks:**
- **Security:** Unpatched CVE vulnerabilities
- **Legal:** Commercial usage may require WinRAR license
- **Compatibility:** Recent RAR formats not supported

**Update Plan:**
1. **Option A (Recommended):** Migrate to 7-Zip (LGPL, actively maintained)
   - Advantages: Free license, maintained, more secure
   - Disadvantages: Refactoring required
   - Complexity: Medium (M)

2. **Option B:** Update to UnRAR 6.2.12
   - Advantages: Maximum compatibility
   - Disadvantages: Verify license for commercial use
   - Complexity: Low (S)

**Files to Modify:**
- `Plugins/RARBuilder/RARBuilder.cpp` - Adapt interface
- `Plugins/RARBuilder/Unrar.h` - Update signatures
- `Services/UnRAR/` - Replace with new version or 7-Zip

**Priority:** P1 (Security + Compatibility)

---

### 2. MiniUPnP

**Path:** `Services/MiniUPnP/`
**Current Version:** 2.0 (April 2016)
**Upstream Version:** 2.2.6 (2023)
**License:** BSD-3-Clause (see `Services/MiniUPnP/License.txt`)

**Usage:**
- `Envy/UPnPFinder.cpp:709-743` - Port forwarding
- `Envy/UPnPNAT.cpp:127-188` - Modern mapping
- `Envy/MiniUPnP.cpp` - Wrapper

**Identified Issues:**
1. **Outdated Version:** 7+ years behind
2. **Security:** Buffer overflow vulnerabilities fixed in recent versions
3. **Compatibility:** Some modern routers not supported

**Risks:**
- **Security:** Potential buffer overflows
- **Functionality:** Incompatibility with recent routers

**Update Plan:**
1. Update to MiniUPnP 2.2.6
   - Complexity: Low (S)
   - Impact: Security + Compatibility

**Files to Modify:**
- `Services/MiniUPnP/` - Replace with version 2.2.6
- `Envy/MiniUPnP.cpp` - Verify API compatibility

**Priority:** P1 (Security)

---

### 3. zlib

**Path:** `Services/zlib/`
**Current Version:** 1.2.10 (January 2017)
**Upstream Version:** 1.3.1 (August 2023)
**License:** zlib License (very permissive)

**Usage:**
- General compression/decompression
- File formats (ZIP, etc.)

**Identified Issues:**
1. **Outdated Version:** 6+ years behind
2. **Security:** Vulnerabilities fixed in 1.2.11+ (CVE-2022-37434, etc.)

**Risks:**
- **Security:** Malicious decompression (zip bombs, etc.)

**Update Plan:**
1. Update to zlib 1.3.1
   - Complexity: Low (S)
   - Impact: Security

**Files to Modify:**
- `Services/zlib/` - Replace with version 1.3.1
- Verify binary compatibility (ABI stable)

**Priority:** P1 (Security)

---

### 4. GeoIP (Legacy)

**Path:** `Services/GeoIP/`
**Current Version:** Legacy (unspecified version, probably 1.x)
**Upstream Version:** **DEPRECATED** - MaxMind GeoIP2 recommended
**License:** LGPL/GPL (depending on version)

**Usage:**
- `Envy/Envy.cpp:2193-2237` - IP geolocation
- Dynamic loading via `GeoIP.dll`

**Identified Issues:**
1. **Deprecated:** MaxMind discontinued GeoIP Legacy support
2. **Database:** Obsolete `.dat` format, no more updates
3. **Security:** No security updates

**Risks:**
- **Functionality:** Outdated geolocation data
- **Security:** No security patches

**Update Plan:**
1. **Option A (Recommended):** Migrate to libmaxminddb (GeoIP2)
   - Modern MMDB format
   - Free GeoLite2 database
   - Complexity: Medium (M)

2. **Option B:** Use external service (ipapi.co, ip-api.com)
   - Advantages: No maintenance
   - Disadvantages: Network dependency, rate limits

**Files to Modify:**
- `Envy/Envy.cpp:2193-2237` - Replace `LoadCountry()`/`FreeCountry()`
- `Envy/Envy.h` - Update types/pointers
- `Services/GeoIP/` - Remove or replace

**Priority:** P2 (Functionality)

---

### 5. LibUTP (uTorrent Transport Protocol)

**Path:** `Services/LibUTP/`
**Current Version:** June 2014 (unspecified version)
**Upstream Version:** **INACTIVE** - Last commit 2014
**License:** MIT (see `Services/LibUTP/LICENSE`)

**Usage:**
- BitTorrent transport protocol (UTP)
- Alternative to TCP for BitTorrent

**Identified Issues:**
1. **Abandoned:** Project inactive since 2014
2. **Security:** No security updates
3. **Compatibility:** May not work with modern BitTorrent clients

**Risks:**
- **Security:** Unpatched vulnerabilities
- **Functionality:** Incompatibility with modern clients

**Update Plan:**
1. **Option A:** Keep as is (if working)
   - Document risks
   - Disable by default if issues

2. **Option B:** Migrate to maintained libutp fork (if available)
   - Search for active forks on GitHub

3. **Option C:** Remove UTP support
   - Use TCP only
   - Complexity: Low (S)

**Files to Modify:**
- `Services/LibUTP/` - Evaluate necessity
- `Envy/BTClient.cpp` - Verify usage

**Priority:** P2 (Security if vulnerabilities found)

---

### 6. Bzlib (bzip2)

**Path:** `Services/Bzlib/`
**Current Version:** Unspecified (probably 1.0.6)
**Upstream Version:** 1.0.8 (July 2019)
**License:** BSD-style (see `Services/Bzlib/License.txt`)

**Usage:**
- bzip2 compression

**Identified Issues:**
1. **Potentially outdated version:** Verify exact version
2. **Security:** Check recent CVEs

**Update Plan:**
1. Verify current version
2. Update to 1.0.8 if necessary
   - Complexity: Low (S)

**Priority:** P2 (Maintenance)

---

### 7. BugTrap

**Path:** `Services/BugTrap/`
**Current Version:** Unspecified
**Upstream Version:** **INACTIVE** - Last version 3.x
**License:** BSD-style

**Usage:**
- Crash reporting
- Diagnostics

**Identified Issues:**
1. **Abandoned:** Inactive project
2. **Compatibility:** May not work with Windows 11/VS 2022+

**Update Plan:**
1. **Option A:** Keep as is (if working)
2. **Option B:** Migrate to Crashpad (Google) or Breakpad
   - Complexity: High (L)
   - Advantages: Actively maintained

**Priority:** P2 (Maintenance)

---

### 8. SQLite

**Path:** `Services/SQLite/`
**Current Version:** Unspecified (check `sqlite3.h`)
**Upstream Version:** 3.45.0 (December 2024)
**License:** Public Domain

**Usage:**
- Local database
- Metadata storage

**Identified Issues:**
1. Verify exact version
2. Update if < 3.40.0 (security)

**Update Plan:**
1. Verify current version
2. Update to 3.45.0 if necessary
   - Complexity: Low (S)
   - ABI stable, simple update

**Priority:** P1 (Security if old version)

---

## 📊 Summary Table

| Library | Current Version | Upstream Version | Priority | Complexity | Risk |
|---------|-----------------|------------------|----------|------------|------|
| UnRAR | 5.3.8 (2015) | 6.2.12 (2023) | P1 | M | Security + License |
| MiniUPnP | 2.0 (2016) | 2.2.6 (2023) | P1 | S | Security |
| zlib | 1.2.10 (2017) | 1.3.1 (2023) | P1 | S | Security |
| GeoIP | Legacy | Deprecated | P2 | M | Functionality |
| LibUTP | 2014 | Inactive | P2 | - | Security |
| Bzlib | ? | 1.0.8 (2019) | P2 | S | Maintenance |
| BugTrap | ? | Inactive | P2 | L | Maintenance |
| SQLite | ? | 3.45.0 (2024) | P1 | S | Security |

---

## 🔄 Sequential Update Plan

### Phase 1: Critical Security (P1)
1. **zlib 1.3.1** - 1 day
   - Simple update, ABI compatible
   - Tests: Compression/decompression

2. **MiniUPnP 2.2.6** - 2-3 days
   - Verify API compatibility
   - Tests: Port forwarding on different routers

3. **SQLite 3.45.0** - 1 day
   - Check current version first
   - Tests: Database migration (if necessary)

### Phase 2: Security + Compatibility (P1)
4. **UnRAR → 7-Zip or UnRAR 6.2.12** - 1-2 weeks
   - Decision: 7-Zip (recommended) or UnRAR 6.2.12
   - Tests: Extraction of various RAR formats
   - Verify license if UnRAR

### Phase 3: Maintenance (P2)
5. **GeoIP → libmaxminddb** - 1 week
   - Migration to GeoIP2
   - Tests: IP geolocation

6. **LibUTP** - Evaluation
   - Decide: Keep, Fork, or Remove

7. **BugTrap** - Evaluation
   - Decide: Keep or migrate to Crashpad

---

## ⚠️ Compatibility Notes

### UnRAR
- **License:** Verify commercial usage - may require WinRAR license
- **7-Zip Alternative:** RAR format partially supported (read-only for some formats)

### GeoIP Legacy
- **Migration:** Format `.dat` → `.mmdb` (incompatible)
- **Database:** Download GeoLite2 from MaxMind (free, monthly updates)

### MiniUPnP
- **API:** Verify API changes between 2.0 and 2.2.6
- **Tests:** Test on recent routers (2020+)

---

## ✅ Validation Checklist

For each update:
- [ ] Verify ABI/API compatibility
- [ ] Read changelog for breaking changes
- [ ] Test critical functionality
- [ ] Verify licenses (commercial usage)
- [ ] Update documentation
- [ ] Complete regression tests

---

## 📝 License Notes

### UnRAR
- **Freeware:** Free usage for extraction only
- **Commercial:** RAR archiver development requires WinRAR license
- **Distribution:** Allowed in other software (include license)

### GeoIP Legacy
- **LGPL/GPL:** Depending on version
- **GeoIP2 (libmaxminddb):** Apache 2.0
- **GeoLite2 DB:** Creative Commons Attribution-ShareAlike 4.0

### Others
- **zlib:** zlib License (very permissive)
- **MiniUPnP:** BSD-3-Clause
- **SQLite:** Public Domain
- **LibUTP:** MIT

---

**Next Steps:**
1. Verify exact versions of all dependencies
2. Prioritize P1 updates (security)
3. Plan regression tests
4. Document license changes if necessary
