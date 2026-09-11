# Known inconsistencies

- **ED2K/Kad scope:** `ED2K_KAD_GAP_ANALYSIS` describes historical gaps; `kad2-compatibility-report` focuses on wire-level Kad2 opcode matching with eMule/aMule. Neither is live interop. Canonical high-level status is `docs/10_dev/status.md`.

- **SecureIdent:** January 2026 docs (`modernization-summary.md`, `security-improvements-summary.md`, older CHANGELOG “SecureID version = 3”) contradicted #75. Current code: `ED2K_VERSION_SECUREID = 0`; RSA not implemented. Those historical changelog lines remain as history of a later-reverted advertisement.

- **`docs/DEV_TRACKER.md`:** listed in README historically as the operational dashboard but **gitignored** (`.gitignore`). Session notes belong in `.local/DEV_TRACKER.md`. Committed dashboard: `docs/DEVELOPMENT_PLAN.md` + `docs/10_dev/status.md`.

- **Missing index targets:** `docs/00_index/MASTER_PLAN.md` and `docs/30_protocols/ed2k/ED2K_SEARCH_DIAGNOSTICS.md` were linked but absent; links were removed from the index/ED2K README rather than inventing stub files.

- **EDClient.h comments:** Member `m_bEmSupportsSourceEx2` is commented "Not supported" but SourceEx2 (REQUESTSOURCES2/ANSWERSOURCES2) is implemented in `EDClient.cpp` and advertised; consider updating the comment to "Source Exchange v2".

- **Gnutella `{deflate}` sizing (QueryHit vs G1Packet):** `CQueryHit::ReadXML` (`QueryHit.cpp`) passes `nSize - 10` to `CZLib::Decompress` after the 9-byte `{deflate}` marker (effective compressed length excludes one trailing byte). The sibling path in `CG1Packet` (`G1Packet.cpp`) advances the pointer by 9 and decompresses `len - 9` (full remainder). Memory-safety hardening only requires `nSize > 10` before the QueryHit subtraction; reconciling the off-by-one as a functional bug is a separate maintainer decision (do not "fix" it opportunistically in parser-length PRs).

- **Gnutella `{deflate}` sizing (QueryHit vs G1Packet):** `CQueryHit::ReadXML` (`QueryHit.cpp`) passes `nSize - 10` to `CZLib::Decompress` after the 9-byte `{deflate}` marker (effective compressed length excludes one trailing byte). The sibling path in `CG1Packet` (`G1Packet.cpp`) advances the pointer by 9 and decompresses `len - 9` (full remainder). Memory-safety hardening only requires `nSize > 10` before the QueryHit subtraction; reconciling the off-by-one as a functional bug is a separate maintainer decision (do not "fix" it opportunistically in parser-length PRs).
