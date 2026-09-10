# Known inconsistencies

- **ED2K/Kad scope:** `ED2K_KAD_GAP_ANALYSIS` describes historical gaps; `kad2-compatibility-report` focuses on wire-level Kad2 compatibility with eMule/aMule. Both are valid; canonical high-level status is `docs/10_dev/status.md`. No merge required.

- **EDClient.h comments:** Member `m_bEmSupportsSourceEx2` is commented "Not supported" but SourceEx2 (REQUESTSOURCES2/ANSWERSOURCES2) is implemented in `EDClient.cpp` and advertised; consider updating the comment to "Source Exchange v2".

- **Gnutella `{deflate}` sizing (QueryHit vs G1Packet):** `CQueryHit::ReadXML` (`QueryHit.cpp`) passes `nSize - 10` to `CZLib::Decompress` after the 9-byte `{deflate}` marker (effective compressed length excludes one trailing byte). The sibling path in `CG1Packet` (`G1Packet.cpp`) advances the pointer by 9 and decompresses `len - 9` (full remainder). Memory-safety hardening only requires `nSize > 10` before the QueryHit subtraction; reconciling the off-by-one as a functional bug is a separate maintainer decision (do not "fix" it opportunistically in parser-length PRs).
