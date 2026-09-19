# Known inconsistencies

- **ED2K/Kad scope:** `ED2K_KAD_GAP_ANALYSIS` describes historical gaps; `kad2-compatibility-report` focuses on wire-level Kad2 opcode matching with eMule/aMule. Neither is live interop. Canonical high-level status is `docs/10_dev/status.md`.

- **SecureIdent:** January 2026 docs (`modernization-summary.md`, `security-improvements-summary.md`, older CHANGELOG “SecureID version = 3”) contradicted #75. Current code: `ED2K_VERSION_SECUREID = 0`; RSA not implemented. Those historical changelog lines remain as history of a later-reverted advertisement.

- **`docs/DEV_TRACKER.md`:** listed in README historically as the operational dashboard but **gitignored** (`.gitignore`). Session notes belong in `.local/DEV_TRACKER.md`. Committed dashboard: `docs/DEVELOPMENT_PLAN.md` + `docs/10_dev/status.md`.

- **Missing index targets:** `docs/00_index/MASTER_PLAN.md` and `docs/30_protocols/ed2k/ED2K_SEARCH_DIAGNOSTICS.md` were linked but absent; links were removed from the index/ED2K README rather than inventing stub files.

- **Historical `.github/` docs:** Former live copies of roadmap / upgrade summary / modern C++ guide under `.github/` contradicted `docs/10_dev/status.md` (e.g. IPv6 “complete”). They are now pointers; archives live under `docs/10_dev/archive/`. AI-rule thin-adapter consolidation is deferred while PR #164 touches `AGENTS.md` / `CLAUDE.md` / `.github/CONTRIBUTING.md`.

- **EDClient.h comments:** Member `m_bEmSupportsSourceEx2` is commented "Not supported" but SourceEx2 (REQUESTSOURCES2/ANSWERSOURCES2) is implemented in `EDClient.cpp` and advertised; consider updating the comment to "Source Exchange v2".

- **Gnutella `{deflate}` sizing (QueryHit vs G1Packet) — resolved (#119):** Not a functional bug. `CQueryHit::ReadXML` receives a fixed `nXMLSize` that includes a trailing NUL (Shareaza heritage: `{plaintext}` used `nSize - 12` = 11-byte header + NUL; `{deflate}` uses `nSize - 10` = 9-byte marker + NUL). `CG1Packet::ReadXML` measures length until `G1_PACKET_HIT_SEP`/NUL, so `len` already excludes the separator and correctly uses `len - 9`. Keep both arithmetic paths; do not "unify" them.

- **Uploads `MaxPerHost` accept vs enforce counts:** `CUploads::AllowMoreTo` treats `nCount <= MaxPerHost` as OK (so `MaxPerHost+1` uploading+queued can be allowed). `CanUploadFileTo` uses `nCount < MaxPerHost`. `EnforcePerHostLimit` also counts `upsPreQueue`. Documented in `docs/50_user/transfer-settings.md`; engine not changed in the transfer-settings foundation PR.

- **Uploads FairUseMode:** Registry/UI remnant (`Uploads.FairUseMode`). No core consumer. Uploads checkbox is disabled as of the transfer-settings foundation PR. Do not document as a live 10% media limit.
