# Known inconsistencies

- **Protect develop required approvals (2026-09-19):** Live ruleset
  `Protect develop` (`16457466`) returns `required_approving_review_count: 0`
  via the GitHub API, while `AGENTS.md`, `docs/10_dev/devsecops-envy.md`, and
  `.github/settings.yml` still describe the **intended** policy as ≥1
  APPROVED review. Prefer restoring the live ruleset to 1; until then treat
  docs as policy intent and the API as the enforceable gate. See
  `docs/10_dev/CI_AUDIT_2026-09.md`.

- **Protect develop Code Quality rule:** Live ruleset includes a
  `code_quality` rule with severity `notes`. DevSecOps prose was updated in
  2026-09 to match (`docs/10_dev/devsecops-envy.md`,
  `docs/10_dev/CI_AUDIT_2026-09.md`). `.github/settings.yml` still records
  the intended policy as having **no** GitHub Code Quality ruleset rule
  (Probot comment block). Open item: maintainer decision whether to keep the
  notes rule, raise it, or remove it in favor of Sonar/CodeQL/CI — and align
  `settings.yml` afterward.

- **ED2K/Kad scope:** `ED2K_KAD_GAP_ANALYSIS` describes historical gaps; `kad2-compatibility-report` focuses on wire-level Kad2 opcode matching with eMule/aMule. Neither is live interop. Canonical high-level status is `docs/10_dev/status.md`.

- **SecureIdent:** January 2026 docs (`modernization-summary.md`, `security-improvements-summary.md`, older CHANGELOG “SecureID version = 3”) contradicted #75. Current code: `ED2K_VERSION_SECUREID = 0`; RSA not implemented. Those historical changelog lines remain as history of a later-reverted advertisement.

- **`docs/DEV_TRACKER.md`:** listed in README historically as the operational dashboard but **gitignored** (`.gitignore`). Session notes belong in `.local/DEV_TRACKER.md`. Committed dashboard: `docs/DEVELOPMENT_PLAN.md` + `docs/10_dev/status.md`.

- **Missing index targets:** `docs/00_index/MASTER_PLAN.md` and `docs/30_protocols/ed2k/ED2K_SEARCH_DIAGNOSTICS.md` were linked but absent; links were removed from the index/ED2K README rather than inventing stub files.

- **Historical `.github/` docs:** Former live copies of roadmap / upgrade summary / modern C++ guide under `.github/` contradicted `docs/10_dev/status.md` (e.g. IPv6 “complete”). They are now pointers; archives live under `docs/10_dev/archive/`. AI-rule thin-adapter consolidation is deferred while PR #164 touches `AGENTS.md` / `CLAUDE.md` / `.github/CONTRIBUTING.md`.

- **EDClient.h comments:** Member `m_bEmSupportsSourceEx2` is commented "Not supported" but SourceEx2 (REQUESTSOURCES2/ANSWERSOURCES2) is implemented in `EDClient.cpp` and advertised; consider updating the comment to "Source Exchange v2".

- **Gnutella `{deflate}` sizing (QueryHit vs G1Packet) — resolved (#119):** Not a functional bug. `CQueryHit::ReadXML` receives a fixed `nXMLSize` that includes a trailing NUL (Shareaza heritage: `{plaintext}` used `nSize - 12` = 11-byte header + NUL; `{deflate}` uses `nSize - 10` = 9-byte marker + NUL). `CG1Packet::ReadXML` measures length until `G1_PACKET_HIT_SEP`/NUL, so `len` already excludes the separator and correctly uses `len - 9`. Keep both arithmetic paths; do not "unify" them.

- **nodes.dat versions:** `docs/10_dev/roadmap.md` and `kad2-compatibility-report.md` previously said HostCache imports nodes.dat v0–3. `CHostCache::ImportNodes` accepts old format (leading count ≠ 0) and new format **version 1 only**; version ≠ 1 returns 0. eMule-Security `nodes.dat` on 2026-09-18 is new-format version 2. Canonical note: `docs/10_dev/status.md` and `docs/30_protocols/bootstrap-sources.md`.

- **HostCache DNS-only BT routers:** shipped `DefaultServers.dat` `B` rows are hostnames. `CHostCacheList::Add` keeps `m_pAddress = INADDR_ANY` until a later resolve. The map is a `std::multimap`, so multiple `0.0.0.0` keys coexist; DHT bootstrap walks `m_HostsTime`. Canonical note: `docs/30_protocols/bootstrap-sources.md`. Do not treat this as a reason to hard-code DHT DNS in C++ (D-012).
- **Uploads `MaxPerHost` accept vs enforce counts:** `CUploads::AllowMoreTo` treats `nCount <= MaxPerHost` as OK (so `MaxPerHost+1` uploading+queued can be allowed). `CanUploadFileTo` uses `nCount < MaxPerHost`. `EnforcePerHostLimit` also counts `upsPreQueue`. Documented in `docs/50_user/transfer-settings.md`; engine not changed in the transfer-settings foundation PR.

- **Remote `BindAddress` unused:** `Settings.Remote.BindAddress` defaults to `127.0.0.1` (`Settings.cpp`) but no listener binds it. HTML Remote is multiplexed on the P2P HTTP accept path (`CUploads::OnAccept` → `CRemote`). Access control is `CRemoteSecurity::IsRemoteAccessAllowed` (IPv4 only; `::1` is not loopback). Canonical: `docs/20_arch/AUDIT_REMOTE_API_2026-09.md`. Follow-up is a dedicated API port (D-017), not silently trusting this setting.

- **`Remote/api-specification.md` vs C++:** The JSON `/api/downloads` family is design-only. `CRemote::PageSwitch` serves `/remote/*` HTML. Do not treat the spec or `envy-modern.js` as a live contract.

- **#90 / PR #243 crash reporter:** `develop` still ships BugTrap until this PR merges. PR #243 now uses Crashpad (`CrashPadHost` + `crashpad_handler.exe`), not in-process `MiniDumpWriteDump`. Canonical: `docs/10_dev/crash-reporting.md`.
