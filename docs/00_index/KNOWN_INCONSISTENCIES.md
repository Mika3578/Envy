# Known inconsistencies

- **Mixed C++17/C++20 Release|x64 baseline:** Policy is C++20 first-party and
  C++17 legacy plugins (`AGENTS.md`, `MODERNIZATION.md`). Live MSBuild uses
  the last `<LanguageStandard>` in a `ClCompile` block, so Release|x64 for
  Envy, HashLib, TorrentEnvy, and Unpacker currently compiles as C++17
  (`stdcpp20` then trailing `stdcpp17`). Canonical wording:
  `docs/10_dev/standards.md`. Do not remove those overrides in a docs PR.

- **Protect develop ruleset (re-verified 2026-09-21):** Live ruleset
  `16457466` still reports `required_approving_review_count: 0` via the GitHub
  API, with Code Quality severity **all**, required review-thread resolution,
  squash-only + linear history, and the published required status checks.
  Maintainer **target** remains **1 required approval**; do not treat older
  “already matched 1 approval” notes as live. Coverage restriction remains
  **off**. Historical 2026-09-19 snapshots that recorded Code Quality `notes` /
  `review_on_push: false` are retained as history. Repository Copilot UI toggles that still
  need manual verification are **Allow Copilot to approve pull requests**,
  **Allow Copilot approvals to count toward merge requirements**, review
  effort **Balanced**, and the optional path allowlist (Stage-3 docs/i18n
  globs in `docs/10_dev/devsecops-envy.md`; excludes review-governance). Automatic Copilot review is
  already live on Protect develop (`copilot_code_review` + `review_on_push`);
  it is not a remaining UI gap. An AI comment/assessment alone is not an
  `APPROVED` review. See `docs/10_dev/CI_AUDIT_2026-09.md` and
  `docs/10_dev/devsecops-envy.md`.

- **ED2K/Kad scope:** `ED2K_KAD_GAP_ANALYSIS` is a historical snapshot (routing-table items annotated 2026-09-19 after `KadRoutingTable.h`). `kad2-compatibility-report` covers opcode/format matching plus local routing maintenance. Neither is live interop. Canonical high-level status is `docs/10_dev/status.md`. The gap-analysis `FIREWALLED_REQ`/`RES` TagList/TargetID framing is outdated; eMule/aMule use exact 2-byte port / 4-byte IPv4 (`docs/30_protocols/kad/kad2-compatibility-report.md`).

- **SecureIdent:** January 2026 docs (`modernization-summary.md`, `security-improvements-summary.md`, older CHANGELOG “SecureID version = 3”) contradicted #75. Current code: `ED2K_VERSION_SECUREID = 0`; RSA not implemented. Those historical changelog lines remain as history of a later-reverted advertisement.

- **`docs/DEV_TRACKER.md`:** listed in README historically as the operational dashboard but **gitignored** (`.gitignore`). Session notes belong in `.local/DEV_TRACKER.md`. Committed dashboard: `docs/DEVELOPMENT_PLAN.md` + `docs/10_dev/status.md`.

- **Missing index targets:** `docs/00_index/MASTER_PLAN.md` and `docs/30_protocols/ed2k/ED2K_SEARCH_DIAGNOSTICS.md` were linked but absent; links were removed from the index/ED2K README rather than inventing stub files.

- **Historical `.github/` docs:** Former live copies of roadmap / upgrade summary / modern C++ guide under `.github/` contradicted `docs/10_dev/status.md` (e.g. IPv6 “complete”). They are now pointers; archives live under `docs/10_dev/archive/`. AI-rule thin-adapter consolidation is this PR (#293): `AGENTS.md` is canonical; Copilot/Claude/Cline/Windsurf/Continue files are pointers.

- **EDClient.h comments:** Member `m_bEmSupportsSourceEx2` is commented "Not supported" but SourceEx2 (REQUESTSOURCES2/ANSWERSOURCES2) is implemented in `EDClient.cpp` and advertised; consider updating the comment to "Source Exchange v2".

- **Gnutella `{deflate}` sizing (QueryHit vs G1Packet) — resolved (#119):** Not a functional bug. `CQueryHit::ReadXML` receives a fixed `nXMLSize` that includes a trailing NUL (Shareaza heritage: `{plaintext}` used `nSize - 12` = 11-byte header + NUL; `{deflate}` uses `nSize - 10` = 9-byte marker + NUL). `CG1Packet::ReadXML` measures length until `G1_PACKET_HIT_SEP`/NUL, so `len` already excludes the separator and correctly uses `len - 9`. Keep both arithmetic paths; do not "unify" them.

- **nodes.dat versions:** `CHostCache::ImportNodes` now parses legacy v0 plus new-format v1/v2/v3 via `Envy/KadNodesDat.h` (v3 edition 1 is bootstrap-only / bounded). Remote HTTP `nodes.dat` is still not wired. Canonical note: `docs/10_dev/status.md` and `docs/30_protocols/bootstrap-sources.md`.

- **HostCache DNS-only BT routers:** shipped `DefaultServers.dat` `B` rows are hostnames. `CHostCacheList::Add` keeps `m_pAddress = INADDR_ANY` until a later resolve. The map is a `std::multimap`, so multiple `0.0.0.0` keys coexist; DHT bootstrap walks `m_HostsTime`. Canonical note: `docs/30_protocols/bootstrap-sources.md`. Do not treat this as a reason to hard-code DHT DNS in C++ (D-012).
- **Uploads `MaxPerHost` accept vs enforce counts:** `CUploads::AllowMoreTo` treats `nCount <= MaxPerHost` as OK (so `MaxPerHost+1` uploading+queued can be allowed). `CanUploadFileTo` uses `nCount < MaxPerHost`. `EnforcePerHostLimit` also counts `upsPreQueue`. Documented in `docs/50_user/transfer-settings.md`; engine not changed in the transfer-settings foundation PR.

- **Remote `BindAddress` unused:** `Settings.Remote.BindAddress` defaults to `127.0.0.1` (`Settings.cpp`) but no listener binds it. HTML Remote is multiplexed on the P2P HTTP accept path (`CUploads::OnAccept` → `CRemote`). Access control is `CRemoteSecurity::IsRemoteAccessAllowed` (IPv4 only; `::1` is not loopback). Canonical: `docs/20_arch/AUDIT_REMOTE_API_2026-09.md`. Follow-up is a dedicated API port (D-017), not silently trusting this setting.

- **`Remote/api-specification.md` vs C++:** The JSON `/api/downloads` family is design-only. `CRemote::PageSwitch` serves `/remote/*` HTML. Do not treat the spec or `envy-modern.js` as a live contract.

- **#90 / PR #243 crash reporter:** `develop` ships Crashpad (`CrashPadHost` + `crashpad_handler.exe` from vcpkg), not BugTrap and not in-process `MiniDumpWriteDump`. Local Visual Studio builds must restore `vcpkg_installed` first (`scripts/bootstrap-vcpkg.cmd`); CI already does. Canonical: `docs/10_dev/crash-reporting.md`, `docs/10_dev/build.md`.
