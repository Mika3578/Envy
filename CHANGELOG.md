# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **NMDC hub user list + remote file-list browse** — Hub chat user sidebar can private-message and Browse a remote nick (`hub+nick`, not a global nick). Browse reuses `CHostBrowser` `PROTOCOL_DC` (`dchub://nick@hub:port/files.xml.bz2`). `$NickList` is a nick-only seed merged with `$MyINFO` (no duplicates; 20,000-user cap enforced on both paths). Hostile `files.xml.bz2` lists are fail-closed (compressed/uncompressed size capped at transfer time, bounded XML walk for depth/entries/Name/path-traversal; TTH-less File entries skipped). Incoming FileListing directories feed the existing Browse Host left tree from an owned path/index snapshot (not a DC++-identical control). Outgoing DC file lists omit unhashed files (no fake TTH). This is **not** ADC hub support and **not** “full DC++ support”. Live hub interop remains unverified in CI.
- **DevSecOps tooling (local + PR advisors)** — `scripts/ci-fast.ps1` / `scripts/ci-verify.ps1` for a Windows-local gate approximating MSVC/tests; Renovate (`renovate.json5`) owns GitHub Actions updates with grouping/digests while Dependabot keeps **vcpkg only**; CodeRabbit (`.coderabbit.yaml`) and clang-tidy→reviewdog (`.github/workflows/clang-tidy-pr.yml`) are advisory PR reviewers. See `docs/10_dev/devsecops-envy.md`.
- **`CTextCtrl` viewport helpers + EnvyTests** — `TextCtrlViewport.h` pure scroll/geometry math with smoke tests; manual UI checklist in `docs/10_dev/textctrl-log-ui-checklist.md`.
- **Cloud Agent Linux dev environment (`.cursor/environment.json`)** — Cloud Agents now boot a ready-to-use Linux environment for Envy's cross-platform checks. The install step provisions `clang-format-18`/`clang-tidy`/`cppcheck` and installs the Remote web UI security test dependencies (`npm --prefix Remote/tests ci`). The MFC/ATL app and HashLib remain Windows-only (MSVC v145); this environment targets the same checks CI runs on `ubuntu-latest` (Format Check uses clang-format 18), with `cppcheck` available as an additional local analysis tool.
- **Cross-platform foundations (docs)** — Canonical plan for progressive EnvyCore / platform abstraction / retained MFC Windows frontend; Linux/macOS marked **planned** (not supported); Win32 legacy Stage A policy; CMake portable-slice priority (D-012…D-015). See `docs/20_arch/PORTABILITY_PLAN.md`.
- **DevSecOps tooling (local + PR advisors)** — `scripts/ci-fast.ps1` / `scripts/ci-verify.ps1` for a Windows-local gate approximating MSVC/tests; Renovate (root `renovate.json`) owns GitHub Actions updates with grouping/digests while Dependabot keeps **vcpkg only**; CodeRabbit (`.coderabbit.yaml`) and clang-tidy→reviewdog (`.github/workflows/clang-tidy-pr.yml`) are advisory PR reviewers. See `docs/10_dev/devsecops-envy.md`.

- **4.2.0 Preview 1 release packaging** — Unified product version metadata (`version.json` `4.2.0-preview.1`, Windows `FILEVERSION`/`PRODUCTVERSION` `4.2.0.1`, display `4.2.0 Preview 1`). Release workflow builds per-platform Inno Setup installers (`InstallerAlpha=Preview` from tags containing `preview`), publishes `Envy-<version>-{x64|win32}-{setup.exe|.zip}` plus `SHA256SUMS.txt`, and creates a **draft** GitHub Release marked **prerelease** when the tag contains `preview`/`beta`/`rc`/`alpha`. Preview 1 uses separate x64 and Win32 setups (unified universal installer deferred).
- **Release pipeline validation scripts** — `scripts/release/verify-version.ps1`, `stage-portable.ps1`, `verify-artifacts.ps1`, `publish-draft-release.ps1`, and `repair-draft-release.ps1` gate tag/`version.json`/`Envy.rc`/`Envy.exe` consistency, stage a full portable runtime tree, verify SHA256 + ZIP/setup sanity, and support idempotent draft asset repair.

### Changed
- **CI always-emit Build x64/Win32 Release on PRs** — When classify sets `run_windows_build=false`, required Build jobs still run as ubuntu success no-ops (mirror Documentation Check) so Protect develop never treats SKIPPED Builds as unsatisfied; real MSBuild remains on `windows-2025-vs2026` when classify says build. See `docs/10_dev/CI_AUDIT_2026-09.md`.
- **Architecture / roadmap / status** — Document EnvyCore interface rule (no new MFC/Win32 types on portable core APIs), clarify CMake full-app vs portable-slice, and resolve the Windows-only vs multi-OS open question toward long-term multi-OS with Windows-first delivery.
- **CI PR `ready_for_review` + dispatch Format Check** — Build, Code Quality, PR Gate, Security, CodeQL, and Dependency review also run when a draft PR is marked ready. Format Check / Documentation Check can run on `workflow_dispatch` (Static Analysis stays push/schedule only).
- **DC hublist sources (2026-09)** — Default `DC.HubListURL` is `https://dchublist.org/hublist.xml.bz2`. `DefaultServices.dat` `H` rows use that URL plus HTTPS `hublist.pwiam.com` and `dchublist.ru`. Dead `dchublist.com` (HTTP-only, 301 to Team Elite) and `tankafett.biz` (timeout) are commented. Settings > Networks > DC++ > Download uses `CUpdateServersDlg` in hublist mode (no eDonkey/server.met copy). eDonkey `server.met` dialog text is unchanged. `ImportHubList()` still accepts `dchub://` and skips `adc://` / `adcs://`.
- **CI audit + micro-optimizations (2026-09)** — Documented measured PR/push timings and critical path in `docs/10_dev/CI_AUDIT_2026-09.md` (including Protect main API snapshot). Skip empty NuGet restore in `windows-msbuild` (~22s/job measured no-op), upload PR build logs only on failure, always emit required `Documentation Check` (classify no-op when out of scope; cancelled/superseded classify also no-ops success), keep PR Gate `POLL_SEC` at script default 15s (no faster override — Actions API quota), and record live Protect develop approval-count drift vs docs.

- **Bootstrap catalogues (2026-09-18)** — Refresh `Data/DefaultServices.dat` / `Data/DefaultServers.dat`: drop static ED2K IPs and dead GWC/hublists; HTTPS `server.met` (eMule-Security, shortypower) and DC hublists (dchublist.org/ru, Team Elite); gtk-gnutella UHCs; Transmission/libtorrent DHT routers. `CDHT::Connect` cold-start pings HostCache BT catalogue hosts instead of a hard-coded `router.bittorrent.com` DNS name. Kad remote `nodes.dat` is **not** added (Kad2 remains partial). See `docs/30_protocols/bootstrap-sources.md`.
- **Bootstrap catalogues (2026-09-18)** — Refresh `Data/DefaultServices.dat` / `Data/DefaultServers.dat`: drop static ED2K IPs and dead GWC/hublists; HTTPS `server.met` (eMule-Security, shortypower) and DC hublists (dchublist.org/ru, Team Elite); gtk-gnutella UHCs; Transmission/libtorrent DHT routers. `CDHT::Connect` cold-start sends BEP 5 `find_node` to HostCache BitTorrent hosts instead of a hard-coded DNS name. Kad remote `nodes.dat` is **not** added (Kad2 remains partial). See `docs/30_protocols/bootstrap-sources.md`.
- **CI CodeQL + Format gates** — Every PR to `develop` always runs CodeQL `Analyze (c-cpp)`, `Analyze (javascript-typescript)`, and `Analyze (csharp)` (no classify-changes dependency). Format Check uses pinned `clang-format-diff-18` on changed hunks only and fails closed on tooling/git errors. PR Gate requires `success` for must_pass (rejects `neutral` / unexpected `skipped`).
- **Format Check legacy encoding** — Format Check invokes `.github/scripts/clang-format-diff-safe` (binary/latin-1 I/O) so ISO-8859 first-party sources no longer crash stock `clang-format-diff` on copyright bytes (`0xA9`).
- **Protect develop review policy (docs + settings alignment)** — Document and template the live Protect develop gate: ≥1 GitHub APPROVED review, dismiss-stale reviews on push, `require_last_push_approval` off, required thread resolution, signed commits, force-push block, CodeQL+Gitleaks code scanning, no GitHub Code Quality ruleset rule. Remove Dependabot `gh pr review --approve`. PR Gate remains CI-only (not a review substitute).
- **CI lightweight job timeouts (#97)** — Add explicit `timeout-minutes` to Code Quality Format/Docs/Remote JS jobs (10–15m), Static Analysis (120m), Version Management (20m), and Copilot setup (60m). Required check names unchanged.
- **Agent autonomy policy** — `AGENTS.md` allows ready-for-review + squash auto-merge under explicit low-risk / high-risk evidence gates; adds a hard max of **3** open development PRs (Dependabot/Renovate excluded). See `docs/10_dev/devsecops-envy.md`.
- **Local ci-verify -Full** — Builds and runs EnvyTests Win32; fails if expected binaries are missing; requires `clang-format` on PATH (ci-fast may still warn-only when absent).
- **CodeRabbit** — Skip draft PRs (`drafts: false`); path instructions cover `Remote/**` assets and `Envy/*Remote*` C++ surface.
- **Renovate** — `enabledManagers` is `github-actions` only (no unused `regex` manager). Root config migrated from `renovate.json5` to `renovate.json` with `"forkProcessing": "enabled"` so Mend Renovate can process this fork (API pre-check only reads the default `renovate.json` filename).
- **Gnutella `{deflate}` QueryHit vs G1Packet sizing (#119)** — Documented as intentional Shareaza heritage, not a bug: `CQueryHit::ReadXML` uses `nSize - 10` because fixed `nXMLSize` includes a trailing NUL; `CG1Packet::ReadXML` uses `len - 9` because length stops before HIT_SEP/NUL. No wire-behavior change. Deduped `KNOWN_INCONSISTENCIES.md` entry.

### Security
- **NMDC `$ADCGET`/`$ADCSND` numeric parse (#81)** — Strict length-aware unsigned decimal offset/length (`DcAdcGetValidate.h`); embedded NULs rejected. `$ADCGET` length may be exactly `-1` (until-EOF); `$ADCSND` forbids `-1` and all-digits `2^64-1` (sentinel reserved). Fixed-length replies must match the request (no silent `min()` truncate in `CDownloadTransferDC::OnDownload`). EnvyTests smoke coverage.
- **Remote Stored XSS HTML escape (#76)** — `CRemote::Add()` HTML-entity-encodes substitution values via `Escape()` before `<% =key %>` output; peer-controlled filenames/nicks/agents/addresses are no longer injected raw. `AddRaw` reserved for trusted markup (filter `checked` attrs, pre-escaped schema `<option>` lists); `AddText` skin strings unchanged. `RemoteHtmlEscape.h` + EnvyTests smoke coverage.
- **Remote password PBKDF2-SHA256 (#79)** — New Remote passwords use `BCryptDeriveKeyPBKDF2` (HMAC-SHA256, 100k iterations, 16-byte salt, 32-byte DK) stored as `pbkdf2-sha256:<iters>:<saltB64>:<dkB64>`. Successful login migrates legacy 40-hex SHA1 (UTF-16LE heritage) and intermediate `sha256-salted:` hashes; Settings UI hashes on Apply/OK. Policy helpers in `RemotePasswordPolicy.h` with EnvyTests smoke coverage.
- **GitHub Actions SHA pinning (#96)** — External actions in `.github/workflows/` and `.github/actions/` are pinned to full commit SHAs (with `# vN` comments). Upgrade process documented in `docs/10_dev/agents-and-automation.md`.

### Fixed
- **NMDC file-list browse never loaded** — `CHostBrowser::OnNewFile` only handled DC file lists (`Files of <nick>.xml.bz2`); the previous inverted guard skipped every DC+nick download. `Browse(PROTOCOL_DC)` now sets `hbsConnecting`. File-list `$ADCGET` uses the protocol name `files.xml.bz2` instead of the library display name. Completion matches hub+port (download name includes `ip_port`, plus `dchub://` URL when present) so two hubs with the same nick do not steal each other’s lists. Private-chat Browse is enabled for a selected hub user (G1/G2 browse path unchanged). FileListing folders populate the Browse Host tree; hit names keep the directory path. The tree is built from the owned hit chain **before** `OnQueryHits` / `CNetwork` take ownership (avoids use-after-free). Empty directories still appear; directories count toward the 100k node cap; failed parses discard partial entries.
- **NMDC file-list browse never loaded** — `CHostBrowser::OnNewFile` only handled DC file lists (`Files of <nick>.xml.bz2`); the previous inverted guard skipped every DC+nick download. `Browse(PROTOCOL_DC)` now sets `hbsConnecting`. File-list `$ADCGET` uses the protocol name `files.xml.bz2` instead of the library display name. Completion matches hub+port (download name includes `ip_port`, plus `dchub://` URL when present) so two hubs with the same nick do not steal each other’s lists. Private-chat Browse is enabled for a selected hub user (G1/G2 browse path unchanged). FileListing folders populate the Browse Host tree; hit names keep the directory path.
- **NMDC file-list browse never loaded** — `CHostBrowser::OnNewFile` only handled DC file lists (`Files of <nick>.xml.bz2`); the previous inverted guard skipped every DC+nick download. `Browse(PROTOCOL_DC)` now sets `hbsConnecting`. File-list `$ADCGET` uses the protocol name `files.xml.bz2` instead of the library display name. Private-chat Browse is enabled for a selected hub user (G1/G2 browse path unchanged).
- **System/Network log top-aligned (`CTextCtrl`)** — Short journals paint from the top of the pane (empty space below); conventional scroll with follow-bottom only when already at the end; `HitTest`/keyboard navigation aligned with the new geometry.
- **G2 SGP UDP reassembly / inflate zip-bomb (#81)** — Cap SGP fragment count (64) on receive and send; enforce cumulative reassembled size in `CDatagramIn::Add` (before buffer copy) and `ToG2Packet` using `min(Settings.Gnutella.MaximumPacket, 256 KiB)` / `G2SgpEffectiveByteCap`; Inflate capped to the same budget so UDP G2 cannot bypass TCP `MaximumPacket`.
- **BitTorrent SourcesWanted re-enforced for PEX/source-exchange/tracker (#81)** — Stop `AddSourceBT` / tracker `m_pSources` growth once effective count reaches `Settings.Downloads.SourcesWanted` in `OnUtPex`, `OnSourceResponse`, tracker HTTP peer parse (dict + compact), HTTP apply, and UDP announce (`BtSourcesWantedAllowsMore`). Compact IPv4 peer blobs validated with `BtCompactPeerListBytesOk` in `OnUtPex`, HTTP compact peers, and UDP announce remaining payload (malformed non-multiple-of-6 rejected).
- **VersionChecker HTTP response size cap (#81/#82)** — Automatic version-check downloads use `LimitContentLength(VERSION_CHECK_HTTP_RESPONSE_MAX)` (64 KiB) and fail-closed oversize bodies (`VersionCheckerHttpResponseOk`) before key=value parse. Exact-limit (64 KiB) bodies are accepted; oversize still discard.
- **Update Servers HTTP response size cap (#81/#82)** — `CUpdateServersDlg` calls `LimitContentLength(UPDATE_SERVERS_HTTP_RESPONSE_MAX)` (32 MiB) and fail-closes oversize bodies before MET/hublist import (`UpdateServersHttpResponseOk`). `CHttpRequest` probes one byte past the cap via `InternetReadFile` so exact-limit bodies are kept while truncated/oversize responses are discarded (avoids the chunked `QueryDataAvailable`/`nMore==0` race).
- **Kademlia store-entry tag length cap (#81)** — Reject per-tag values above 4 KiB (`KadStoreTagLengthOk` / `KAD_STORE_TAG_MAX`) in `CKademlia::ReadEntryTags` before `vector` allocate (WORD×32 tags DoS).
- **BitTorrent MSE len(IA) fail-closed (#81)** — Cap responder `len(IA)` at 96 (`BtMseIaLengthOk` / `BT_MSE_IA_MAX`); stall in new `MSE_AWAITING_IA` until the full IA is buffered before `crypto_select` (avoids RC4 desync from partial IA / oversized WORD lengths).
- **BitTorrent MSE Pad_C/Pad_D receive cap (#81)** — Reject peer-advertised pad lengths above 512 (`BtMsePadLengthOk` / `BT_MSE_PAD_MAX` = `MSE_PAD_MAX_LEN`) before `new[]`/wait-for-bytes during MSE handshake. Decode/encode pad length fields as big-endian (`BtMseBeWordFromWire` / `BtMseBeWordToWire`) per Vuze MSE.
- **BitTorrent TCP length-prefix absolute cap (#81)** — Reject single-message length-prefixes above 16 MiB (`BtPacketLengthOk` / `BT_PACKET_LENGTH_MAX`) in `CBTPacket::ReadBuffer`; clear the input and close the peer (`IDS_PROTOCOL_TOO_LARGE`) instead of stalling forever on a multi-GB wait.
- **G2 HIT_WRAP embedded G1 length fail-closed (#81)** — Reject negative wrapped `GNUTELLAPACKET::m_nLength` in `CG1Packet::New` before `(DWORD)` cast/`Write`; `SeekToWrapped` uses `G1WrappedPayloadFits` (negative + 256 KiB ceiling + remaining) for G2→G1 conversion. Null-check `New()` at wrap call sites so HostBrowser `MaximumPacket*8` browse is unchanged.
- **G2 compound sub-packet length overflow (#81)** — Order-safe `G2SubpacketPayloadFits` / `G2FrameLengthFits` replace `remaining < body + prefix` checks in `CG2Packet::ReadPacket`, `SkipCompound`, and `ReadBuffer` (defense-in-depth; G2 wire lengths are 2-bit capped below DWORD max).
- **G1 QueryHit QHD XML size fail-closed (#81)** — Reject attacker-controlled `nXMLSize` that does not leave room for the trailing GUID (`G1QueryHitXmlFits`, including zero-length XML); replace soft clamp to 0 and the commented-out size check with `AfxThrowUserException` (same class as invalid public-size).
- **ED2K ViewSharedDirAnswer directory-name sync (#81)** — Consume the WORD-prefixed directory name before reading file `count` in browse-host answers (`Ed2kEdStringHeaderOk` / `Ed2kEdStringPayloadOk`); previously the skip was commented out so `count` was read from the string length/bytes. `OnViewSharedDir` / `OnAskSharedDirsAnswer` reject oversize directory strings fail-closed; `OnServerMessage` applies the same wire checks plus a 5000-byte MOTD cap (`Ed2kServerMessageLengthOk`) before `ReadEDString`.
- **ED2K chat MESSAGE length predicate (#81)** — `CEDClient::OnChatMessage` uses shared `Ed2kChatMessageLengthOk` (non-empty, `<= ED2K_CHAT_MESSAGE_MAX` / `ED2K_MESSAGE_MAX`, exact remaining fit) with EnvyTests smoke coverage; `CChatSession::SendPrivateMessage` clamps outgoing text by encoded wire byte length so UTF-8 frames stay within the max.
- **ED2K unknown-tag skip fail-closed (#81)** — Speculative STRING skip for unknown tag types no longer falls back to an INT-sized seek when a plausible length exceeds remaining (`Ed2kUnknownTagStringSkipOk`); INT fallback kept only when length exceeds the STRING heuristic max.
- **ED2K ReadEDString / ReadLongEDString fail-closed (#81)** — After reading the length prefix, reject when claimed payload exceeds remaining (`Ed2kEdStringPayloadOk` / `Ed2kLongEdStringPayloadOk`) via `AfxThrowUserException` instead of silently clamping in `ReadString*`.
- **GGEP DEFLATE inflate output cap (#81)** — `CGGEPItem::Inflate` passes `GGEP_INFLATE_MAX` (256 KiB) into `CZLib::Decompress` and rejects empty/oversize output (`GgepInflateOutputOk`); closes uncapped zip-bomb path on inbound GGEP items.
- **CBuffer InflateStreamTo default output cap (#81)** — `InflateStreamTo` with `nMaxOutput=0` now applies `CBUFFER_INFLATE_STREAM_MAX` (32 MiB, alias of `CBUFFER_INFLATE_MAX`) so Neighbour G1/G2 `Content-Encoding: deflate` cannot grow an unbounded uncompressed backlog; HostBrowser may still pass an explicit smaller cap. G1/G2/ED/DC `OnRead` propagates inflate failure so the connection closes instead of buffering forever.
- **CBuffer Inflate/Ungzip default output cap (#81)** — `CBuffer::Inflate`/`Ungzip` with `nMaxOutput=0` now apply `CBUFFER_INFLATE_MAX` (32 MiB) via `Decompress2` / growth clamps (`CBufferInflateOutputOk`); closes unlimited datagram/legacy CBuffer inflate zip-bombs while callers may still pass an explicit smaller cap.
- **ED2K FileComment length guards (#81)** — `OnFileComment` requires rating+length header and rejects claimed comment lengths above `ED2K_FILE_COMMENT_MAX` or remaining payload (`Ed2kFileCommentHeaderFits` / `Ed2kFileCommentLengthOk`); fail-closed instead of clamp-then-truncate.
- **ED2K wire TAG_BLOB absolute size cap (#82)** — Packet-path `CEDTag::Read` now uses `Ed2kTagBlobLengthOk` (4 MiB + remaining) instead of remaining-only checks, matching `.met` / collection TAG_BLOB policy. Oversized peer-advertised blobs fail closed.
- **BitTorrent source-response double-free (#92)** — `CDownloadTransferBT::OnSourceResponse` no longer `delete`s `pPacket->m_pNode` when `peers` is missing/non-list (packet owns the node); null-guard `pRoot`/`pPeers` and nested peer nodes before `IsType`.
- **ED2K wire TAG_UINT64 remaining check (#81)** — `CEDTag::Read` required only 1 remaining byte before `ReadInt64()`; now requires 8 via `Ed2kTagUint64RemainingOk` (+ EnvyTests). Fail-closed on truncated packets.
- **Network async job queue cap (#81)** — `CNetwork::m_oJobs` drops oldest owned search/hit trees once depth reaches 2048 (`NETWORK_JOB_QUEUE_MAX` / `EnqueueJob`); `RunJobs` requeues retained jobs through `EnqueueJob` so the cap holds across the unlock window.
- **Chat session undelivered queue cap (#81)** — `CChatSession::m_pMessages` drops oldest owned payloads once depth reaches 1024 (`CHAT_SESSION_QUEUE_MAX` / `EnqueueMessage`) so wire chat floods cannot grow forever when no private window drains the queue.
- **NMDC hub user-list size cap (#81)** — `CDCNeighbour::OnUserInfo` refuses new `$MyINFO` nick inserts once `m_oUsers` reaches 20,000 (`DcHubUserCountOk` / `DC_HUB_USERS_MAX`); existing nick updates still apply.
- **CBuffer UnBZip output cap (#81)** — DC hublist / file-listing loaders use `LoadFromBZipFile` with a 32 MiB decompress cap (`CBUFFER_UNBZIP_MAX`); oversized compressed input is rejected (`CBufferUnBZipInputOk`). Legacy `UnBZip()` with `nMaxOutput=0` remains unlimited.
- **G1 `{deflate}` XML inflate cap (#81)** — `CQueryHit::ReadXML` and `CG1Packet::ReadXML` pass `G1_DEFLATE_XML_INFLATE_MAX` (256 KiB) into `CZLib::Decompress` and reject empty/oversize output (`G1DeflateXmlInflateOk`); closes uncapped zip-bomb path on QueryHit metadata.
- **Gnutella QHT patch inflate zip-bomb (#81)** — Cap compressed QRP/QHT fragment accumulation (`QhtPatchCompressedBudgetOk`) and pass expected patch size to `CBuffer::Inflate(nMaxOutput)` before applying patches (`QueryHashTable::OnPatch`).
- **ED2K packed-protocol inflate cap (#81)** — `CEDPacket::Inflate` defaults to / enforces `ED2K_PACKED_INFLATE_MAX` (512 KiB) for EMULE/KAD/REVCONNECT packed packets (`Ed2kPackedInflateOk`); closes unlimited C2C/UDP inflate zip-bomb while matching the prior server-path guard.
- **BitTorrent tracker HTTP response size cap (#81/#82)** — `CBTTrackerRequest::ProcessHTTP` calls `LimitContentLength(BT_TRACKER_HTTP_RESPONSE_MAX)` (32 MiB) so `CHttpRequest::OnRun` stops buffering hostile announce/scrape bodies before inflate; post-inflate length checked with `BtTrackerHttpResponseOk`.
- **Discovery GWC/server-list HTTP response size cap (#81/#82)** — `SendWebCacheRequest` calls `LimitContentLength(DISCOVERY_HTTP_RESPONSE_MAX)` (32 MiB) and fail-closes on oversize buffered bodies (`DiscoveryHttpResponseOk`); `RunServerList` null/size-checks before `CMemFile` copy.
- **Browse Host HTTP body size cap (#81/#82)** — Reject peer `Content-Length` above 32 MiB (`HostBrowserHttpBodyOk`); require a full decimal Content-Length (no trailing junk); cap reassembled/deflated browse buffers before allocation (`HostBrowserHttpBufferOk` + `InflateStreamTo` nMaxOutput); close-delimited totals use `m_nReceived + GetInputLength()`.
- **ED2K COMPRESSEDPART stream inflate cap (#81)** — `OnCompressedPart` / `OnCompressedPart64` share `AcceptCompressedPartChunk` (`Ed2kCompressedPartInflateBudget` / `Ed2kCompressedPartInflateOk`) to reject uncompressed output past one ED2K part or remaining file size (zero at EOF) before `SubmitData`; `CEDClient::OnPacket` propagates rejection so `OnRead` stops. Closes streaming zip-bomb into the download (`ED2K_C2C_COMPRESSEDPART` / `ED2K_C2C_COMPRESSEDPART_I64`).
- **G1 packet length overflow-safe framing (#81)** — `CG1Neighbour::ProcessPackets` validates signed payload length with `G1PacketTotalLengthOk` before `header + payload` (reject negative / wrap vs `MaximumPacket`).
- **Gnutella1 UDP packet length overflow (#81)** — Reject negative / oversize `GNUTELLAPACKET::m_nLength` on the UDP datagram path (`G1PacketTotalLengthOk` / `G1PacketTotalLength`) before `sizeof + signed` equality and `CG1Packet::New` Write (closes the TCP-only gap of the G1 neighbour framing fix).
- **ED2K .met TAG_STRING / tag-key length bounds (#81/#82)** — `CEDTag::Read(CFile*)` rejects WORD-prefixed key and `ED2K_TAG_STRING` values that exceed remaining file bytes before allocate/Read (`Ed2kTagStringLengthOk`); empty strings accepted. Complements existing TAG_BLOB / hashset caps.
- **Windows Firewall WFAS migration (#166)** — Replace XP-era `INetFwMgr`/`INetFwPolicy`/`INetFwProfile` with `INetFwPolicy2` rules API. Application exceptions use inbound allow rules on Domain+Private+Public; UPnP uses WFAS rule-group enable; `AreExceptionsAllowed` consults BlockAllInboundTraffic on every currently active profile. `FirewallWfasPolicy.h` + EnvyTests smoke coverage.
- **BitTorrent BEP-9 ut_metadata size cap (#82)** — Reject peer-advertised `metadata_size`/`total_size` above 32 MiB and refuse `LoadInfoPiece` for oversize info dicts (`BtUtMetadataSizeOk`).
- **Cooperative thread close without TerminateThread (#92)** — `CEnvyThread::CloseThread` abandons timed-out threads after cancel instead of `TerminateThread` (`EnvyThreadPolicy.h`); `throw()` → `noexcept`.
- **ED2K EDClients-before-Transfers lock order (#92)** — Canonical order `EDClients.m_pSection` then `Transfers.m_pSection` (`Ed2kLockOrder.h`); fix inverted acquisition in `CEDClients::OnAccept`, UDP C2C path, and `CHostBrowser::Browse`.
- **ED2K CryptLayer Hello honesty (#121)** — Confirm MiscOptions2 CryptLayer bits mean TCP protocol obfuscation (not PUBLICKEY packet RC4). Keep Hello advertise at 0; peer Hello crypt bits no longer start PUBLICKEY; peer flag defaults FALSE until Hello. Policy helpers + smoke tests extended.
- **NMDC HubName/HubTopic/chat length underflow (#81)** — Reject frames that would underflow `nLength - prefix - 1` (trailing `|`) before `UTF8Decode` in chat and hub-name parsers; shared predicates in `DcPacketLengthValidate.h` with EnvyTests smoke coverage.
- **Portable ZIP incomplete runtime tree** — Release packaging no longer flattens only `*.exe`/`*.dll` into the ZIP. `stage-portable.ps1` mirrors the Inno install layout (`Envy.exe` + service DLLs at root, plugins under `Plugins\`, plus `Data\`/`Schemas\`/`Skins\`/`Skins\Languages\`/`Templates\`/`Remote\`). `verify-artifacts.ps1` fails flattened or resource-less ZIPs.
- **Release draft asset upload race** — Tag-push packaging no longer uses parallel `softprops/action-gh-release` uploads against a freshly created draft (that failed mid-upload with `Error saving asset` and left Preview 1 missing x64 assets). Uploads now run sequentially via GitHub API against the concrete `release_id`, skip/replace assets idempotently, verify the final remote set, and never auto-publish (`draft` stays true). `workflow_dispatch` remains a dry-run unless `repair_release_id` is set explicitly.

## [4.1.0] - 2026-01-11

### Added
- **Release preparation** (`4012a89`) - Version 4.1.0 milestone preparation
- **Development infrastructure** - Enhanced tooling and build systems
- **C++17 migration** - Modern language standard adoption
- **Security enhancements** - Vulnerability fixes and protection measures
- **Protocol improvements** - Enhanced ED2K and Kademlia support
- **Build automation** - CI/CD pipeline improvements
- **Code quality tools** - Static analysis and formatting utilities

### Changed
- **Build system modernization** - CMake integration and multi-platform support
- **Code organization** - Improved structure and maintainability
- **Development workflows** - Enhanced processes and automation

## [4.0] - 2025-01-01

### Added
- Major architectural improvements and modernization
- Enhanced protocol support and network capabilities
- Improved user interface and user experience
- Extended plugin system capabilities
- Better error handling and stability improvements

### Changed
- Significant codebase refactoring and cleanup
- Updated dependency management
- Improved performance and memory usage
- Enhanced security features

### Fixed
- Various stability and performance issues
- Protocol compatibility improvements
- User interface bugs and inconsistencies

## [3.0] - 2024-01-01

### Added
- Advanced BitTorrent support and optimizations
- Enhanced Kademlia DHT implementation
- Improved search and discovery mechanisms
- Extended media library capabilities
- Better internationalization support

### Changed
- Major user interface redesign and improvements
- Enhanced network protocol handling
- Improved file management and organization
- Better resource utilization

### Fixed
- Memory leaks and resource management issues
- Network connectivity problems
- File sharing and transfer reliability issues

## [2.0] - 2023-01-01

### Added
- Multi-protocol support (Gnutella2, eDonkey2000, BitTorrent)
- Advanced chat and community features
- Plugin architecture for extensibility
- Improved download management and queuing
- Enhanced security and privacy features

### Changed
- Complete user interface overhaul
- Improved network performance and stability
- Better file organization and management
- Enhanced search capabilities

### Fixed
- Numerous stability and compatibility issues
- Network protocol bugs
- User interface responsiveness problems

## [1.0.0.0] - 2022-01-01

### Added
- Initial release of Envy P2P client
- Basic file sharing functionality across multiple networks
- Support for Gnutella, eDonkey, and BitTorrent protocols
- User interface with tabbed browsing and search
- Basic download management and queuing system
- Network connectivity and peer discovery
- Simple chat functionality
- Basic media library and file organization
- Plugin system foundation
- Configuration and settings management
- Basic security features and IP filtering

### Changed
- Project structure and organization
- Codebase refactoring from PeerProject foundation
- Build system improvements
- Documentation and licensing updates

## [1.0.0.0.Pre] - 2021-12-01

### Added
- Pre-release development and testing
- Core P2P functionality implementation
- Network protocol integration
- Basic user interface components
- Foundation for plugin system

### Changed
- Initial project setup and configuration
- Codebase preparation for public release

## [0.x] - 2021-01-01 to 2021-11-30

### Added
- Project foundation as fork of PeerProject
- Initial codebase migration and cleanup
- Basic build system setup
- Core networking infrastructure
- Protocol handler implementations
- User interface framework
- Basic file sharing capabilities

### Changed
- Codebase modernization and refactoring
- Project rebranding from PeerProject to Envy
- Build system improvements
- Documentation updates

---

## Project History

### Origins (Pre-2021)
Envy originated as a fork of **PeerProject**, which was itself derived from the **Shareaza** P2P client. The project represents a continuation of the open-source P2P file sharing tradition with a focus on modernizing the codebase and improving user experience.

### Development Evolution
The project has undergone significant evolution based on git commit history:

- **2016**: Initial development by SkinVista - Project foundation and basic P2P functionality (r1-r42)
- **2017**: Continued development with feature additions and bug fixes (r16-r20)
- **2018**: Additional releases and maintenance (r21)
- **2020**: Major version milestone (4.0) - Significant architectural improvements (r34-r42)
- **2026**: Modernization phase - Complete codebase transformation:
  - **January 2026**: Major development push with Kademlia DHT, AI integration, and security fixes
  - **4.1.0 Release**: Enhanced development infrastructure and tooling
  - **Current development**: Ongoing improvements and new features

### Technical Improvements (2026)
- **Kademlia DHT implementation**: Complete distributed hash table with routing and peer discovery
- **C++17 modernization**: Rule of Five implementation, smart pointers, modern language features
- **Security enhancements**: CVE-2025-8088 vulnerability fix, improved file extraction validation
- **Build system evolution**: CMake support, multi-platform CI/CD (x64/Win32), automated testing
- **Development tooling**: Clang/CppCheck integration, PowerShell automation scripts, AI-assisted development
- **Protocol enhancements**: Source Exchange v2, MultiPacketExt2, KADEMLIA2 support
- **Code quality**: Static analysis, automated formatting, comprehensive testing infrastructure
- **Dependency management**: SQLite/zlib updates, enhanced version checking and reporting

### Protocol Support Evolution
- **2016-2020**: Core P2P protocols (Gnutella, eDonkey, BitTorrent) - Basic multi-network support
- **2026 Q1**: Major protocol enhancements:
  - **ED2K/eDonkey2000**: FileIdentifier, HashsetRequest2, MultiPacket Ext2, AICH support, CryptLayer/SecureID preparation
  - **Kademlia DHT**: Complete implementation with routing, node management, and KADEMLIA2 protocol
  - **Source Exchange**: Version 2 implementation with enhanced peer discovery
  - **Security**: CryptLayer negotiation preparation, SecureID support preparation, enhanced authentication
  - **Code Quality**: Improved packet reading, case-insensitive search filtering
- **Current**: Advanced multi-protocol P2P client with modern DHT, enhanced security preparation, and improved user experience

## Detailed Commit History (2020-2026)

### 2026 Development Phase
- `XXXXXXX` (2026-01-15) - Code quality improvements: packet reading robustness, case-insensitive search
- `XXXXXXX` (2026-01-15) - ED2K CryptLayer and SecureID framework preparation
- `e3ae644` (2026-01-15) - FileIdentifier class and hashset request handling
- `c9b5966` (2026-01-15) - Complete Kademlia DHT implementation and integration
- `63eb0e7` (2026-01-15) - README.md CI/CD capabilities documentation
- `b61e4b0` (2026-01-15) - Comprehensive CI/CD automation and GitHub configuration
- `5779b77` (2026-01-14) - zlib compression and decompression test implementation
- `35b37a1` (2026-01-14) - .gitignore updates and code refactoring
- `e92d930` (2026-01-13) - CVE-2025-8088 security merge
- `eaab22e` (2026-01-13) - CVE-2025-8088 directory traversal protection in UnRAR
- `ad3bd40` (2026-01-13) - AICH/CryptoProvider headers and development agents documentation
- `5314409` (2026-01-12) - SQLite and zlib component updates
- `3de8ce2` (2026-01-12) - GitHub Actions multi-platform support and Rule of Five implementation
- `e870aa8` (2026-01-12) - Source Exchange v2 and MultiPacketExt2 support
- `c82e405` (2026-01-12) - KADEMLIA2 protocol support and validation
- `a818143` (2026-01-12) - Development tools configuration (Clang, CMake, CppCheck)
- `4012a89` (2026-01-11) - Release 4.1.0 preparation

### 2020 Legacy Phase (Eric)
- `43787f3` (2020-03-18) - Release r42
- `cd4c78a` (2020-02-13) - Release r41
- `510a28f` (2020-01-21) - Release r40 (Version 4.0)
- `c67bd17` (2020-01-21) - Release r39
- `29923e1` (2020-01-20) - Release r38
- `8f6af14` (2020-01-18) - Release r37
- `dfad434` (2020-01-04) - Release r36
- `540cd2d` (2020-01-04) - Release r35
- `3aa4e6e` (2020-01-02) - Release r34

### 2016-2018 Development Phase (SkinVista)
- Multiple releases from r1 to r21 focusing on core P2P functionality, UI improvements, and bug fixes
- `091f444` (2016-04-02) - Initial commit establishing project foundation

For the complete git history with file changes and full commit details, please refer to the git repository.
