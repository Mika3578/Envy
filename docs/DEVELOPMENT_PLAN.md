# DEVELOPMENT PLAN (LIVING)

> **LIVING DOCUMENT** — Must be updated after every meaningful change (feature, architectural decision, scope change, blocker resolution).

- **Last Updated:** 2026-09-18
- **Changelog Entry:** 2026-09-18 — Protect develop docs aligned to live ruleset: ≥1 APPROVED review, dismiss-stale on push, `require_last_push_approval` off, signed commits + force-push block, CodeQL/Gitleaks code scanning, no GitHub Code Quality rule; Dependabot auto-approve removed.
- **Changelog Entry:** 2026-09-18 — #81/#82: file-backed ED2K tag key / TAG_STRING lengths checked against remaining `.met` bytes (`Ed2kTagStringLengthOk`) before allocate/Read.
- **Changelog Entry:** 2026-09-18 — #166 / D-009 P1: Windows Firewall exceptions via WFAS `INetFwPolicy2` (all Domain/Private/Public profiles); drop legacy `INetFwMgr`.
- **Changelog Entry:** 2026-09-18 — #76: Remote UI HTML-escapes `CRemote::Add()` substitutions (`Escape`); `AddRaw` for trusted markup; `RemoteHtmlEscape.h` + EnvyTests smoke coverage.
- **Changelog Entry:** 2026-09-18 — #82 partial: BEP-9 ut_metadata advertised size capped at 32 MiB (`BtUtMetadataSizeOk`) before accepting metadata pieces.
- **Changelog Entry:** 2026-09-18 — #79: Remote passwords stored with PBKDF2-HMAC-SHA256 (`BCryptDeriveKeyPBKDF2`); legacy SHA1 / sha256-salted verify + migrate on login.
- **Changelog Entry:** 2026-09-18 — #92 cooperative close: abandon timed-out threads without `TerminateThread` (`EnvyThreadPolicy.h`); completes remaining #92 slice after lock-order.
- **Changelog Entry:** 2026-09-18 — #92 lock-order: EDClients before Transfers (`Ed2kLockOrder.h`); remaining #92 item is cooperative thread close without `TerminateThread`.
- **Changelog Entry:** 2026-09-18 — #121: CryptLayer Hello bits stay 0 (TCP obfuscation unimplemented); peer Hello crypt bits no longer start PUBLICKEY packet crypto (`Ed2kCryptLayerHelloBitsMayStartPacketCrypto`).
- **Changelog Entry:** 2026-09-18 — DevSecOps finalize: `AGENTS.md` controlled autonomy + max-3 development PR cap; Renovate `enabledManagers` = github-actions only; CodeRabbit `drafts: false` + `Envy/*Remote*` path; `ci-verify.ps1 -Full` builds/runs Win32 EnvyTests and requires clang-format; Merge Queue documented as optional.
- **Changelog Entry:** 2026-09-18 — #96: pin external GitHub Actions to immutable commit SHAs under `.github/workflows` and `.github/actions` (documented upgrade path in `docs/10_dev/agents-and-automation.md`).
- **Changelog Entry:** 2026-09-18 — Restored historical `CHANGELOG.md` body truncated by #148 squash (kept current Unreleased; reattached from `## [4.1.0]` onward).
- **Changelog Entry:** 2026-09-18 — #81: NMDC HubName/HubTopic/chat prefixed-payload length guards before trailing-`|` arithmetic (`DcPacketLengthValidate.h` + EnvyTests).
- **Changelog Entry:** 2026-09-18 — Restored full `docs/DEVELOPMENT_PLAN.md` body accidentally truncated by #159 squash; retained post-#147/#153 changelog lines and #119 `{deflate}` resolution note.
- **Changelog Entry:** 2026-09-17 — #119: QueryHit `nSize-10` vs G1Packet `len-9` `{deflate}` sizing documented as intentional (trailing NUL vs HIT_SEP framing); no wire change.
- **Changelog Entry:** 2026-09-17 — #92 slice: Remote Base64 empty-input safety (`RemoteBase64.h`), CHM `LocalAlloc`/`LocalFree` pairing, TorrentEnvy clipboard wide-NUL size. #92 TerminateThread and lock-order slices delivered.
- **Changelog Entry:** 2026-09-17 — Portable ZIP staging now mirrors the Inno runtime tree (`stage-portable.ps1`: `Data`/`Skins`/`Schemas`/`Plugins`/…); flattened EXE/DLL-only ZIPs are rejected by `verify-artifacts.ps1`.
- **Changelog Entry:** 2026-09-17 — Hardened `release.yml`: replaced parallel `softprops/action-gh-release` asset uploads with idempotent sequential `gh api` uploads by `release_id` (`scripts/release/*`); draft stays unpublished; `workflow_dispatch` remains dry-run unless explicit `repair_release_id`.
- **Changelog Entry:** 2026-09-17 — #120: ED2K preview frames capped at 4 MiB and written with a bounded bulk copy (`Ed2kPreviewFrameAcceptable`).
- **Changelog Entry:** 2026-09-17 — #77: Remote CSRF enforced for mutating query keys (`connect`/`disconnect`, filters, group/queue UI actions); `_method` no longer bypasses CSRF.
- **Changelog Entry:** 2026-09-17 — #141: listen sockets open before NAT completes (`OnRun` no longer waits on `IsAsyncFindRunning`); `MapPorts` starts after successful bind/listen (D-011).
- **Changelog Entry:** 2026-09-17 — #78 security: remove weak `rand()` fallbacks for session/CSRF/salt and protocol anti-spoof nonces; single CSPRNG helper (`SecureRandom.h` / `BCryptGenRandom`) with fail-closed contracts. Out of scope: #79 PBKDF2, #77 CSRF policy, #76 XSS.
- **Changelog Entry:** 2026-09-17 — #140 docs: clarify MiniUPnPc 2.0 SSDP is one discovery receive phase (`searchalltypes=1`), not a strict wall-clock deadline; #142 / P3 covers absolute SSDP and HTTP timeout bounding.
- **Changelog Entry:** 2026-09-17 — #140 P0 runtime PASS on post-squash HEAD: targeted IGD discovery (single MiniUPnPc receive phase), gateway-only rootdevice fallback, non-IGD devices never receive WAN mapping commands. Known debt: MiniUPnPc 2.0 SSDP/HTTP latency (#142 / P3). Listen-before-NAT delivered as #141. Next after #166 WFAS: P2 ports.
- **Changelog Entry:** 2026-09-17 — #140 P0 strategy: targeted IGD SSDP (`searchalltypes=1`, one discovery receive phase) + gateway-only rootdevice fallback. SSDP success != usable IGD; discovery fails cleanly when no IGD/WAN service is exposed.
- **Changelog Entry:** 2026-09-16 — UPnP SSDP discovery selects Internet-facing IPv4 via `GetAdaptersAddresses` + `GetBestRoute2` (`NetworkInterfaceSelector`), replacing `GetAdaptersInfo` fallback on PR #140. Phased NAT/Firewall plan: P0 interface → P1 WFAS firewall → P2 local/external ports → P3 MiniUPnPc 2.3.x vendored → P4 PCP/NAT-PMP → P5 CGNAT/diagnostics. MiniUPnPc stays vendored (not vcpkg-only) for now.
- **Changelog Entry:** 2026-09-16 — Started **Envy 4.2.0 Preview 1** release preparation: single version source (`4.2.0-preview.1` / Windows `4.2.0.1`), Inno `alpha` driven from CI (`/p:InstallerAlpha=Preview`), `release.yml` publishes per-platform setup + ZIP + `SHA256SUMS.txt` as draft prerelease. Universal installer and Authenticode deferred. See README Preview section. (Still gated on interactive installer smoke before merge; includes #139 WebHook BHO fix.)
- **Changelog Entry:** 2026-09-16 — Fixed legacy IE WebHook startup registration: skip `WebHook32.dll`/`WebHook64.dll` (and historical `WebHook.dll`) when `WebHookEnable` is false; BHO key registered in code under HKCU (per-user) or HKLM (machine). Documented as IE-only legacy; candidate for removal in favor of a modern browser extension + `envy://url:`.
- **Changelog Entry:** 2026-09-16 — Search Input/Advanced panel layout is font/DPI-aware (`GetPreferredHeight` + progressive Y); combo drop-down height kept separate from visible stacking; hash/prefix anchored to the search edit. No change to `GetSearchPanelWidth()` / SidebarWidth floor.
- **Changelog Entry:** 2026-09-16 — Skin engine P0: StatusbarHeight pointer fix, ParseRect point/size + FindOneOf, roundRect size validation, LoadFromXML section-failure aggregation (non-transactional), strict metric parse/clamp aligned with Settings bounds; `SkinEngineP0.h` + EnvyTests. HiDPI/logical units deferred to P1+.
- **Changelog Entry:** 2026-09-16 — Search window left panel clamps to `max(SidebarWidth, SCALE(200))` only in `CSearchWnd` (Shareaza PANEL_WIDTH); avoids Advanced two-column collapse without raising the global SidebarWidth floor used by other panes / ~182 px PeerProject skins.
- **Changelog Entry:** 2026-09-16 — Fixed CoolMenu selected-item double blue band: `DrawButton`/`DrawButtonMap` stretch one skin state vertically (no vertical tile) when destination height exceeds asset height; CoolMenu `rcItem` stays within `DRAWITEMSTRUCT` and icon offsets use `SCALE()`.
- **Changelog Entry:** 2026-09-15 — Deterministic `About.htm.gz` / `Browser.htm.gz` generation (`gzip -n`), restore valid binary blobs, `*.gz binary` in `.gitattributes`. See `docs/10_dev/build.md`.
- **Changelog Entry:** 2026-09-15 — Added Envy self-golden Hello/HelloAnswer TCP vectors (`Ed2kHelloWire.h` + EnvyTests) freezing honest MiscOptions bits; compression advertise left frozen for post-interop decision. No wire behavior change.
- **Changelog Entry:** 2026-09-15 — Reconciled status/roadmap: live Kad2 is `Kademlia.cpp` only (`KadProtocol` legacy inactive); SEARCH/PUBLISH wire-only; ADC/ADCS hub not implemented (NMDC preserved). Prevents roadmap drift from the September 2026 current-code audit.
- **Changelog Entry:** 2026-09-15 — ED2K Hello honesty: stop advertising Ext Multipacket (MiscOptions2 bit 5) until 0x92/0xA4 (or wired Ext2) handlers exist; `Ed2kExtMultipacketAdvertised()` + smoke tests.
- **Changelog Entry:** 2026-09-15 — Keep C++ RTTI disabled (`/GR-`). `CUploadQueue::StartImpl` uses a construction-proven `static_cast` instead of `dynamic_cast` for ED2K uploads. Future protocol actions should move to virtual methods; do not enable global RTTI.
- **Changelog Entry:** 2026-09-15 — Fixed ED2K regression: `CEDPacket::WriteFile` no longer uses `dynamic_cast` (Envy builds with `/GR-`, so it crashed in `__RTDynamicCast` during `SendSharedFiles`); restored the historical `static_cast` contract (complete files are always `CLibraryFile`). No RTTI enablement.
- **Changelog Entry:** 2026-09-13 — Fixed Debug splash assertion: `nSplashSteps` now accounts for the conditional `Kademlia DHT` step when `eDonkey.EnableKad` is enabled (miscount since Kad init splash was added; surfaced after EnableKad defaulted true).
- **Changelog Entry:** 2026-09-11 — Documented external P2P reference implementations (eMule Community, aMule, eMule Qt, eMule AI, aria2-next, Ember, Rucio, eMule eSE), Envy’s multi-network positioning, specification-first policy (D-008), and the P0–P3 interoperability/architecture sequence. Restored the missing `docs/10_dev/status.md` matrix. Corrected remaining SecureIdent “active/complete” claims: RSA SecureIdent is not implemented (#75).
- **Changelog Entry:** 2026-09-10 — Runtime performance audit backlog: reproducible benchmarks (#111), then CBuffer front-consume (#112), network hot-path copies/locks (#113), TransferFiles I/O contention (#114). IOCP and dedicated hashing optimization deferred pending evidence. #102 remains CI runner latency only.
- **Changelog Entry:** 2026-09-10 — Two-speed GitHub Actions: change-aware PR
  gate (skip Windows/CodeQL/Remote/C# when unrelated), CodeQL C++ `build-mode: none`
  on PRs with full manual analysis on `develop`/weekly, vcpkg files binary
  cache (Win32 included; `x-gha` is gone upstream), differential Format Check, clang-tidy moved off PRs, EnvyTests after
  MSBuild. Live required check names include Format, Documentation, secret-scan,
  gitleaks, PR Gate, Analyze (c-cpp), and SonarCloud (see `.github/settings.yml`).
  `PR Gate` is a required CI wait job; it does not replace GitHub review rules.
- **Changelog Entry:** 2026-09-10 — Safely disabled invalid ED2K/eMule SecureIdent verification (#75): no SecureIdent advertisement, no MD5/non-zero accept path, peers never marked verified without future RSA validation. Documented ED2K SecureIdent RSA roadmap and separate ED2K/Kad interop checklists. SecureIdent remains authentication/trust only — not required for ED2K connectivity.
- **Changelog Entry:** 2026-09-08 — Restored inbound packet length validation (closed PR #69) on current `develop`: ED2K `ReadBuffer`, BitTorrent extension framing, Gnutella QueryHit `{deflate}`, GGEP `H`/`M` type-byte guards, and ED2K preview frame unsigned bounds. Shared predicates in `PacketLengthValidate.h` with EnvyTests smoke coverage. Documented QueryHit vs G1Packet `{deflate}` -10/-9 sizing as a known inconsistency (functional follow-up, not fixed here).
- **Changelog Entry:** 2026-05-27 — Documented linear-history workflow for `develop`: squash/rebase merges only, `git pull --ff-only`, feature-branch rebase commands; aligned `.github/settings.yml` with GitHub merge settings.
- **Changelog Entry:** 2026-05-17 — Improved CodeQL C# analysis precision by introducing a dedicated manual-build workflow and documenting legacy FictionBookReader build blockers plus minimal .NET Framework 4.8 retarget path.
- **Changelog Entry:** 2026-05-15 — Synced repository hygiene status for `develop`: documented branch state, CI gate maturity, Dependabot labels requirement, and dependency register status (`docs/DEPENDENCIES.md` exists but remains an incomplete seed).
- **Changelog Entry:** 2026-05-15 — Hardened legacy Kad publish packet construction by replacing unsafe keyword copy with bounded copy and explicit terminator in `KadProtocol::CreatePublishRequest`, preserving wire format.

- **Changelog Entry:** 2026-05-15 — ED2K Source Exchange hardening: added shared bounds validation for SourceEx/SourceEx2 source lists, modernized SourceEx2 request length handling, and documented current IPv4-only SourceEx wire limitation.

## Update Protocol
1. Update **Last Updated** date on every meaningful change.
2. Add a one-line entry to the changelog section above.
3. Reflect status changes in **Current Status** and **Roadmap**.
4. Record consequential technical decisions in **Decisions Log**.
5. Close or refresh **Open Questions** explicitly.

## Repository Status (develop)
- Default branch is `develop`.
- `main` is currently behind `develop`.
- **Merge policy (GitHub):** merge commits disabled; squash and rebase merges
  enabled globally. Protect develop forces **squash-only** onto `develop`.
- **History:** `develop` was rewritten to a linear history with no merge commits; the pre-rewrite snapshot is preserved as the immutable tag `backup/develop-before-linear-rewrite` (local mutable backup/rollback branches were removed after the rewrite stabilized).
- **Local hygiene:** use `git pull --ff-only` on `develop`; rebase feature branches with `git rebase origin/develop` and `git push --force-with-lease`.
- **Branch protection:** the active `Protect develop` ruleset requires pull
  requests, linear history, signed commits, ≥1 APPROVED review, dismiss-stale
  approvals, conversation resolution, code scanning (CodeQL+Gitleaks), passing
  required checks, and blocks force-pushes/deletions. `.github/settings.yml`
  mirrors the Probot-capable subset; the ruleset is the source of truth.
- CI uses a two-speed model: change-aware PR jobs plus full integration on
  `develop` / scheduled analysis. The live `Protect develop` ruleset requires
  the eleven named contexts listed in `.github/settings.yml` (including
  Documentation Check, gitleaks, PR Gate, and SonarCloud). `PR Gate` waits for
  classified CI only — it is not a review substitute. See
  `docs/10_dev/agents-and-automation.md`.
- Dependabot expects GitHub labels `ci` and `dependencies` to exist for automated PR labeling.

## Canonical Documentation Split
- `docs/DEVELOPMENT_PLAN.md`: strategic roadmap, major decisions, and sequencing (this file).
- `docs/10_dev/status.md`: protocol/architecture status matrix (evidence-based; no “complete” without proof).
- `docs/10_dev/roadmap.md`: technical modernization itemization aligned with the P0–P3 sequence below.
- `docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md`: external P2P reference projects and spec-first policy.
- `.local/DEV_TRACKER.md`: session notes (gitignored). `docs/DEV_TRACKER.md` is also gitignored and is not a committed source of truth.

## Vision & Goals
- Keep Envy a stable **Windows-native multi-network** client: BitTorrent, Gnutella, Gnutella2, ED2K, Kad, Direct Connect, Remote/Web, plus library and multi-network search.
- Improve ED2K/Kad interoperability against eMule Community and aMule without dropping other networks.
- Reduce modernization risk with incremental core/UI boundaries, testability, and dependency hygiene.
- Increase release confidence through clearer architecture boundaries and measurable quality gates.

## Positioning
Envy is not an eMule fork and is not replaced by aMule, eMule Qt, aria2-next, Ember, or Rucio. Those projects are **references**:

- ED2K/Kad behaviour: eMule Community and aMule
- core/UI split: eMule Qt (incremental, not a rewrite)
- modern reachability: eMule AI
- engine/API/headless: aria2-next
- DHT/security research: Ember (Envy-specific extensions only; never labelled Kad2)
- IPv6/Kad6 experiments: eMule eSE (P3 only)

Policy: specification first, interoperability implementation second. See D-008 in `docs/DECISIONS.md`.

## Current Status
### Done
- CI workflows for build/quality/security exist, with a change-aware PR gate
  and full validation after merge to `develop`.
- Hash-focused unit tests integrated in repo and workflows.
- Audit and core documentation baseline established.
- Remote CRITICAL/HIGH security items: CSRF (#77), PBKDF2 passwords (#79), CSPRNG (#78), CSP/redirects/rate limit, and Remote XSS HTML escape on `Add()` (#76). Remaining Remote security follow-ups tracked separately if found.
- Remote JS security regression tests wired into `code-quality.yml`.
- Skin engine **P0** input hardening (`SkinEngineP0.h`): StatusbarHeight registration,
  ParseRect `point`/`size`, roundRect validation, LoadFromXML section-failure
  aggregation (non-transactional), strict metric parse/clamp. HiDPI deferred.

### In Progress
- **Envy 4.2.0 Preview 1 release readiness** — version/packaging PR; install/uninstall + network smoke tests still required before tagging `v4.2.0-preview.1` and publishing the draft GitHub prerelease.
- C++ modernization across legacy modules.
- Incremental protocol compatibility and robustness improvements.
- **P0 ED2K/Kad interoperability baseline** against eMule Community and aMule (live interop unverified; see `docs/10_dev/status.md`).

### Blocked / At Risk
- Full CMake parity with Visual Studio build graph.
- Dependency refresh for older vendored components without regressions.

## Roadmap

Protocol and architecture work uses the sequence below. Engineering phases (tests, CI, CMake, performance) remain in parallel and must not be dropped for ED2K-only work.

Priorities must match `docs/10_dev/status.md` and `docs/10_dev/roadmap.md`.

### P0 — ED2K / Kad interoperability baseline

Absolute priority before new ED2K/Kad extensions. Validate against eMule Community and aMule (live Envy ↔ eMule, Envy ↔ aMule, ideally eMule ↔ Envy ↔ aMule). Status today: **partial / unverified live**.

ED2K: Hello / HelloAnswer, MuleInfo / MuleInfoAnswer, userhash, ClientID, HighID / LowID, callbacks, capability negotiation, compression, multipacket, search, Source Exchange, publish-as-source, upload/download, large files, unsupported-extension handling.

Kad2: bootstrap, routing table, node ID, UDP, HELLO / HELLO_RES, PING / PONG, FIND_NODE, keyword search, source search, publish, firewall check, Buddy, NAT traversal, HighID / LowID / firewalled.

Do not advertise an eMule capability that Envy does not implement.

### P0/P1 — Real RSA SecureIdent

Only after a reliable ED2K baseline without SecureIdent. **Not implemented today** (`ED2K_VERSION_SECUREID = 0`, #75). Primary reference: eMule Community; secondary: aMule. Details in the SecureIdent section below.

### P1 — IPv6 / reachability

References: eMule AI, eMule Qt, eMule eSE, aria2-next where relevant. Start with a clean dual-stack architecture (address type, sockets, DNS A/AAAA, connect/listen, source exchange, host cache, bans, dedup, UI/logging, UPnP / NAT-PMP / PCP, CGNAT). **Do not start Kad6** before this foundation. See `docs/ipv6/PLAN.md`.

### P1 — Incremental core / UI separation

Inspired by eMule Qt, aMule, and aria2-next. Long-term shape:

`EnvyCore` → protocol engines → transfer engine → library/search → stable internal API / IPC → MFC frontend → future Web/CLI frontend.

Incremental extraction only. No full rewrite.

### P1 — Skin engine HiDPI / modern display (after P0)

Do not mix with metric validation P0. Remaining backlog from the 2026-09 skin display audit:

- Logical 96-DPI XML units → per-window `MulDiv(..., dpi, 96)` for fonts, frames, anchors, regions
- Multi-monitor maximize using the window's `MONITORINFO.rcWork` (not primary-only)
- Black mask `000000` vs absent mask; restore or reject `LVSIL_MID` 24px; command-image index bounds
- Dialog skinning by control ID; real PNG alpha; transactional skin load / rollback
- Mark Slim / Win7–8 / Vista skins Legacy until the DPI layer exists

### P1 — Headless / API

Evaluate an Envy daemon, CLI, REST or JSON-RPC, remote-control API, interop-test automation, and running without a GUI. References: aMule, eMule Qt, aria2-next, Rucio. Today: MFC GUI plus limited Remote web UI (`docs/API.md`).

### P1/P2 — BitTorrent modernization

Preserve the existing BitTorrent track. Continue v1, BEP 10, DHT, PEX, UDP tracker, uTP, magnet, BEP 52 / v2, hybrid torrents. Never sacrifice BitTorrent to make Envy an eMule-only client.

### P2 — DHT / security research

References: Ember, Rucio, original Kademlia papers. Possible studies: stronger node verification, anti-amplification, routing-table diversity, subnet limits, signed records, modern crypto identities, BLAKE3 for **Envy-specific** features. Must not break Kad2/eMule compatibility. Any Envy-only extension must be versioned, optional, backward compatible, and distinct from Kad2.

### P3 — Experimental Kad6 / next overlay

Reference: eMule eSE. Not a short-term goal. Preconditions: stable Envy IPv6, stable Kad2 interop, clean NAT/reachability, and a protocol test harness.

### Phase 1 — Stability & Visibility (P0)
- [ ] Create dependency register + ownership map (2d) — **In progress on develop** (`docs/DEPENDENCIES.md` exists but remains an incomplete seed).
- [x] Add threat model and secure-coding checklist (2d)
- [ ] Expand tests for protocol parser/state-machine paths (5d)
- [ ] Establish baseline metrics (startup, memory, throughput) (3d) — tracked as [#111](https://github.com/Mika3578/Envy/issues/111)

### Runtime performance (audit 2026-09-10)

Measure before optimizing. Recommended order:

1. [#111](https://github.com/Mika3578/Envy/issues/111) — reproducible runtime benchmarks (P0)
2. [#112](https://github.com/Mika3578/Envy/issues/112) — `CBuffer` amortized front consume (P1)
3. [#113](https://github.com/Mika3578/Envy/issues/113) — network hot-path copies / lock hold times (P1; stability dependency [#92](https://github.com/Mika3578/Envy/issues/92))
4. [#114](https://github.com/Mika3578/Envy/issues/114) — global `TransferFiles` I/O lock contention (P1)
5. Hashing throughput — only if #111 measurements justify a dedicated issue; keep protocol hashes unchanged
6. IOCP — deferred until scalability evidence after Buffer/lock work; sockets are already non-blocking

Do not reuse [#102](https://github.com/Mika3578/Envy/issues/102) (CI runner latency) for `Envy.exe` runtime performance.

### Phase 2 — Build/Quality Convergence (P1)
- [ ] Define CMake migration boundary and milestones (3d)
- [ ] Reduce duplicated CI workflow logic (2d)
- [ ] Promote selected static-analysis checks to required gates (2d)

### Phase 3 — Architecture Hardening (P2)
- [ ] Isolate core transfer engine interfaces from UI classes (10d) — same intent as **P1 core/UI separation** above; incremental only
- [ ] Version plugin-facing APIs and compatibility policy (5d)
- [ ] Create automated dependency/SBOM release artifact (3d)

## ED2K / eMule SecureIdent roadmap

**Important:** SecureIdent is an authentication/trust feature. It must not be
confused with ED2K connectivity or Kad. Short-term goal: Envy remains visible,
can communicate, search, exchange sources, and transfer files with compatible
ED2K clients even when SecureIdent is unavailable. RSA SecureIdent comes later
to improve authentication and eMule credit-system compatibility.

### Current (#75 — safe disable)
- [x] Stop advertising SecureIdent (`ED2K_VERSION_SECUREID = 0`).
- [x] Never accept MD5/non-zero/legacy responses as verified.
- [x] Ignore inbound SecureIdent packets without dropping ED2K connections.
- [x] Keep ED2K transfer independent of SecureIdent.

### Current (#87 — honest Hello advertising)
- [x] AICH: local hash support may exist; **do not advertise** AICH FeatureVersions
  until C2C request/answer handlers are implemented (`Ed2kAichAdvertisedVersion() = 0`).
- [x] CryptLayer Hello bits (SUPPORTS/REQUESTS/REQUIRES) stay **0** until TCP
  protocol-obfuscation interop with eMule/aMule is proven; packet PUBLICKEY
  crypto is not treated as equivalent to MiscOptions2 crypt bits.
- [x] CryptLayer Hello bit alignment (separate PR after obfuscation audit — #121).
- [ ] Live Hello capture vs eMule Community / aMule (validation after merge).

### Current (#124 — EnableKad settings binding)
- [x] Register `eDonkey.EnableKad` with `Settings.Add` (default `true`) so
  `InitKademlia()` can run; distinct from `EnableKadHello`.
- [ ] UI checkbox for EnableKad (optional follow-up; registry/settings dump works).
- [ ] Kad search/source hits → `AddSourceED2K` (separate PR; not #86 routing table).

### Future RSA SecureIdent (separate workstream)
1. Baseline ED2K interoperability with eMule/aMule without SecureIdent.
2. Confirm Envy works correctly when SecureIdent is unsupported/unavailable.
3. Implement real eMule SecureIdent (not the removed MD5 stub).
4. Remote public-key handling (`ED2K_C2C_PUBLICKEY` / peer key store).
5. Local private-key generation/persistence if required by the protocol.
6. Protocol-correct SecureIdent challenge (`ED2K_C2C_SECIDENTSTATE`).
7. RSA signature generation (`ED2K_C2C_SIGNATURE`).
8. RSA signature verification against the peer public key.
9. Correct binding of identity / userhash / challenge / peer context.
10. Explicit SecureIdent state machine: unsupported, unavailable/incomplete,
    unverified, verified, failed.
11. Rejection tests: invalid signature, wrong key, wrong challenge, replay,
    response from another client.
12. Live interop tests: Envy ↔ eMule, Envy ↔ aMule, ideally eMule ↔ Envy ↔ aMule.

Protocol references for that future work: specifications first (eDonkey
paper, aMule ED2K wiki, ED2K URI spec), then eMule Community as de-facto
wire reference and aMule as second interop target. See
`docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md`. Adapt behaviour; do not
copy blindly.

### Future ED2K interoperability checklist (document only)
Hello/HelloAnswer, MuleInfo/MuleInfoAnswer, userhash, ClientID, HighID/LowID,
LowID callback, advertised capabilities/extensions, extended protocol,
compression, multipacket, search, source exchange, publish-as-source,
upload/download, large files, and clean handling of unsupported extensions.
**Rule:** Envy must advertise an eMule capability only when it is actually
implemented and sufficiently tested.

### Future Kad interoperability checklist (document only — out of #75 scope)
Bootstrap, routing table, Node ID, UDP, HELLO/HELLO_RES, PING/PONG, FIND_NODE,
keyword search, source search, publish, firewall check, UDP firewall, Buddy,
NAT traversal, Kad versions, HighID/LowID/firewalled behavior, and
eMule/aMule interop. No Kad code changes in the SecureIdent safe-disable work.

## Backlog
- [ ] Replace unsafe string operations in first-party code (incremental: bounded keyword copy in legacy Kad publish packet builder completed)
- Consolidate duplicate roadmap/status markdown into canonical set
- Document remote API implementation status endpoint-by-endpoint
- Add long-running memory/regression test scenario
- Archive legacy `.vcproj` files once migration is complete

## Decisions Log
- **2026-09-17:** #140 wording: MiniUPnPc 2.0 targeted discovery is one receive phase for requested ST values, not a strict wall-clock SSDP deadline; absolute SSDP and HTTP timeout bounding → [#142](https://github.com/Mika3578/Envy/issues/142) / P3.
- **2026-09-18:** #166 / D-009 P1 delivered: WFAS `INetFwPolicy2` replaces `INetFwMgr`; application rules on all profiles; UPnP via rule-group enable. Next: P2 LocalPort/ExternalPort.
- **2026-09-17:** #140 P0 runtime PASS (post-squash HEAD): targeted discovery + gateway-only rootdevice fallback; non-IGD devices never receive WAN mapping commands. Remaining MiniUPnPc 2.0 SSDP/HTTP latency → [#142](https://github.com/Mika3578/Envy/issues/142) / P3. Separate backlog: bind/listen must not wait for NAT completion → [#141](https://github.com/Mika3578/Envy/issues/141). Order remains P1 WFAS → P2 ports → P3 MiniUPnPc 2.3.x.
- **2026-09-17:** SSDP success != usable IGD. #140 uses targeted `upnpDiscoverDevices` with `searchalltypes=1` (one discovery receive phase), filters to explicit IGD/WAN ST, and limits rootdevice fallback to the selected gateway IP with exact LOCATION string dedupe. `UPNP_GetValidIGD` runs once on filtered candidates; results `0`/`3` never issue WAN commands.
- **2026-09-16:** NAT/Firewall recovery is phased PRs (not a monolith): P0 modern interface selection (#140), P1 Windows Firewall WFAS (`INetFwPolicy2`), P2 LocalPort/ExternalPort model (behavior-preserving first), P3 MiniUPnPc 2.3.x **vendored** update (no vcpkg introduction for this alone), P4 NatTraversalManager + PCP/NAT-PMP, P5 CGNAT/diagnostics. Do not declare inbound reachability fixed without runtime evidence on a non-CGNAT path.
- **2026-09-15:** Keep C++ RTTI disabled project-wide (`RuntimeTypeInfo=false` / `/GR-`). Do not enable `/GR` to make `dynamic_cast` work. Protocol-specific actions belong on the transfer/neighbour classes via `virtual`/`override`. Localized `static_cast` is acceptable only when the construction path proves the concrete type (first case: `PROTOCOL_ED2K` uploads are always `CUploadTransferED2K` from `CEDClient::OnQueueRequest`). The protocol enum remains valid for UI, stats, logs, filtering, and serialization.
- **2026-09-11:** Persist `eDonkey.EnableKad` via `Settings.Add` (#124) separately
  from Kad routing-table work (#86) and from Kad→`AddSourceED2K` source delivery.
  Default remains `true` per settings reference; no migration (key never existed).
- **2026-09-11:** For #87 Hello honesty, stop advertising AICH until C2C
  handlers exist. Keep CryptLayer MiscOptions2 bits at 0 until TCP
  obfuscation interop is audited separately from packet PUBLICKEY crypto.
  SecureIdent advertisement remains 0 (#75).
- **2026-09-11:** Adopt an explicit reference-implementation policy (D-008): specifications first; eMule Community/aMule as ED2K/Kad de-facto interop; eMule Qt/aria2-next/eMule AI as architecture; Ember/eSE as experimental only. Envy stays multi-network.
- **2026-09-10:** Runtime performance work starts with reproducible benchmarks (#111). No IOCP rewrite issue until peer-scalability evidence after Buffer/lock optimizations. No dedicated LibraryBuilder hashing issue until measurements show a user-visible bottleneck. #92 stays correctness/stability (lock order); #113 tracks contention separately.
- **2026-09-10:** Adopt a two-speed CI: path-aware PR jobs (`if:`, never
  `paths-ignore` on required workflows), CodeQL C++ `build-mode: none` on PRs
  and manual traced builds on `develop`/schedule, vcpkg files binary cache
  (`x-gha` removed upstream). Required Protect develop check names are listed
  in `.github/settings.yml` (including `PR Gate` as a required CI wait).
- **2026-09-10:** For issue #75, choose safe disable of fake SecureIdent over
  implementing RSA in the same PR. Advertisement stays at version 0 until a
  dedicated RSA SecureIdent workstream lands. ED2K connectivity must not depend
  on SecureIdent.
- **2026-05-27:** Rewrote `develop` into a linear history with no merge commits while preserving the final tree through backup refs; enforce linear history going forward via the active `Protect develop` ruleset (squash-only on `develop`), global GitHub merge settings (no merge commits; squash/rebase enabled), and contributor `git pull --ff-only` hygiene.
- **2026-05-15:** Repository hygiene baseline on `develop` requires explicit branch-state tracking and GitHub label prerequisites (`ci`, `dependencies`) before enforcing CI as mandatory gates.
- **2026-04-22:** Added IPv6 dual-stack Phase 0 scoping inventory and phased rollout plan under `docs/ipv6/`.
- **2026-04-22:** Remote web UI must use cryptographic token generation (`crypto.getRandomValues`) and allowlist-based redirect validation for all client-side navigation paths.
- **2026-04-22:** Keep Visual Studio solution as authoritative full-build path while CMake remains partial.
- **2026-04-22:** Standardize new audit reports under `docs/audit/`.
- **2026-04-22:** Treat this plan as a required living artifact for project management continuity.

## Open Questions
1. Should this project explicitly remain Windows-only, or is cross-platform parity still a target? (Headless/API work can proceed on Windows first; aMule-style multi-OS is not a current delivery goal.)
2. What is the acceptable backward-compatibility policy for legacy protocols/features? Working default: preserve G1/G2/DC/BitTorrent; ED2K/Kad changes must remain eMule/aMule-compatible unless versioned as optional Envy extensions.
3. Which dependency update cadence (monthly/quarterly) is realistic for maintainers?
4. Should remote API documentation be strict contract-first or implementation-first?
5. REST versus JSON-RPC for a future Envy daemon API (evaluate against aMule EC, eMule Qt, and aria2-next; no choice yet).
