# DEVELOPMENT PLAN (LIVING)

- **Last Updated:** 2026-11-26

> **LIVING DOCUMENT** — update the sections below after every meaningful
> change (feature, architectural decision, scope change, blocker resolution).
> Per-PR narrative records are **not** kept here: git history, squash-merge
> bodies, `CHANGELOG.md` and PR descriptions carry them. The 2026 journal
> that used to sit under this header is archived at
> [`docs/10_dev/archive/development-plan-journal-2026.md`](10_dev/archive/development-plan-journal-2026.md).

## Update Protocol
1. Update **Last Updated** on every meaningful change.
2. Edit the affected section in place; do not append journal entries.
3. Reflect status changes in **Current Status** and **Roadmap**.
4. Record consequential decisions as a row in `docs/DECISIONS.md`.
5. Close or refresh **Open Questions** explicitly.

## Update Protocol
1. Update **Last Updated** date on every meaningful change.
2. Add a one-line entry to the changelog section above.
3. Reflect status changes in **Current Status** and **Roadmap**.
4. Record consequential technical decisions in **Decisions Log**.
5. Close or refresh **Open Questions** explicitly.
## Repository Status (develop)

Branch, merge-policy and protection details live in
[`docs/10_dev/pr-workflow.md`](10_dev/pr-workflow.md) and
`.github/CONTRIBUTING.md`; the verified live-ruleset state is recorded in
[`docs/00_index/KNOWN_INCONSISTENCIES.md`](00_index/KNOWN_INCONSISTENCIES.md).
This file stays strategy-only and does not restate the merge policy.

## Documentation map
- `docs/DEVELOPMENT_PLAN.md` (this file): strategic roadmap and sequencing.
- [`docs/10_dev/status.md`](10_dev/status.md): protocol/architecture status matrix (evidence-based; no “complete” without proof).
- [`docs/10_dev/roadmap.md`](10_dev/roadmap.md): technical modernization itemization aligned with the P0–P3 sequence.
- [`docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md`](30_protocols/REFERENCE_IMPLEMENTATIONS.md): external P2P reference projects and spec-first policy.
- `.local/DEV_TRACKER.md`: session notes (gitignored, not a committed source of truth).

## Vision & Goals
- Keep Envy a stable **Windows-native multi-network** client today: BitTorrent, Gnutella, Gnutella2, ED2K, Kad, Direct Connect, Remote/Web, plus library and multi-network search.
- Evolve toward a portable `EnvyCore` + platform abstraction so Linux x86_64 and macOS ARM64 can become real targets later (**planned**, not supported yet). See D-012 and `docs/20_arch/PORTABILITY_PLAN.md`.
- Improve ED2K/Kad interoperability against eMule Community and aMule without dropping other networks.
- Reduce modernization risk with incremental core/UI boundaries, testability, and dependency hygiene.
- Increase release confidence through clearer architecture boundaries and measurable quality gates.
- Stop reinforcing unnecessary MFC/Win32 coupling in **new** core interfaces (D-013) while preserving the MFC Windows frontend.

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
- CI workflows for build/quality/security exist with staged validation:
  Draft runs the cheap lane, `stage:live-test` and Ready run full Windows/C#
  validation, and native workflow conclusions provide the merge checks.
- Hash-focused unit tests integrated in repo and workflows.
- Audit and core documentation baseline established.
- Remote CRITICAL/HIGH security items: CSRF (#77), PBKDF2 passwords (#79), CSPRNG (#78), CSP/redirects/rate limit, and Remote XSS HTML escape on `Add()` (#76). Remaining Remote security follow-ups tracked separately if found.
- Remote JS security regression tests wired into `code-quality.yml`.
- Skin engine **P0** input hardening (`SkinEngineP0.h`): StatusbarHeight registration,
  ParseRect `point`/`size`, roundRect validation, LoadFromXML section-failure
  aggregation (non-transactional), strict metric parse/clamp. HiDPI deferred.
- **#90 / #354 crash reporting** — BugTrap removed. **x64:** BugSplat SDK v8.0.0 (`ThirdParty/BugSplat`, optional upload when `EnvyBugSplatDatabase` is set). **Win32:** Crashpad local database + next-launch opt-in GitHub issue workflow (upload off). See `docs/10_dev/crash-reporting.md` (D-019, D-020).

### In Progress
- **BugSplat runtime reliability (#359 / PR #362)** — synchronize deterministic x64 dependency discovery with installer and portable packaging; require staged CRT files and preserve Win32 Crashpad. Current-head CI and maintainer runtime validation remain required. Live Protect develop currently records zero required approvals, contrary to the documented one-approval policy; independent human approval remains required for workflow changes.
- **Envy 4.2.0 Preview 1 release readiness** — version/packaging PR; install/uninstall + network smoke tests still required before tagging `v4.2.0-preview.1` and publishing the draft GitHub prerelease.
- C++ modernization across legacy modules.
- Incremental protocol compatibility and robustness improvements.
- **P0 ED2K/Kad interoperability baseline** against eMule Community and aMule (live interop unverified; harness exists — `tools/interop/README.md`; see `docs/10_dev/status.md`).
- **Bootstrap catalogues** — shipped `DefaultServices.dat` / `DefaultServers.dat` refreshed 2026-09-18. Remaining: importer hardening (P0 potential); last-known-good remote catalogue (`docs/30_protocols/bootstrap-sources.md`). Validated HTTPS Kad `nodes.dat` cold-start fallback and local `ImportNodes` v1/v2/v3 are implemented; Kad2 interop remains partial. Do not restore C++ DHT DNS constants when the catalogue is missing (D-012).
- Transfer settings UX: first slice (labels + validation + mapping) in `docs/50_user/transfer-settings.md`; no fake capabilities.
- **Modern Transfer Capacity / Broadband 2026** (#341–#345, #332, #111): #341 correctness foundation (multigig-safe conversions + upload headroom) in flight; #342 capacity vs user limits UX; #343 connection-speed presets; #344 elastic ED2K/HTTP slots; #345 BitTorrent choking; measure (#111) before raising concurrency (#113/#114).

### Blocked / At Risk
- Full CMake parity with Visual Studio build graph.
- Dependency refresh for older vendored components without regressions.

## Roadmap

Protocol and architecture work uses the sequence below. Engineering phases (tests, CI, CMake, performance) remain in parallel and must not be dropped for ED2K-only work.

Priorities must match `docs/10_dev/status.md` and `docs/10_dev/roadmap.md`.

### P0 — ED2K / Kad interoperability baseline

Absolute priority before new ED2K/Kad extensions. Validate against eMule Community and aMule (live Envy ↔ eMule, Envy ↔ aMule, ideally eMule ↔ Envy ↔ aMule). Status today: **partial / unverified live**. Phase-1 evidence collection: `python3 tools/interop/run.py` (`tools/interop/README.md`). The harness existing is **not** an interoperability claim.

ED2K: Hello / HelloAnswer, MuleInfo / MuleInfoAnswer, userhash, ClientID, HighID / LowID, callbacks, capability negotiation, compression, multipacket, search, Source Exchange, publish-as-source, upload/download, large files, unsupported-extension handling.

Kad2: bootstrap, routing table, node ID, UDP, HELLO / HELLO_RES, PING / PONG, FIND_NODE, keyword search, source search, publish, firewall check, Buddy, NAT traversal, HighID / LowID / firewalled.

Do not advertise an eMule capability that Envy does not implement.

### P0/P1 — Real RSA SecureIdent

Only after a reliable ED2K baseline without SecureIdent. **Not implemented today** (`ED2K_VERSION_SECUREID = 0`, #75). Primary reference: eMule Community; secondary: aMule. Details in the SecureIdent section below.

### P1 — IPv6 / reachability

References: eMule AI, eMule Qt, eMule eSE, aria2-next where relevant. Start with a clean dual-stack architecture (address type, sockets, DNS A/AAAA, connect/listen, source exchange, host cache, bans, dedup, UI/logging, UPnP / NAT-PMP / PCP, CGNAT). **Do not start Kad6** before this foundation. See `docs/ipv6/PLAN.md`.

### P1 — Incremental core / UI separation

Inspired by eMule Qt, aMule, and aria2-next. Long-term shape:

```text
EnvyCore (protocols / transfers / library-search)
    → Platform Abstraction
    → Windows | Linux | macOS
         ↳ MFC frontend (Windows, retained)
EnvyCore → Local API / headless → WebUI / CLI / future GUI
```

Incremental extraction only. No full rewrite. No Qt (or other GUI toolkit) introduction in this track. First multiplatform goal is core/headless, not a new desktop GUI. Tracked with #91 (test seam) and #161 (EnvyCore/headless); portability sequencing in `docs/20_arch/PORTABILITY_PLAN.md`.

### P1 — Cross-platform foundations (docs + sequencing)

Formalize platforms (Windows x64 primary; Win32 legacy Stage A; Linux/macOS **planned**), CMake portable-slice priority (D-015), and future CI order: Windows x64 → portable tests → Linux x86_64 → macOS ARM64. Do not add required non-Windows CI until portable code exists. Do not remove Win32 without Stage B/C evidence (D-024).

### P1 — Skin engine HiDPI / modern display (after P0)

Do not mix with metric validation P0. Remaining backlog from the 2026-09 skin display audit:

- Logical 96-DPI XML units → per-window `MulDiv(..., dpi, 96)` for fonts, frames, anchors, regions
- Multi-monitor maximize using the window's `MONITORINFO.rcWork` (not primary-only)
- Black mask `000000` vs absent mask; restore or reject `LVSIL_MID` 24px; command-image index bounds
- Dialog skinning by control ID; real PNG alpha; transactional skin load / rollback
- Mark Slim / Win7–8 / Vista skins Legacy until the DPI layer exists

### P1 — Headless / API

Native versioned REST `/api/v1` (D-017/D-018, 2026-09-19 audit). HTML Remote is not that API. First *arr on-ramp is a **qBittorrent Web API v2 subset**, after transfer services exist — never labelled “qBittorrent-compatible” until tests pass. Torznab is a separate **client**. Tracked: #161 plus [#239](https://github.com/Mika3578/Envy/issues/239) native `/api/v1`, [#240](https://github.com/Mika3578/Envy/issues/240) qBit subset, [#241](https://github.com/Mika3578/Envy/issues/241) Torznab. Today: MFC GUI plus limited Remote web UI.

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
- [x] Define CMake migration boundary and milestones — **clarified 2026-09-18**: full-app CMake low priority; portable `EnvyCore`/HashLib/tests/headless CMake is foundational (D-015 / `PORTABILITY_PLAN.md`). Implementation still open under #91/#161.
- [ ] Reduce duplicated CI workflow logic (2d)
- [ ] Promote selected static-analysis checks to required gates (2d)
- [ ] Bootstrap non-Windows CI only after portable tests exist (Linux x86_64, then macOS ARM64); keep jobs advisory until green

### Phase 3 — Architecture Hardening (P2)
- [ ] Isolate core transfer engine interfaces from UI classes (10d) — same intent as **P1 core/UI separation** above; incremental only (#161)
- [ ] Introduce portable platform abstractions (sockets/DNS/FS/threads/RNG) behind EnvyCore — no mass `#ifdef` rewrite
- [ ] Version plugin-facing APIs and compatibility policy (5d)
- [ ] Create automated dependency/SBOM release artifact (3d)
- [ ] Execute Win32 retirement per D-024: Stage B #454 (stop Win32 releases), Stage C #455 (remove Win32 build/CI and Crashpad); no dependency on the Linux/macOS ports

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

### Current (#87 — honest Hello advertising + LowID callback baseline)
- [x] AICH: local hash support may exist; **do not advertise** AICH FeatureVersions
  until C2C request/answer handlers are implemented (`Ed2kAichAdvertisedVersion() = 0`).
- [x] CryptLayer Hello bits (SUPPORTS/REQUESTS/REQUIRES) stay **0** until TCP
  protocol-obfuscation interop with eMule/aMule is proven; packet PUBLICKEY
  crypto is not treated as equivalent to MiscOptions2 crypt bits.
- [x] CryptLayer Hello bit alignment (separate PR after obfuscation audit — #121).
- [x] Phase-1 PUBLICIP_REQ/ANSWER + C2C CALLBACK baseline (`Ed2kLowIdCallback.h`,
  `CEDClient` handlers). Classic server callback unchanged. **Partial** only —
  not Buddy / REASKCALLBACKTCP / FWCHECK / complete LowID.
- [ ] REASKCALLBACKTCP + Buddy bond (phase 2).
- [ ] BUDDYPING / BUDDYPONG / FWCHECKUDPREQ (phase 2 / Kad).
- [ ] Live Hello / LowID capture vs eMule Community / aMule (#160).

### Current (#124 — EnableKad settings binding)
- [x] Register `eDonkey.EnableKad` with `Settings.Add` (default `true`) so
  `InitKademlia()` can run; distinct from `EnableKadHello`.
- [ ] UI checkbox for EnableKad (optional follow-up; registry/settings dump works).
- [x] Kad search/source hits → `AddSourceED2K` (HighID SEARCH_RES delivery + tests; keyword excluded; buddy/callback types deferred; outbound TagList framing still open — not full #86).
- [x] App-trigger `SearchSource` from ED2K download source acquisition (`DownloadWithSearch::MaybeSearchKadSources`); outbound SEARCH_SOURCE_REQ includes FileSize.
- [x] Kad TCP firewall-detection baseline (`FIREWALLED_REQ`/`RES`, bounded checks, public-IP consensus, TCP ACK count). UDP firewall verification, Buddy and callback remain incomplete (#86 remainder).
- [x] Kad routing-table maintenance (zone split, LRU/type liveness, bounded replacement, stale-zone FIND_NODE refresh, /24 diversity + tests).
- [x] Local `nodes.dat` v1/v2/v3 parser (`KadNodesDat.h`); v3 bootstrap edition bounded; UDP-key/`verified` bytes discarded. Remote HTTP `nodes.dat` still open.
- [ ] Kad UDP firewall tester / Buddy / callback / UDP-key runtime (#86 remainder).

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
- [x] Document remote API implementation status endpoint-by-endpoint — 2026-09-19 audit (`docs/20_arch/AUDIT_REMOTE_API_2026-09.md`); OpenAPI remains `planned` until routes are served
- Add long-running memory/regression test scenario
- Archive legacy `.vcproj` files once migration is complete

## Decisions

The decision register lives in [`docs/DECISIONS.md`](DECISIONS.md) — one
ADR-lite row per decision, with superseded rows compressed. The chronological
working log previously kept in this section (2026-04-22 to 2026-10-01) moved
to [`docs/10_dev/archive/decision-log-2026.md`](10_dev/archive/decision-log-2026.md);
consult it for context behind table rows and for operational decisions that
were never promoted to the table.
