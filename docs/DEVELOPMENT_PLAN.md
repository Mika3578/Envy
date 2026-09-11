# DEVELOPMENT PLAN (LIVING)

> **LIVING DOCUMENT** — Must be updated after every meaningful change (feature, architectural decision, scope change, blocker resolution).

- **Last Updated:** 2026-09-11
- **Changelog Entry:** 2026-09-11 — Documented external P2P reference implementations (eMule Community, aMule, eMule Qt, eMule AI, aria2-next, Ember, Rucio, eMule eSE), Envy’s multi-network positioning, specification-first policy (D-008), and the P0–P3 interoperability/architecture sequence. Restored the missing `docs/10_dev/status.md` matrix. Corrected remaining SecureIdent “active/complete” claims: RSA SecureIdent is not implemented (#75).
- **Changelog Entry:** 2026-09-10 — Runtime performance audit backlog: reproducible benchmarks (#111), then CBuffer front-consume (#112), network hot-path copies/locks (#113), TransferFiles I/O contention (#114). IOCP and dedicated hashing optimization deferred pending evidence. #102 remains CI runner latency only.
- **Changelog Entry:** 2026-09-10 — Two-speed GitHub Actions: change-aware PR
  gate (skip Windows/CodeQL/Remote/C# when unrelated), CodeQL C++ `build-mode: none`
  on PRs with full manual analysis on `develop`/weekly, vcpkg files binary
  cache (Win32 included; `x-gha` is gone upstream), differential Format Check, clang-tidy moved off PRs, EnvyTests after
  MSBuild. Live required check names are unchanged. `PR Gate` is advisory until
  a maintainer updates the `Protect develop` ruleset.
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
- **Merge policy (GitHub):** merge commits disabled; squash and rebase merges enabled. Prefer squash for PRs.
- **History:** `develop` was rewritten to a linear history with no merge commits; the pre-rewrite snapshot is preserved as the immutable tag `backup/develop-before-linear-rewrite` (local mutable backup/rollback branches were removed after the rewrite stabilized).
- **Local hygiene:** use `git pull --ff-only` on `develop`; rebase feature branches with `git rebase origin/develop` and `git push --force-with-lease`.
- **Branch protection:** the active `Protect develop` ruleset requires pull requests, linear history, passing checks, and blocks force-pushes/deletions. `.github/settings.yml` mirrors the intended policy for Probot Settings or manual audits.
- CI uses a two-speed model: change-aware PR jobs plus full integration on
  `develop` / scheduled analysis. The live `Protect develop` ruleset still
  requires the eight named contexts listed in `.github/settings.yml`; `PR Gate`
  is emitted on every PR but is not required until a maintainer updates the
  ruleset. See `docs/10_dev/agents-and-automation.md`.
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
- Remote CRITICAL/HIGH security items remediated (CSRF, XSS sanitization, CSP hardening, redirects, rate limiter, API input validation).
- Remote JS security regression tests wired into `code-quality.yml`.

### In Progress
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
- **2026-09-11:** Adopt an explicit reference-implementation policy (D-008): specifications first; eMule Community/aMule as ED2K/Kad de-facto interop; eMule Qt/aria2-next/eMule AI as architecture; Ember/eSE as experimental only. Envy stays multi-network.
- **2026-09-10:** Runtime performance work starts with reproducible benchmarks (#111). No IOCP rewrite issue until peer-scalability evidence after Buffer/lock optimizations. No dedicated LibraryBuilder hashing issue until measurements show a user-visible bottleneck. #92 stays correctness/stability (lock order); #113 tracks contention separately.
- **2026-09-10:** Adopt a two-speed CI: path-aware PR jobs (`if:`, never
  `paths-ignore` on required workflows), CodeQL C++ `build-mode: none` on PRs
  and manual traced builds on `develop`/schedule, vcpkg files binary cache
  (`x-gha` removed upstream). Keep the eight live required check names until `PR Gate` is promoted in the
  GitHub ruleset by a maintainer.
- **2026-09-10:** For issue #75, choose safe disable of fake SecureIdent over
  implementing RSA in the same PR. Advertisement stays at version 0 until a
  dedicated RSA SecureIdent workstream lands. ED2K connectivity must not depend
  on SecureIdent.
- **2026-05-27:** Rewrote `develop` into a linear history with no merge commits while preserving the final tree through backup refs; enforce linear history going forward via the active `Protect develop` ruleset, GitHub merge settings (no merge commits; squash/rebase only), and contributor `git pull --ff-only` hygiene.
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
