# P2P ecosystem audit (October 2026)

Status: research / audit pass (documentation only — no protocol implementation)
Last updated: 2026-10-20 (section 7 added: eMule Qt deep audit; sections 1-6 verified 2026-10-07)
Base commit: `develop` @ `c8cc5c3`
Scope: Open-source P2P clients and engines compared against Envy docs and tracker for **reference selection**, not feature claims.
Authority: specifications and BEPs first; `docs/10_dev/status.md` for Envy claims; `docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md` for the canonical registry; local clones via `tools/references/` (D-023).

This supersedes the unpublished September 2026 draft that lived only on the
historical tip of PR #387 (`docs/p2p-ecosystem-audit` @ `6bbb7d3`). That draft
is **not** shipped in this tree: there is no
`P2P_ECOSYSTEM_AUDIT_2026-09.md` on the current branch. It incorrectly
classified `irwir/eMule` as historical and used `pushed_at`-only rows for some
clients.

---

## 1. Methodology

### 1.1 Envy inventory (2026-10-07)

| Source | Count / notes |
| --- | --- |
| Open development PRs (non-Dependabot) | 9 at audit start (overlap awareness; no governance change in this PR) |
| Focus of this pass | External reference registry + local clone workflow |

Documents read: `AGENTS.md`, `docs/10_dev/status.md`, `docs/10_dev/roadmap.md`,
`docs/DEVELOPMENT_PLAN.md`, `docs/DECISIONS.md` (D-008, D-023),
`docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md`.

### 1.2 “Active” evidence rule

A project is **active** only with at least one of:

- a release with functional scope; or
- a functional / protocol commit or merged PR; or
- clear maintenance that changes behaviour (not Weblate-only, README-only, or bot metadata).

**`pushed_at` alone is never sufficient.**

Status classes:

| Class | Meaning |
| --- | --- |
| active reference | Maintained; suitable for interop / behaviour comparison |
| maintenance | Fixes/releases without claiming protocol leadership |
| active experimental | Maintained but **not** normative for wire compatibility |
| historical | Useful archive / heritage; not modern wire authority |
| inactive | Abandoned or discontinued |

### 1.3 Authority ladder (ED2K/Kad)

```text
Specification / protocol docs
    ↓
eMule Community (P0 wire)
    ↓
aMule amule-org (P0 interop)
    ↓
eMuleBB / emulebb-rust / eMule Qt / padMule / eMule AI / aria2-next
    ↓
MorphXT and other historical mods
    ↓
Ember / eMule eSE / NeoKad-style experiments
```

---

## 2. Reference matrix (verified 2026-10-07)

Projects examined for this refresh: **primary Envy-relevant set** below
(plus historical mods via the eMuleBB mods archive). Broader Soulseek /
libp2p / Syncthing rows from the September draft remain optional architecture
ideas only and are **not** Envy protocol targets.

### 2.1 ED2K / Kad — P0

| Repository | Class | Evidence (not `pushed_at`) | Primary Envy use | Restrictions |
| --- | --- | --- | --- | --- |
| [irwir/eMule](https://github.com/irwir/eMule) | **active reference** | Release [`eMule_v0.72a-community`](https://github.com/irwir/eMule/releases/tag/eMule_v0.72a-community) **2026-08-20**; prior community releases 0.70a/0.70b | P0 ED2K/Kad2 wire (Hello, SourceEx, SecureIdent, AICH, Kad2, Buddy, …) | Specs still first when written |
| [amule-org/amule](https://github.com/amule-org/amule) | **active reference** | Release [`3.1.0`](https://github.com/amule-org/amule/releases/tag/3.1.0) 2026-09-21; functional merges 2026-10-06 e.g. AICH source ranking, live TCP/UDP port apply (`#1738`/`#1739` class) | P0 interop + daemon/EC/Web/CLI | Prefer over `amule-project/amule` |
| [amule-project/amule](https://github.com/amule-project/amule) | historical redirect | Org frozen; last release 3.0.0 era; superseded by amule-org README notice | Legacy URL only | Do not treat as active tip |

### 2.2 ED2K / Kad — modern implementations (P1)

| Repository | Class | Evidence | Primary Envy use | Restrictions |
| --- | --- | --- | --- | --- |
| [emulebb/emulebb](https://github.com/emulebb/emulebb) | maintenance | Release [`emulebb-v0.7.3`](https://github.com/emulebb/emulebb/releases/tag/emulebb-v0.7.3) 2026-07-05; functional commits 2026-07 (BUG-117 part flush/resume, `diag(ed2k_tcp)`); nightly 2026-10-03 | Large library, upload/queue, REST/automation patterns | Not Kad2-normative |
| [emulebb/emulebb-rust](https://github.com/emulebb/emulebb-rust) | active experimental | Nightly betas Oct 2026; functional commits 2026-10-06 (`fix(ed2k)` UDP trains, `fix(kad)` search matching, `feat(search)` evidence) | Parsers, headless, differential tests | Beta; not wire authority |
| [ModderMule/emule-qt](https://github.com/ModderMule/emule-qt) | active reference | Release [`v0.6.22`](https://github.com/ModderMule/emule-qt/releases/tag/v0.6.22) 2026-10-19 (re-verified 2026-10-20; was `v0.5.6`); `main` @ `aa891270`; details in section 7 | #161 core/UI, IPC, REST; hash scheduling and port-mapping principles | Architecture only; GPL-2.0, no code reuse; its tests are not run in its CI |
| [eMuleAI/eMuleAI](https://github.com/eMuleAI/eMuleAI) | active experimental | Release [`eMuleAI_v1.6`](https://github.com/eMuleAI/eMuleAI/releases/tag/eMuleAI_v1.6) 2026-07-25 | IPv6 / NAT / reachability ideas | Not ED2K-normative |
| [ajbufort/padMule](https://github.com/ajbufort/padMule) | active experimental | Functional commits 2026-08-14 (share naming, atomic `nodes.dat`/`clients.met`, Kad diagnostics) | Independent Rust ED2K/Kad engine + differential testing | Declares eMule 0.50a wire authority / aMule oracle |
| [AnInsomniacy/aria2-next](https://github.com/AnInsomniacy/aria2-next) | active reference | Releases [`v2.8.6`](https://github.com/AnInsomniacy/aria2-next/releases/tag/v2.8.6) 2026-10-04; stream I/O fix commits | Engine/RPC/headless; BT+ED2K | Not Envy UI replacement |
| [diad87/eMule-eSE-LiveTV](https://github.com/diad87/eMule-eSE-LiveTV) | active experimental | Releases eSE 9.1.0 / 9.2.0-rc (2026-08–09) | IPv6 / Kad6 R&D | **Kad6 ≠ Kad2** |

### 2.3 Historical mods / interop research (P2)

| Source | Class | Evidence / location | Primary Envy use | Restrictions |
| --- | --- | --- | --- | --- |
| MorphXT | historical + **interop test target** | SF [emulemorph](https://sourceforge.net/projects/emulemorph/); GH mirror [Stullemon/emulemorph](https://github.com/Stullemon/emulemorph); archive tree MorphXT 12.7 | Envy ↔ MorphXT Hello/capabilities/SourceEx/queue behaviour | Never modern wire authority |
| Xtreme, StulleMule, ScarAngel, NeoMule, MagicAngel, Mephisto, AdunanzA, Beba, AcKroNiC, ZZUL, DreaMule, eMule Plus, … | historical | [emulebb/emulebb-mods-archive](https://github.com/emulebb/emulebb-mods-archive) | Feature research only | Clone archive on demand; do not mass-import |
| kMule / VeryCD easyMule / EastShare | historical (conditional) | Add row only when a concrete exploitable source is confirmed | — | Skip if source unverifiable |

### 2.4 Multi-network heritage

| Repository | Class | Evidence | Primary Envy use | Restrictions |
| --- | --- | --- | --- | --- |
| Shareaza (SF + [ivan386/Shareaza](https://github.com/ivan386/Shareaza)) | historical | SF project; GH tip largely pre-2020 meaningful protocol work | G1/G2 / library / unified search lineage | Envy tree is the live G1/G2 reference |
| [peerproject/peerproject](https://github.com/peerproject/peerproject) | historical | Last meaningful push ~2016 | Immediate Envy predecessor | Not modern authority |
| [NeoLoader/NeoLoader](https://github.com/NeoLoader/NeoLoader) | historical | Release `0.53a` (2018) | Multi-protocol / core-GUI architecture | Not protocol-normative; NeoKad experimental |
| [ygrek/mldonkey](https://github.com/ygrek/mldonkey) | maintenance | Release `release-3-2-1` (2024); functional commits through 2025-01 | Independent ED2K/Kad + daemon | Not eMule wire oracle |

### 2.5 BitTorrent (BEP first)

| Repository | Class | Evidence | Primary Envy use | Restrictions |
| --- | --- | --- | --- | --- |
| [arvidn/libtorrent](https://github.com/arvidn/libtorrent) | active reference | Release [`v2.1.2`](https://github.com/arvidn/libtorrent/releases/tag/v2.1.2) 2026-09-25; functional fixes Oct 2026 | #88 engine/BEP matrix | BEP docs still first |
| [qbittorrent/qBittorrent](https://github.com/qbittorrent/qBittorrent) | active reference | Releases 5.2.4 / 5.3.0rc1 2026-09-28; WebUI/search commits Oct 2026 | UX/API/tags/ATM | Product patterns, not BEP substitute |
| [transmission/transmission](https://github.com/transmission/transmission) | active reference | Release 4.1.3 2026-06-30; peer/RPC fixes 2026 | Daemon/RPC/headless | — |
| [BiglySoftware/BiglyBT](https://github.com/BiglySoftware/BiglyBT) | active reference | Release v4.1.0.0 2026-05; tracker/relocation commits Oct 2026 | Swarm merge / tags / rules | — |

### 2.6 Direct Connect

| Repository | Class | Evidence | Primary Envy use | Restrictions |
| --- | --- | --- | --- | --- |
| DC++ (SF Mercurial) | active reference | Site stable **0.883** (2025-09-12); Hg on SourceForge | NMDC/ADC implementation reference | Listing ≠ Envy protocol expansion |
| [airdcpp/airdcpp-core](https://github.com/airdcpp/airdcpp-core) | active reference | Functional PRs 2026-10-04: [#551](https://github.com/airdcpp/airdcpp-core/pull/551) bloom overflow, [#541](https://github.com/airdcpp/airdcpp-core/pull/541) udpAddr, [#537](https://github.com/airdcpp/airdcpp-core/pull/537) SSL | Modern DC engine / TLS / queue | Not a reason to add ADC hubs alone |
| [airdcpp/airdcpp-windows](https://github.com/airdcpp/airdcpp-windows) | active reference | Release 4.30 (2025-09); core sync commits 2026-10-04 | Product DC client | — |
| [eiskaltdcpp/eiskaltdcpp](https://github.com/eiskaltdcpp/eiskaltdcpp) | maintenance | Commits through 2026-09 (cmake/build); last tagged release older | Secondary ADC/NMDC | Cross-platform secondary |

### 2.7 Experimental / R&D

| Repository | Class | Evidence | Primary Envy use | Restrictions |
| --- | --- | --- | --- | --- |
| [untaimed18/Ember-P2P](https://github.com/untaimed18/Ember-P2P) | active experimental | Release v1.7.1 2026-10-04 | DHT/security research ideas | **Never Kad2** |
| [ogarcia/rucio](https://github.com/ogarcia/rucio) | active experimental | Commits Oct 2026 | Daemon/Web architecture | Not CERN Rucio; not ED2K-normative |

### 2.8 Gnutella note

| Repository | Class | Evidence | Notes |
| --- | --- | --- | --- |
| [gtk-gnutella/gtk-gnutella](https://github.com/gtk-gnutella/gtk-gnutella) | active reference | Release 1.3.1 + commits 2026-03 | Independent G1 reference (#162) |
| G2 upstream | — | No strong independent modern G2 upstream found | Envy/Shareaza-lineage is the practical G2 reference |

---

## 3. Corrections vs September draft (#387 @ `6bbb7d3`)

| Topic | September draft | October 2026 |
| --- | --- | --- |
| `irwir/eMule` | historical (no qualifying activity) | **active reference P0** via `eMule_v0.72a-community` (2026-08-20) |
| `emulebb/emulebb` | active via `pushed_at` only | maintenance with release 0.7.3 + BUG-117 / ed2k_tcp commits |
| `airdcpp/airdcpp-core` | active via `pushed_at` only | active via functional PRs #551/#541/#537 (2026-10) |
| AGENTS.md soft-target removal | In scope | **Out of scope** — left on `develop` unchanged |
| Local clones | Mentioned vaguely as `Examples/` | `Examples/References/` + `tools/references/` (D-023) |
| padMule / MorphXT / NeoLoader / MLDonkey | Incomplete | Formalized in registry + this matrix |

---

## 4. Immediate local clones (ED2K/Kad workstream)

```powershell
./tools/references/sync-references.ps1 -Group ed2k-immediate
```

Clones (gitignored): `emule-community`, `amule`, `emulebb`, `emulebb-rust`,
`emule-qt`, `padmule`, `morphxt`, `neoloader`, `mldonkey`, `shareaza`.

Do **not** clone the full mods archive unless a specific audit needs it.

---

## 5. Sequencing (documentation → later code)

1. Keep this registry/audit truthful (this PR).
2. ED2K/Kad interop evidence via `tools/interop/` (#160) against eMule Community + aMule (+ MorphXT when relevant).
3. Focused protocol PRs for #86/#87/#88 remain separate — **not** this documentation PR.
4. Architecture ideas from eMule Qt / aria2-next / NeoLoader stay behind #161 boundaries.

---

## 6. Conclusions

- eMule Community remains the **primary live ED2K/Kad2 wire reference** (release evidence 2026-08).
- aMule’s active home is **amule-org/amule**.
- Modern ED2K clients (eMuleBB, emulebb-rust, padMule, eMule Qt) are valuable **below** Community/aMule for wire disputes.
- Historical mods (especially MorphXT) are interop/feature research only.
- BitTorrent stays BEP-first; DC references do not expand Envy’s protocol claims.
- Experimental overlays are never documented as Kad2.

---

## 7. eMule Qt deep audit (2026-10-20)

Scope: documentation only. Question asked: which eMule Qt lessons are **verified in its code and tests** and worth carrying into Envy's plan? No Envy production code, dependency or governance rule changes.

### 7.1 Revision examined

| Item | Value |
| --- | --- |
| Repository | <https://github.com/ModderMule/emule-qt> (GPL-2.0, `main`, 40 stars, 9 open issues) |
| Latest release (re-verified 2026-10-20) | [`v0.6.22`](https://github.com/ModderMule/emule-qt/releases/tag/v0.6.22), 2026-10-19 18:42 UTC, tag commit `069a3918` |
| `main` tip examined | `aa89127021989fd4233815bcda98f8242f7c27fe` (2026-10-19, "add rest api port change call"), one commit after the release |
| Cadence | 30 releases since 2026-03-07; 15 `v0.6.x` releases between 2026-10-08 and 2026-10-19; release notes are three bullets. A young, fast-moving single-maintainer project (first issue 2026-04-24) |
| Examined | `README.md`, `src/core/files/SharedFileList.{h,cpp}`, `SharedDirWatcher.h`, `src/core/kademlia/`, `src/core/portmap/`, `src/core/net/BindAddress.h`, `src/ipc/IpcProtocol.h`, `src/daemon/`, `tests/CMakeLists.txt`, `tests/tst_SharedFileLargeSet.cpp`, `tst_KadLiveNetwork.cpp`, `tst_SourceExchangeCompat.cpp`, `.github/workflows/*.yml`, `docs/protocol/*.md`, `docs/port-mapping.md`, open issue #39 |

Paths below are relative to that `main` tip. Authority is unchanged: eMule Qt stays **below** eMule Community and aMule for wire disputes (registry ladder).

### 7.2 Principal findings

1. **The test suite is not CI evidence.** `tests/` holds 239 `tst_*.cpp` files (README says "150+"), but every CI workflow configures with `-DEMULE_BUILD_TESTS=OFF` (`linux.yml:66`, `windows.yml:189`, `macos.yml:101`, `macos-intel.yml:109`) and the "Run tests" step is commented out in all four (`linux.yml:73-76`, `windows.yml:197-200`, `macos.yml:108-111`, `macos-intel.yml:116-119`). Tests are developer-run. Live-network tests (`tst_KadLiveNetwork`, `tst_PortMapLive`, `tst_ServerConnectLive`, ...) are built only with `-DEMULE_LIVE_TESTS=ON` (`tests/CMakeLists.txt:1007`, label `live`) and are never mixed with the default set. No sanitizer or fuzzing configuration exists in CMake, `cmake/`, `scripts/` or the workflows.
2. **Shared-folder scans are non-recursive by design**, so eMule Qt is *not* a model for Envy's recursive library scan. `SharedDirWatcher.h:6` states "the share model is one directory, no subdirectories"; `SharedFileList::listDirectory` (`SharedFileList.cpp:1563`) uses a flat `QDirIterator` with no cancellation token, run on the owner thread. Open issue #40 suspects multi-minute freezes tied to a very large shared list (unconfirmed by the reporter), and closed #9 reported 100 % disk use at startup although every file was already hashed.
3. **Its hashing design is the useful part**: one `HashingThread` per volume up to `kMaxHashWorkers = 4` (`SharedFileList.cpp:1271`, `.h:466`); path order inside a volume (`orderForHashing`, `:1297`); part-file rehash jobs queued ahead of shared files (`:65`); a generation counter that discards results of a superseded scan; an atomic cancel flag passed into `createFromFile`, `requestStop()` + `wait()` in the destructor (`:85`, `:178`); an interrupted file is neither "hashed" nor "failed" and is hashed again at next start (no mid-file resume); a persisted `HashFailureStore` with scheduled retry and give-up (`:1488-1509`, `stepDeferredScans` `:1871`); a "changed since scan" path that defers instead of failing (`:143`).
4. **Kad is a port of the MFC stack**, with extras: `KadSafeKad` (header: "Ported from eMuleAI SafeKad.h") one-node-per-IP reputation, `KadFastKad` adaptive timeouts (variance tracking), `CorroborationTally` public-IP agreement of several independent peers. Kad stays IPv4-only on purpose (`docs/protocol/ipv6-spec.md` §10.1: an IPv6 contact format "would fork the DHT"), which supports Envy's rule that Kad6 is a distinct P3 track.
5. **NAT traversal between LowID peers is *not* implemented.** `Server.h:43` parses `NatRendezvous = 0x00008000` ("parsed, unused"); `ipv6-spec.md` §9 and §10.5 mark `PR_NAT`, `ST_NAT_PORT` and uTP as out of scope. Issue [#39](https://github.com/ModderMule/emule-qt/issues/39) (opened 2026-10-20 by an aMule contributor, no maintainer reply yet) records three divergences that matter to Envy: (a) ed2k-server uses the same `OP_IDCHANGE` TCP bit `0x8000` for "accepts `OP_IPV6_UPDATE` (0x63)", so reading it as NAT rendezvous would misread those servers; (b) eMule Qt plans its own reliable-UDP layer on `0xB2` sub-type `0x10`, whereas eMuleAI/aMule use uTP (`0xB2`/`0x00`) and QUIC (`0xB2`/`0x01`), so peers could meet but not transfer; (c) ed2k-server announces a LowID hole punch (`0x60`-`0x62`, keepalive `0x9F`) with TCP flag `0x20000`. Treat as an **unsettled area**; nothing there is a protocol Envy can adopt.
6. **Port mapping is well engineered and documented** (`docs/port-mapping.md`): PCP, NAT-PMP and UPnP IGD1/IGD2 raced at startup, ranked by whether the *exact* port was granted, status `Degraded` for a different external port or a CGNAT `100.64.0.0/10` address, round extended from 3 s to 15 s only when nothing is available yet (UPnP discovery measured at 7.2 s on a normal LAN). Unit tests: `tst_PortMapWire`, `tst_PortMapper`, `tst_UdpMappingBackend`.
7. **Bind-interface policy fails closed** (`net/BindAddress.h`): a selection that does not resolve yields state `Blocked` and no socket is opened; the pin applies to UDP as well. `tst_BindInterface` covers literal/interface/subnet resolution, loopback pin, "refuses other routes", "blocked opens nothing, then resumes" and UDP pinning. This is a ready acceptance list for Envy #230 (still routing control, not anonymity).
8. **Daemon/GUI split is real**: `emulecored` and `emuleqt` link one static core library and talk over length-prefixed CBOR (`IpcProtocol.h`, 16 MiB payload cap), with IPC and core tests that run without a GUI. The optional encryption layer, however, is AES-256-CBC with the key derived as an unsalted SHA-256 of the access token (`IpcProtocol.h:874-885`) and no MAC was found in `IpcProtocol.cpp` / `IpcConnection.cpp`. **Do not copy that design.**
9. **Documentation of other clients' bugs is valuable interop evidence.** `ipv6-spec.md` §10.7 reports that at least one implementation's IPv6 UDP obfuscation key overwrites its magic byte and leaves offset 32 uninitialised, so it is not even self-consistent; §10.8 reports an ExtSX reader that drops a whole answer on one unknown tag. Both are inputs for Envy #431 and the Source Exchange vectors, to be confirmed against Community/aMule.
10. **Licence**: GPL-2.0, partly derived from eMuleAI. Envy is AGPL-3.0-or-later and `AGENTS.md` hard rule 9 forbids GPL-2.0 dependencies. No code, tables or tests are to be copied; use the principles, the scenarios, and the published specifications, then re-implement independently.

README claims that were **not** verified: "150+ test executables" (the tree has more, but none runs in CI), "51 MCP tools", "9 languages", PCP/NAT-PMP behaviour on real routers, hardened-Kad benefits on the live network.

### 7.3 Comparison eMule Qt / Envy

State vocabulary: *implemented* (code + unit tests in the tree), *partial*, *plan only* (documented, no code), *absent*. "Tests in CI" is **never** true for eMule Qt (finding 1). Envy state is taken from `develop` @ `80f091b4`.

| Area | eMule Qt (state, source) | Envy today | Decision |
| --- | --- | --- | --- |
| Recursive share scan | absent by design; flat `listDirectory`, no cancel (`SharedFileList.cpp:1563`) | recursive `CLibraryFolder::ThreadScan` under `Library.m_pSection`; fixes in PR [#467](https://github.com/Mika3578/Envy/pull/467) ([#452](https://github.com/Mika3578/Envy/issues/452), [#493](https://github.com/Mika3578/Envy/issues/493)), [#497](https://github.com/Mika3578/Envy/issues/497), [#498](https://github.com/Mika3578/Envy/issues/498), [#499](https://github.com/Mika3578/Envy/issues/499) | **No reference value.** Do not duplicate in-flight work |
| Per-volume hash workers, ordering, generations | implemented (`SharedFileList.cpp:1212-1330`) | single `CLibraryBuilder` queue; no per-volume policy ([#384](https://github.com/Mika3578/Envy/issues/384)) | **Retain** (principle), measure first (#111) |
| Cancel / shutdown during hashing | implemented; restart from byte 0 (`:85`, `:111-150`, `:178`) | scan cancellation reworked in PR #467; builder cancel not audited here | **Retain** as test scenario |
| Hash failure retry with give-up | implemented (`HashFailureStore`, `:1488-1509`, `:1871`) | none seen; enumeration retry proposed in #497 | **Retain** as design input for #497 |
| Shared-dir watcher | implemented, non-recursive; 2 s settle, 10 s max hold, 64 pending then overflow, polling for network shares (`SharedDirWatcher.h`) | none ([#385](https://github.com/Mika3578/Envy/issues/385)) | **Retain** parameters, not code |
| Large-set share tests | `tst_SharedFileLargeSet.cpp`: many small files, external path (env), reload during hashing, several directories; not run in CI | none | **Retain** scenarios for a test PR |
| Kad bootstrap / routing / search | implemented (port of MFC), unit-tested; live test optional | partial ([#86](https://github.com/Mika3578/Envy/issues/86), PR [#462](https://github.com/Mika3578/Envy/pull/462), [#430](https://github.com/Mika3578/Envy/issues/430)) | Community/aMule remain authority; eMule Qt only a secondary cross-check |
| Kad UDP firewall tester, Buddy, LowID routes | implemented (`KadFirewallTester`, `KadBuddyStore`); audit `docs/protocol/lowid-reachability-audit.md` | TCP firewall baseline only; UDP tester, Buddy, callback absent (`status.md`) | **Retain** audit as checklist for #86 |
| Sybil/eclipse hardening, adaptive timeouts | implemented (`KadSafeKad`, `KadFastKad`) | `/24` diversity, 1 ID per IP, two-peer public-IP agreement | **Defer** (P2 DHT/security research bucket); eMuleAI-derived |
| Kad IPv6 | absent by design (`ipv6-spec.md` §10.1) | absent; Kad6 = P3 | Confirms Envy's plan |
| Source Exchange compatibility tests | `tst_SourceExchangeCompat.cpp` (79 cases, foreign readers modelled in-test) | SX v1/v2 IPv4-only, live interop unverified ([#160](https://github.com/Mika3578/Envy/issues/160), [#87](https://github.com/Mika3578/Envy/issues/87)) | **Retain** scenarios; **reject** ExtSX itself (mod extension) |
| TCP/UDP obfuscation | implemented, default on; IPv6 UDP key caveat documented | not implemented ([#431](https://github.com/Mika3578/Envy/issues/431)); Hello crypt bits stay 0 | **Retain** caveat for #431 |
| LowID-to-LowID NAT traversal | plan only (`Server.h:43`, issue #39) | none; Envy defines no `0x00008000` server flag (`Envy/EDPacket.h:368-375`) | **Guard**: do not advertise or act on it |
| PCP / NAT-PMP / UPnP | implemented, exact-port grading, CGNAT = Degraded (`docs/port-mapping.md`) | MiniUPnPc only (`Envy/MiniUPnP.cpp`); PCP/NAT-PMP planned as P4/P5 in the plan, no issue | **Retain** grading principle; RFC 6886/6887 are the authority |
| Bind interface / leak policy | implemented, fail-closed, TCP+UDP (`BindAddress.h`) | none ([#230](https://github.com/Mika3578/Envy/issues/230), P3) | **Retain** as #230 acceptance list |
| IPv6 dual-stack (C2C, C2S) | implemented per its own spec; Kad IPv4-only | partial ([#89](https://github.com/Mika3578/Envy/issues/89), `docs/ipv6/PLAN.md`) | Secondary checklist only |
| Core/daemon/GUI split, IPC | implemented; GUI-less tests | not implemented ([#161](https://github.com/Mika3578/Envy/issues/161), [#91](https://github.com/Mika3578/Envy/issues/91)) | **Retain** principle; **reject** IPC crypto |
| REST API, OpenAPI, API key, CORS | implemented (`docs/rest-api.md`) | planned native `/api/v1` ([#239](https://github.com/Mika3578/Envy/issues/239), [#240](https://github.com/Mika3578/Envy/issues/240)) | **Retain** design points |
| CLI control | implemented (`CliIpcClient`, `--add-link`, ...) | none | Fold into #161 later |
| MCP endpoint | implemented (README: 51 tools, not counted) | none | **Reject** (no need, new attack surface) |
| Categories, rule-based auto-download | categories implemented; feeds are Usenet/newznab | [#232](https://github.com/Mika3578/Envy/issues/232), [#241](https://github.com/Mika3578/Envy/issues/241), [#352](https://github.com/Mika3578/Envy/issues/352) | **Defer** (P3/P4), ideas only |
| Persistent statistics, upload-queue store, source saver | implemented (`StatsHistory`, `UploadQueueStore`, `SourceSaver`) | not found in `Envy/` by search; [#233](https://github.com/Mika3578/Envy/issues/233), [#316](https://github.com/Mika3578/Envy/issues/316) cover persistence/diagnostics | **Defer** (P3/P4) |
| Fake-file detector, DLP | implemented (warn-only confidence column; DLP) | none | **Defer** (P4); interacts with ban policy [#319](https://github.com/Mika3578/Envy/issues/319) |
| HTTP cache, Usenet/NNTP/indexers, Qt 6 / C++23 | implemented, project-specific | out of scope | **Reject** (new protocol / new network / global toolkit migration) |
| Tests and CI | 239 test files, none run in CI; no fuzz/sanitizers | EnvyTests in staged CI; fuzzing [#229](https://github.com/Mika3578/Envy/issues/229) | Do not cite its test count as evidence |

### 7.4 Retained candidates (benefit, risk, cost, tests)

| ID | Candidate | Benefit | Risks (security / compat / maintenance) | Complexity, dependencies | Tests needed | Priority, issue |
| --- | --- | --- | --- | --- | --- | --- |
| C1 | Do not advertise or act on `0x00008000` / `0xB2` sub-type transports; record the #39 divergence | Prevents an interop break with ed2k-server and aMule/eMuleAI | None (documentation guard) | None | None (Hello/flag golden tests already exist) | P0 guard, no issue |
| C2 | Kad LowID / Buddy / callback checklist from `lowid-reachability-audit.md` | Faster review of the open #86 remainder | Wrong if copied from the MFC port without Community check | Documentation | Community/aMule captures via #160 | P1, [#86](https://github.com/Mika3578/Envy/issues/86) |
| C3 | IPv6 UDP-obfuscation key caveat + clear-vs-obfuscated dispatch | Avoids implementing a known non-interoperable key | Wire format: high | After #431 design | Golden vectors from aMule/Community | P1, [#431](https://github.com/Mika3578/Envy/issues/431) |
| C4 | Core library shared by GUI and headless daemon; IPC/API tests with no UI | Proves the EnvyCore boundary early | Large refactor if done wide; keep incremental | Existing CMake portable slice (D-015) | Parser/state tests without MFC (#91) | P1, [#161](https://github.com/Mika3578/Envy/issues/161) / [#91](https://github.com/Mika3578/Envy/issues/91) |
| C5 | Per-volume hash workers, directory-order hashing, generation-tagged results | Less HDD thrash, bounded back-pressure | Threading/locking: needs targeted tests; Envy hashing runs under library locks | Moderate; no new dependency; needs #111 baseline | Multi-volume simulation, cancel/restart, lock-contention bench | P2, [#384](https://github.com/Mika3578/Envy/issues/384) (with [#498](https://github.com/Mika3578/Envy/issues/498)) |
| C6 | Watcher tuning: settle time, max hold, overflow to full rescan, poll network shares | Stable incremental library | Recursion and `ReadDirectoryChangesW` buffer overflow differ from Qt | Moderate; Win32 API only | Burst copy, overflow, SMB share | P2, [#385](https://github.com/Mika3578/Envy/issues/385) |
| C7 | REST design points: key header or bearer, unauthenticated `/health`, OpenAPI document written from an API registry (`ApiRegistry.cpp`, `OpenApiWriter.cpp`), explicit CORS allow-list | Aligns with D-017 contract-first | Auth/CORS mistakes; localhost bind policy [#390](https://github.com/Mika3578/Envy/issues/390) | Part of #239 | Auth failure, CORS, malformed JSON | P2, [#239](https://github.com/Mika3578/Envy/issues/239) |
| C8 | Fuzz/sanitizer targets modelled on the *scenarios* in eMule Qt packet/tag/IPC tests | Reuse of hostile-input cases | eMule Qt has no fuzzing itself; shallow malformed coverage in Kad IO and UDP listener tests | Moderate | Corpus seeded from Community/aMule traffic | P2, [#229](https://github.com/Mika3578/Envy/issues/229) |
| C9 | Port-mapping grading rules: exact-port match first, `Degraded` for CGNAT or port change, extended discovery round | Honest reachability status | Router-specific behaviour; UPnP latency (#142) | Plan P4/P5; new PCP/NAT-PMP client per RFC 6886/6887 | Wire-format unit tests, fake gateway | P2, plan items only (no issue yet) |
| C10 | Bind/VPN acceptance list (fail closed, UDP pinned, resume on re-resolution) | Concrete #230 criteria | Must never be described as anonymity | Depends on core socket layer | Interface down/up, dual-stack | P3, [#230](https://github.com/Mika3578/Envy/issues/230) |
| C11 | Bounded retry with give-up for failed hashing/enumeration | Fewer silent omissions | Retry storms on dead shares | Small | Transient vs permanent failure | P3, [#497](https://github.com/Mika3578/Envy/issues/497) |
| C12 | Share-scan regression scenarios (many files, reload during hashing, several roots, shutdown during hashing) | Cheap regression net for #467 follow-ups | None | Small, MFC-free helpers preferred | Listed scenarios | P3, [#467](https://github.com/Mika3578/Envy/pull/467) follow-up |
| C13 | Source persistence, upload-queue persistence, categories, persistent statistics, fake-file score | UX and resume quality | Privacy (persisted peer data), heuristics produce false positives | Each moderate | Per feature | P3/P4, [#233](https://github.com/Mika3578/Envy/issues/233), [#232](https://github.com/Mika3578/Envy/issues/232), [#316](https://github.com/Mika3578/Envy/issues/316) |

### 7.5 Rejected or deferred

| Item | Verdict | Reason |
| --- | --- | --- |
| Copying any eMule Qt code, tables or tests | **Rejected** | GPL-2.0 vs AGPL-3.0-or-later; hard rule 9; independent re-implementation only, with legal validation first |
| Qt 6 / C++23 migration, Qt GUI | **Rejected** | D-012/D-013; no toolkit change in the EnvyCore track |
| LowID NAT-T flags and own reliable-UDP transport (`0x8000`, `0xB2`/`0x10`) | **Rejected** for now | Unsettled across eMule Qt, aMule and eMuleAI (#39); would be a new protocol |
| HTTP cache extension | **Rejected** | Project-specific protocol with no Community/aMule support |
| ExtSX (`CT_MOD_MISCOPTIONS` bit `0x20`), Kad `ip6`/`bi6` tags | **Rejected** | Mod-level extensions; bit tables are contested (#39 §2) |
| Usenet/NNTP module, newznab indexers, MCP server | **Rejected** | Not an Envy network or goal; MCP adds attack surface |
| IPC AES-256-CBC with unsalted SHA-256 key and no MAC | **Rejected** | Weak design; Envy's API is HTTP REST (D-017) |
| `KadSafeKad` reputation, adaptive Kad timeouts | **Deferred** | eMuleAI-derived; wait for live Kad2 baseline (#86/#160) |
| Fake-file detector, DLP, upload-queue/source persistence | **Deferred** | Product features after P0/P1; DLP interacts with ban policy (#319) |

### 7.6 Priority list (P0 to P4)

Priorities follow `docs/DEVELOPMENT_PLAN.md`. **Nothing here changes an existing priority**; the audit adds evidence to open issues.

- **P0**: #160 live interop and #86 Kad firewall/Buddy/callback stay first. Guard C1 (no NAT-T bits). C2 supports #86.
- **P1**: C3 on #431; C4 on #161/#91; #89 IPv6 stays (eMule Qt spec is a secondary checklist).
- **P2**: C5 on #384 (+#498, after #111 baseline, PR #368); C6 on #385; C7 on #239; C8 on #229; C9 PCP/NAT-PMP (plan P4/P5, after #142/P3 MiniUPnPc).
- **P3**: C10 on #230; C11 on #497; C12 follow-up to PR #467; SafeKad-style research under the existing P2 DHT/security bucket.
- **P4**: C13 convenience features (#232, #316, #333, #344), fake-file confidence column, DLP.

No new issue is justified: every retained item is covered by an open issue or an existing plan item. Suggested comments on #384, #385, #431, #230, #497 and #86 are drafted in `.local/DEV_TRACKER.md` and are not posted.

### 7.7 Suggested order of technical PRs

1. Land in-flight work first and do not duplicate it: PR #467 (share scan, #452/#493), PR #462 (Kad bootstrap rotation, #430).
2. Test-only PR: Source Exchange conformance vectors against Community/aMule framing, byte-identical classic output for peers without the capability, hostile-input reader cases (#87, #91).
3. Test-only PR: share-scan scenarios C12 on top of #467.
4. Kad UDP firewall tester, Buddy and callback from Community sources (#86), after #462.
5. UDP and TCP obfuscation design with golden vectors (#431).
6. Measure then change: benchmark harness (PR #368, #111) before per-volume hash workers (#384/#498).
7. Library watcher (#385) once #499 lock-hold work is measured.
8. Fuzz harness for pure parsers (#229).
9. Bind policy design (#230) once the core socket layer (#179/#89) exists.
10. PCP/NAT-PMP client (plan P4) after MiniUPnPc 2.3.x (#142).

### 7.8 Limits of this audit

- eMule Qt was read, not built or run; its tests were not executed and no live network test was attempted.
- Line references are to `main` @ `aa891270`; the repository moves daily (a release on most days in October), so every number above is a dated snapshot.
- Test-count and keyword statistics are file-level counts, not coverage measurements.
- Envy "absent" statements for persistence features (source saver, upload-queue store, fake-file detector, PCP/NAT-PMP) come from searching `Envy/`; they are not an exhaustive code review.
- Issue #39 is one day old and unanswered; the positions of aMule and eMuleAI cited there were not independently re-checked against their sources.
- The September audit file referenced by issues #384/#385 does not exist in this tree (see the header); the claims there were not reused.

---

## Related documents

- Canonical registry: [`REFERENCE_IMPLEMENTATIONS.md`](REFERENCE_IMPLEMENTATIONS.md)
- Local clone workflow: [`tools/references/README.md`](../../tools/references/README.md)
- Decisions: D-008 (trust order), D-023 (local clones) in `docs/DECISIONS.md`
- Envy status: `docs/10_dev/status.md`
