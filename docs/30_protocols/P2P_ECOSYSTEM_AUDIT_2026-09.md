# P2P ecosystem audit (September 2026)

Status: research / audit pass (no implementation)
Last updated: 2026-09-29
Base commit: `develop` @ `ed57142ba9fce7409f97c92e03da716029eeaee6`
Scope: Open-source P2P clients and engines compared against Envy code, docs, and GitHub tracker.
Authority: specifications and BEPs first; `docs/10_dev/status.md` for Envy claims; `docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md` for canonical reference list.

This document is the **detailed** ecosystem cross-check. The reference list stays concise; this audit holds evidence tables, gap mapping, and sequencing notes.

---

## 1. Methodology

### 1.1 Envy inventory (2026-09-29)

| Source | Count / notes |
| --- | --- |
| Open issues | 81 |
| Open PRs | 12 (snapshot at audit start; no numeric repository cap applies) |
| Discussions | 1 |
| Open development PR themes | CI review automation (#383/#382), benchmarks (#368), connection capacity (#367), NMDC (#358), tooling (#380/#379/#351), community (#370/#369), dependency automation (#327) |

Documents read: `AGENTS.md`, `docs/10_dev/status.md`, `docs/10_dev/roadmap.md`, `docs/DEVELOPMENT_PLAN.md`, `docs/KNOWN_LIMITATIONS.md`, `docs/20_arch/PORTABILITY_PLAN.md`, `docs/20_arch/remote-api.md`, `docs/DECISIONS.md`, `docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md`, `docs/20_arch/AUDIT_REMOTE_API_2026-09.md`.

### 1.2 External “actively maintained” criteria

A repository was classified **active** only when 2025–2026 evidence included functional commits, merged PRs, protocol work, or releases — not merely `pushed_at` from bots, Weblate-only merges, or README edits.

Status classes used in the matrix:

- **active reference** — maintained; use for interop and behaviour comparison
- **active experimental** — maintained but not normative for wire compatibility
- **maintenance only** — fixes/releases without protocol innovation
- **historical reference** — useful archive, not modern behaviour
- **inactive / discontinued** — abandoned or explicitly discontinued

### 1.3 Cross-check rules

For each upstream finding: Envy code search → open/closed issues → open PRs → docs. Actions: `no action`, `documentation only`, `update existing issue`, `new issue`, `Discussion`, `future research`, `security/test follow-up`.

---

## 2. Active repository matrix (verified sample)

**Projects examined:** 41 repositories across ED2K/Kad, BitTorrent, Direct Connect, Gnutella/G2, Soulseek (architecture), and modern P2P architecture (not new Envy protocols).

| Repository | Class | Last meaningful activity (evidence) | Primary Envy use |
| --- | --- | --- | --- |
| [amule-org/amule](https://github.com/amule-org/amule) | active reference | Releases 3.0.0–3.1.0 (2026-06–09); core PRs e.g. [#1686](https://github.com/amule-org/amule/pull/1686), [#1638](https://github.com/amule-org/amule/pull/1638) | ED2K/Kad interop, headless, upload I/O |
| [amule-project/amule](https://github.com/amule-project/amule) | historical redirect | `pushed_at` 2026-06; superseded by **amule-org** | Legacy links only |
| [irwir/eMule](https://github.com/irwir/eMule) | historical reference | No qualifying 2025–2026 functional activity verified | P0 ED2K/Kad wire |
| [eMuleAI/eMuleAI](https://github.com/eMuleAI/eMuleAI) | active experimental | README + issues (NAT, uTP, IPv6 claims); [#174](https://github.com/eMuleAI/eMuleAI/issues/174) endgame | Reachability ideas; not normative |
| [ModderMule/emule-qt](https://github.com/ModderMule/emule-qt) | active reference | Qt6/C++23 ED2K/Kad fork | #161 architecture |
| [emulebb/emulebb](https://github.com/emulebb/emulebb) | active reference | `pushed_at` 2026-09 | Library, REST, VPN binding patterns |
| [emulebb/emulebb-rust](https://github.com/emulebb/emulebb-rust) | active experimental | Daemon/API direction | #161/#239/#230 ideas |
| [untaimed18/Ember-P2P](https://github.com/untaimed18/Ember-P2P) | active experimental | R&D overlay | #86 security ideas only |
| [ogarcia/rucio](https://github.com/ogarcia/rucio) | active experimental | P2P client (not CERN Rucio) | Architecture |
| [diad87/eMule-eSE-LiveTV](https://github.com/diad87/eMule-eSE-LiveTV) | active experimental | Kad6/IPv6 R&D | P3 only |
| [arvidn/libtorrent](https://github.com/arvidn/libtorrent) | active reference | [v2.1.2](https://github.com/arvidn/libtorrent/releases/tag/v2.1.2) 2026-09-25 | #88 BEP matrix |
| [qbittorrent/qBittorrent](https://github.com/qbittorrent/qBittorrent) | active reference | [v5.2.4](https://github.com/qbittorrent/qBittorrent/releases) / 5.3.0rc1 (2026-09) | #88/#240/#230 |
| [transmission/transmission](https://github.com/transmission/transmission) | active reference | BEP-55 [#3705](https://github.com/transmission/transmission/issues/3705) closed | #88 hole punch |
| [deluge-torrent/deluge](https://github.com/deluge-torrent/deluge) | active reference | libtorrent-based | BT policy |
| [BiglySoftware/BiglyBT](https://github.com/BiglySoftware/BiglyBT) | active reference | Swarm merging, tags, I2P | #231 merging semantics |
| [webtorrent/webtorrent](https://github.com/webtorrent/webtorrent) | active reference | WebRTC swarm | P3 after #88 |
| [anacrolix/torrent](https://github.com/anacrolix/torrent) | active reference | Go engine | Endgame, trackers |
| [ikatson/rqbit](https://github.com/ikatson/rqbit) | active reference | Rust BT | uTP robustness class |
| [Tribler/tribler](https://github.com/Tribler/tribler) | active experimental | Research client | Not a protocol target |
| [AnInsomniacy/aria2-next](https://github.com/AnInsomniacy/aria2-next) | active reference | BT+ED2K RPC | #161/#239 |
| [c0re100/qBittorrent-Enhanced-Edition](https://github.com/c0re100/qBittorrent-Enhanced-Edition) | active experimental | Peer filtering | Interop reference only |
| [airdcpp/airdcpp-core](https://github.com/airdcpp/airdcpp-core) | active reference | `pushed_at` 2026-09 | #163 ADC/NMDC |
| [airdcpp-web/airdcpp-webclient](https://github.com/airdcpp-web/airdcpp-webclient) | active reference | Security issues 2026 | #229/#239 negative tests |
| [eiskaltdcpp/eiskaltdcpp](https://github.com/eiskaltdcpp/eiskaltdcpp) | active reference | ADC+NMDC | #163/#229 |
| [direct-connect/go-dcpp](https://github.com/direct-connect/go-dcpp) | active reference | Modern ADC/NMDC | #163 |
| [gtk-gnutella/gtk-gnutella](https://github.com/gtk-gnutella/gtk-gnutella) | active reference | Last commit 2026-03-31 | #162 G1 |
| [Mika3578/Envy](https://github.com/Mika3578/Envy) | product | Primary G2 maintainer | G2 baseline |
| [GetEnvy/Envy](https://github.com/GetEnvy/Envy) | historical reference | Sparse commits | Archive |
| [ansani/Shareaza](https://github.com/ansani/Shareaza) | historical reference | Limited 2024 protocol work | Lineage only |
| [savthe/sharelin](https://github.com/savthe/sharelin) | inactive | README: discontinued | Do not track |
| [nicotine-plus/nicotine-plus](https://github.com/nicotine-plus/nicotine-plus) | active reference | [3.3.11](https://github.com/nicotine-plus/nicotine-plus/releases/tag/3.3.11) 2026-09-16 | #311 UI/search scale |
| [slskd/slskd](https://github.com/slskd/slskd) | active reference | [0.26.0](https://github.com/slskd/slskd/releases/tag/0.26.0) | #161/#311 daemon |
| [jpdillingham/Soulseek.NET](https://github.com/jpdillingham/Soulseek.NET) | active reference | Library patterns | #311 pagination |
| [syncthing/syncthing](https://github.com/syncthing/syncthing) | active reference | File watcher, recovery | Watcher/recovery ideas |
| [libp2p/go-libp2p](https://github.com/libp2p/go-libp2p) | active reference | NAT, relay, QUIC | #86/#89/#230 concepts |
| [ipfs/kubo](https://github.com/ipfs/kubo) | active reference | DHT at scale | Search/index ideas |
| [PurpleI2P/i2pd](https://github.com/PurpleI2P/i2pd) | active reference | Metrics, limits | Observability patterns |
| [n0-computer/iroh](https://github.com/n0-computer/iroh) | active reference | QUIC/NAT | #230 recovery |
| [RetroShare/RetroShare](https://github.com/RetroShare/RetroShare) | maintenance only | Friend-network model | Not Envy target |
| [hyphanet/fred](https://github.com/hyphanet/fred) | active reference | Distributed storage | Architecture only |
| [schollz/croc](https://github.com/schollz/croc) | active reference | Direct transfer | Not multi-network |

**Reclassified as historical / low priority for monitoring:** IronMule, karthiUTH/emulemorph, fmpfeifer Shareaza IPv6 forks (pre-2020 meaningful code); **sharelin** discontinued.

---

## 3. Protocol findings (summary)

### 3.1 ED2K / Kad

**Upstream (verified):**

- Active aMule development is on **amule-org/amule** (releases through 3.1.0, September 2026).
- aMule recent work includes share verification persistence ([#1638](https://github.com/amule-org/amule/pull/1638)), upload I/O issues ([#1585](https://github.com/amule-org/amule/issues/1585)–[#1605](https://github.com/amule-org/amule/issues/1605)), Kad/search PRs ([#1663](https://github.com/amule-org/amule/pull/1663), [#1670](https://github.com/amule-org/amule/pull/1670)), QUIC NAT scaffolding ([#1672](https://github.com/amule-org/amule/pull/1672)).
- eMuleAI documents NAT/uTP/IPv6; open [#174](https://github.com/eMuleAI/eMuleAI/issues/174) (endgame), [#173](https://github.com/eMuleAI/eMuleAI/issues/173) (uTP unsolicited traffic), [#171](https://github.com/eMuleAI/eMuleAI/issues/171) (SourceEx fail-soft).

**Envy evidence:**

- Kad2 partial implementation documented in `docs/10_dev/status.md` (#86 slices landed).
- **Endgame exists per protocol:** `Settings.BitTorrent.Endgame`, `Settings.eDonkey.Endgame`, `CDownloadTransfer::SelectBlock(..., bEndGame)`, activation in `DownloadTransferBT.cpp` / `DownloadTransferED2K.cpp`.
- **Gap:** no documented **cross-protocol** endgame coordinator tied to #231 hash-proven identity; duplicate-request caps and cancel-on-first-valid not audited against eMuleAI/aMule.
- `Library.WatchFolders` toggles **periodic** scan timing (`Library.cpp`); not `ReadDirectoryChangesW` incremental watcher.

### 3.2 BitTorrent

**Upstream:** libtorrent 2.1.2 (2026-09-25); BEP-55 implementation evidence is recorded for Transmission ([#3705](https://github.com/transmission/transmission/issues/3705)). WebTorrent default-on trajectory in libtorrent 2.1.x.

**Envy evidence:** #88 tracks uTP/v2/IPv6 PEX; `Services/LibUTP` vendored, **unused** (`docs/10_dev/status.md`). BEP-55 not explicit in #88 body (addressed via issue update).

### 3.3 Direct Connect

**Upstream:** AirDC++ core active; AirDC Web 2026 security classes (e.g. [#543](https://github.com/airdcpp-web/airdcpp-webclient/issues/543) TigerTree over-read, [#530](https://github.com/airdcpp-web/airdcpp-webclient/issues/530) SSRF). Eiskalt: DHT poisoning / path traversal classes.

**Envy:** NMDC implemented; ADC/ADCS #163; fuzzing #229.

### 3.4 Gnutella / G2

**G1:** gtk-gnutella remains the independent maintained G1 reference (2026 commits).
**G2:** No active independent modern upstream; Shareaza-lineage forks stagnant or discontinued. **Envy is positioned to be a primary maintained G2 implementation** (#162 audit).

### 3.5 Soulseek / architecture

Not protocol targets. Use for **search pagination**, large libraries, daemon/API (#311, #161), disk-slow UI (#295).

---

## 4. Envy gap mapping (selected)

| Upstream finding | Evidence | Relevant? | Envy code / doc | Tracker | Action |
| --- | --- | --- | --- | --- | --- |
| aMule org migration | amule-org releases 2026 | Yes | Old URLs in docs | — | Update `REFERENCE_IMPLEMENTATIONS.md` |
| BEP-55 hole punch | Transmission/libtorrent | Yes | Not wired | #88 | Update issue |
| uTP + UDP hardening | #88, LibUTP unused | Yes | Vendored only | #88, #229 | Update issues |
| SourceEx fail-soft | eMuleAI #171 | Yes | SourceEx2 #331 | #87 | Update issue |
| Kad bootstrap trust | Eiskalt/libp2p ideas | Yes | Kad partial | #86, #229 | Update issue |
| Per-protocol endgame | Envy BT+ED2K | Partial | `DownloadTransfer*.cpp` | #231, #343 | Update #231 (not new issue) |
| Storage-aware hashing | eMuleBB, AirDC | Yes | `LibraryBuilder` no volume policy | — | **New issue** |
| Incremental share watcher | Syncthing, aMule | Yes | `WatchFolders` = periodic | #352 distinct | **New issue** |
| OpenMetrics | i2pd, aMule daemon | Yes | `ED2KMetrics` UI-only | #111, #161 | Update issues |
| WebTorrent/WebRTC | libtorrent 2.1 | Later | Not implemented | #88 | Discussion + #88 |
| Network sleep/recovery | Syncthing, iroh | Yes | No central epoch | #230 | Update issue |
| AirDC Web API security | 2026 CVE-class issues | Yes | Remote/API planned | #229, #161, #239 | Update issues |
| Swarm merging | BiglyBT | Yes | #231 architecture | #231 | Update issue |
| G2 upstream absent | sharelin discontinued | Yes | Envy G2 in-tree | #162 | Update issue |

Full candidate verification for **A–F** (prompt section 7):

| Candidate | Verdict |
| --- | --- |
| A cross-protocol endgame | **Partially implemented** per protocol; gap = coordination + bounds + #231 → update #231/#343 |
| B storage-aware hashing | **Gap** → new issue |
| C library watcher | **Gap** (periodic vs FS notify) → new issue; not #352 |
| D OpenMetrics | **Gap** for EnvyCore → extend #111/#161 |
| E WebTorrent | **Planned P3** → Discussion + #88 matrix |
| F network recovery | **Gap** → extend #230 |

---

## 5. Existing issue mapping (priority list)

Issues receiving **2026-09 ecosystem cross-check** comments on GitHub: #86, #87, #88, #111, #161, #163, #162, #229, #230, #231, #233, #239, #311, #318, #319, #343, #344.

New issues created from this audit: #384 (storage-aware hashing); #385 (incremental shared-library watcher).

Discussion: [Exploratory: WebTorrent/WebRTC priority after #88](https://github.com/Mika3578/Envy/discussions/386).

---

## 6. Recommended sequencing

1. P0/P1 interop and security: #87, #86, #88 (transport + BEP-55), #229 negative tests, #160 harness.
2. Architecture: #161 + #239 with API security envelope; #111 benchmarks before #343/#344 policy changes.
3. Multi-network advantage: #231 before expanding independent per-protocol engines.
4. P2/P3: library watcher + storage-aware hashing; WebTorrent spike after #88 baseline; G2 leadership via #162.

---

## 7. Conclusions

- Envy’s tracker already covers most “fashionable” gaps (ADC, IPv6, VPN binding, REST, BT v2, cross-network identity). This audit **narrows** net-new work to a small set and **enriches** existing issues with upstream evidence.
- The differentiator remains **multi-network fragment space with hash-proven identity** (#231), not cloning a single-protocol client.
- **Do not** treat eMuleAI/Ember/eSE wire experiments as Kad2/eMule standards (D-008).
- Implementation of audit findings is **out of scope** for this document; land via focused PRs per issue.

---

## Related documents

- `docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md` — canonical concise reference list (updated 2026-09-29)
- `docs/20_arch/AUDIT_REMOTE_API_2026-09.md` — Remote API security baseline
- `docs/10_dev/status.md` — Envy feature truth
