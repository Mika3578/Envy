# Reference implementations

Status: active
Last updated: 2026-10-07
Scope: External P2P projects used as interoperability, architecture, and research references for Envy.
Source of truth: protocol specifications first; this document is the complementary **registry**. Canonical Envy status is `docs/10_dev/status.md`.

**Local clones (optional, gitignored):** `Examples/References/<id>/` via
[`tools/references/`](../../tools/references/README.md). Do not vendor sources,
add submodules, or couple the Envy build to these trees. Decision: D-023.

Verification snapshot below reflects GitHub/SourceForge checks on **2026-10-07**.
Do not treat GitHub page `updated_at` alone as "maintained"; prefer commits and releases.
Detailed evidence tables: [`P2P_ECOSYSTEM_AUDIT_2026-10.md`](P2P_ECOSYSTEM_AUDIT_2026-10.md).

---

## Policy

**Specification first, interoperability implementation second.**

Envy remains a **Windows-native multi-network** client. No project listed here
replaces Envy. Compare behaviour and architecture; adapt to Envy's licence
(AGPL-3.0-or-later), MFC codebase, and existing networks.

Presence of a feature in a reference project does **not** mean Envy implements
it or should add that protocol. Envy claims need Envy code, tests, or an
explicit roadmap item.

### Authority hierarchy (mandatory)

When sources disagree, prefer in this order:

1. Protocol specification / RFC / BEP / ADC / primary protocol documentation
2. Live interoperability evidence (Envy <-> reference client)
3. Established reference implementation (eMule Community, aMule)
4. Other maintained implementations (eMuleBB, eMule Qt, padMule, libtorrent, ...)
5. Historical mods (MorphXT, Xtreme, StulleMule, ...)
6. Experimental / R&D (Ember, eMule eSE, NeoKad-style overlays, Rucio)

#### ED2K / Kad ladder

```text
Specification / protocol docs
    ↓
eMule Community          (normative wire reference)
    ↓
aMule                    (interop oracle + daemon architecture)
    ↓
eMuleBB / emulebb-rust / eMule Qt / padMule / eMule AI / aria2-next
    ↓
MorphXT / Xtreme / StulleMule / other historical mods
    ↓
Ember / eMule eSE / NeoKad-style experiments
```

Never document Ember, eSE, or NeoLoader overlays as Kad2 or eMule standard.

### Field legend

| Field | Meaning |
| --- | --- |
| Project | Display name |
| Official repository | Canonical upstream (prefer official org over random forks) |
| Domain | ED2K, Kad, BitTorrent, G1/G2, DC, architecture, UI, API, ... |
| Role | wire reference, interoperability, architecture, historical mod, experimental |
| Priority | P0 / P1 / P2 / P3 for Envy attention |
| Authority | `normative` · `interoperability` · `implementation` · `architecture` · `historical` · `experimental` |
| Active status | `active` · `maintenance` · `historical` |
| Last verified | Date this registry row was checked |
| Verified revision | Tag or commit consulted when useful (evidence, not `pushed_at`) |
| Local directory | Recommended clone path under `Examples/References/` |
| Notes | Limits and usage restrictions |

---

## Official specifications (always preferred)

### ED2K

- Kulbak & Bickson, *The eMule Protocol Specification* (via aMule wiki)
- aMule ED2K protocol wiki: <https://wiki.amule.org/wiki/Ed2k_protocol>
- aMule ED2K overview: <https://amule-org.github.io/docs/p2p-networks/ed2k>
- ED2K URI / link specification: <https://wiki.amule.org/wiki/Ed2k_link>
- Gaps (credits, SecureIdent RSA, Source Exchange edge cases, HighID/LowID): clarify from eMule Community / aMule sources

### Kad

- Maymounkov & Mazieres Kademlia paper: <https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf>
- Kad2 opcodes / contacts / publish / search / firewall / Buddy: eMule Community and aMule Kad sources only to fill documentation gaps
- Experimental NAT / overlay schemes are **not** Kad2

### BitTorrent

- BEP index: <https://www.bittorrent.org/beps/bep_0000.html>
- Especially BEP 3, 5, 6, 9, 10, 11, 15, 29, 32, 52, 55 - **BEP before any client**

### Gnutella / Gnutella2

- Gnutella 0.6 draft: <http://rfc-gnutella.sourceforge.net/src/rfc-0_6-draft.html>
- G2 / Shareaza notes; Envy's G1/G2 stack is Shareaza-derived (preserve; not deprecated by ED2K work)

### Direct Connect

- NMDC: <https://nmdc.sourceforge.net/NMDC.html>
- ADC: <https://adc.sourceforge.io/ADC.html>
- ADC-EXT: <https://adc.sourceforge.io/ADC-EXT.html>
- Registry presence does **not** mean Envy must expand NMDC/ADC support

---

## Registry summary

### P0 - ED2K / Kad authority

| Project | Official repository | Domain | Role | Priority | Authority | Active status | Last verified | Verified revision | Local directory | Notes / restrictions |
| --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- | --- |
| eMule Community | <https://github.com/irwir/eMule> | ED2K, Kad2 | wire reference | P0 | normative | active | 2026-10-07 | tag `eMule_v0.72a-community` (2026-08-20) | `Examples/References/emule-community/` | Primary wire oracle. Community release is qualifying activity (not `pushed_at`). |
| aMule | <https://github.com/amule-org/amule> | ED2K, Kad | interoperability | P0 | interoperability | active | 2026-10-07 | release `3.1.0` (2026-09-21); tip ~`46f0b12b` | `Examples/References/amule/` | **Canonical active org.** `amule-project/amule` is legacy/frozen. |

### P1 - Modern ED2K / Kad implementations and architecture

| Project | Official repository | Domain | Role | Priority | Authority | Active status | Last verified | Verified revision | Local directory | Notes / restrictions |
| --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- | --- |
| eMuleBB | <https://github.com/emulebb/emulebb> | ED2K, Kad, API | implementation / architecture | P1 | implementation | maintenance | 2026-10-07 | tag `emulebb-v0.7.3`; BUG-117 / ed2k_tcp commits 2026-07 | `Examples/References/emulebb/` | Stable MFC 0.7.x line. Not Kad2-normative. |
| emulebb-rust | <https://github.com/emulebb/emulebb-rust> | ED2K, Kad | implementation | P1 | implementation | active | 2026-10-07 | tip ~`e6f20a59` (2026-10-06); beta nightlies | `Examples/References/emulebb-rust/` | Experimental Rust client; parsers/tests. |
| eMule Qt | <https://github.com/ModderMule/emule-qt> | architecture, API | architecture | P1 | architecture | active | 2026-10-07 | release `v0.5.6`; tip 2026-10-07 | `Examples/References/emule-qt/` | Daemon / IPC / REST / Web UI ideas for incremental `EnvyCore` split. |
| eMule AI | <https://github.com/eMuleAI/eMuleAI> | IPv6, NAT | architecture | P1 | architecture | active | 2026-10-07 | release `eMuleAI_v1.6` (2026-07-25) | `Examples/References/emule-ai/` | Reachability ideas only; not ED2K-normative. |
| padMule | <https://github.com/ajbufort/padMule> | ED2K, Kad | implementation | P1 | implementation | active | 2026-10-07 | tip ~`ce2d91b9` (2026-08-14) | `Examples/References/padmule/` | Rust engine; documents eMule 0.50a wire authority and aMule differential oracle. |

### P2 - Historical ED2K mods (never wire authority)

Clone individually only when an audit needs them. Prefer the bulk archive for browsing.

| Project | Official / practical source | Domain | Role | Priority | Authority | Active status | Last verified | Verified revision | Local directory | Notes / restrictions |
| --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- | --- |
| MorphXT | SF [emulemorph](https://sourceforge.net/projects/emulemorph/); GitHub mirror [Stullemon/emulemorph](https://github.com/Stullemon/emulemorph) | ED2K | historical mod / **interop test target** | P2 | historical | historical | 2026-10-07 | MorphXT 12.7 src (2012); mirror tip 2020-11-18 | `Examples/References/morphxt/` | Special Envy <-> MorphXT interop interest. Not modern wire authority. |
| Xtreme | Via [emulebb-mods-archive](https://github.com/emulebb/emulebb-mods-archive) | ED2K | historical mod | P2 | historical | historical | 2026-10-07 | archive tree `eMule-0.50a-Xtreme-8.1-src` | (archive) | Feature research only. |
| StulleMule | Via mods archive | ED2K | historical mod | P2 | historical | historical | 2026-10-07 | archive tree present | (archive) | Feature research only. |
| ScarAngel | Via mods archive | ED2K | historical mod | P2 | historical | historical | 2026-10-07 | archive tree present | (archive) | Feature research only. |
| NeoMule | Via mods archive | ED2K | historical mod | P2 | historical | historical | 2026-10-07 | archive tree present | (archive) | Feature research only. |
| MagicAngel | Via mods archive | ED2K | historical mod | P2 | historical | historical | 2026-10-07 | archive tree present | (archive) | Feature research only. |
| Mephisto | Via mods archive | ED2K | historical mod | P2 | historical | historical | 2026-10-07 | archive tree present | (archive) | Feature research only. |
| eMule Beba | Via mods archive | ED2K | historical mod | P2 | historical | historical | 2026-10-07 | `eMule-0.50a-beba_2.72_src` | (archive) | Distinct from current eMuleBB org. |
| AdunanzA | Via mods archive | ED2K | historical mod | P2 | historical | historical | 2026-10-07 | archive tree present | (archive) | Regional/historical; not normative. |
| AcKroNiC | Via mods archive | ED2K | historical mod | P2 | historical | historical | 2026-10-07 | archive tree present | (archive) | Feature research only. |
| ZZUL | Via mods archive | ED2K | historical mod | P2 | historical | historical | 2026-10-07 | archive tree present | (archive) | Feature research only. |
| eMule Plus | Via mods archive | ED2K | historical mod | P2 | historical | historical | 2026-10-07 | `eMulePlus-1.2e.Source` | (archive) | Historical. |
| DreaMule | Via mods archive | ED2K | historical mod | P2 | historical | historical | 2026-10-07 | archive tree present | (archive) | Historical. |
| Mods archive | <https://github.com/emulebb/emulebb-mods-archive> | ED2K mods | historical research | P2 | historical | historical | 2026-10-07 | tree listing 2026-10-07 | `Examples/References/emulebb-mods-archive/` | Bulk source snapshots; clone on demand only. |

kMule, VeryCD/easyMule, EastShare, and similar: add a registry row only when a
concrete exploitable source and Envy interest are identified.

### Multi-network heritage

| Project | Official repository | Domain | Role | Priority | Authority | Active status | Last verified | Verified revision | Local directory | Notes / restrictions |
| --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- | --- |
| Shareaza | SF [shareaza](https://sourceforge.net/projects/shareaza/); practical GH [ivan386/Shareaza](https://github.com/ivan386/Shareaza) | G1/G2, multi-net, library | heritage / architecture | P1 | historical | historical | 2026-10-07 | GH tip largely 2019-era; SF project page | `Examples/References/shareaza/` | Direct Envy ancestor for G1/G2, unified search, metadata. Envy tree is the live lineage. |
| PeerProject | <https://github.com/peerproject/peerproject> | multi-net | heritage | P2 | historical | historical | 2026-10-07 | last push ~2016-04-26 | `Examples/References/peerproject/` | Immediate Envy predecessor. |
| NeoLoader | <https://github.com/NeoLoader/NeoLoader> | ED2K, Kad, BT, architecture | architecture (historical) | P2 | historical | historical | 2026-10-07 | release `0.53a` (2018); tip sparse | `Examples/References/neoloader/` | Multi-protocol / core-GUI ideas. **Not** protocol authority. NeoKad/NeoShare overlays stay experimental. |
| MLDonkey | <https://github.com/ygrek/mldonkey> | ED2K, Kad, multi-net | interoperability / architecture | P2 | interoperability | maintenance | 2026-10-07 | release `release-3-2-1`; tip 2025-01-28 | `Examples/References/mldonkey/` | Independent multi-protocol daemon; useful ED2K/Kad interop + headless patterns. |

### BitTorrent (BEP first)

| Project | Official repository | Domain | Role | Priority | Authority | Active status | Last verified | Verified revision | Local directory | Notes / restrictions |
| --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- | --- |
| libtorrent | <https://github.com/arvidn/libtorrent> | BT parsing, DHT, PEX, LSD, uTP, v1/v2 | implementation | P1 | implementation | active | 2026-10-07 | release `v2.1.2` (2026-09-25); branch `RC_2_1` | `Examples/References/libtorrent/` | Engine reference after BEPs. |
| qBittorrent | <https://github.com/qbittorrent/qBittorrent> | BT UX, tags, ATM, RSS, WebUI | architecture | P1 | architecture | active | 2026-10-07 | releases 5.2.4 / 5.3.0rc1 (2026-09-28) | `Examples/References/qbittorrent/` | Product/UX/API patterns; not a BEP substitute. |
| Transmission | <https://github.com/transmission/transmission> | core/daemon/RPC | architecture | P1 | architecture | active | 2026-10-07 | release 4.1.3 (2026-06-30) | `Examples/References/transmission/` | Headless / RPC simplicity. |
| BiglyBT | <https://github.com/BiglySoftware/BiglyBT> | swarm merge, tags, subs | architecture | P2 | architecture | active | 2026-10-07 | release v4.1.0.0 (2026-05); tip 2026-10-06 | `Examples/References/biglybt/` | Advanced BT product behaviours. |
| aria2-next | <https://github.com/AnInsomniacy/aria2-next> | engine, RPC, ED2K+BT | architecture | P1 | architecture | active | 2026-10-07 | release `v2.8.6` (2026-10-04) | `Examples/References/aria2-next/` | Multi-protocol engine/API reference. |

### Direct Connect

| Project | Official repository | Domain | Role | Priority | Authority | Active status | Last verified | Verified revision | Local directory | Notes / restrictions |
| --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- | --- |
| DC++ | SF Mercurial <https://sourceforge.net/p/dcplusplus/code/>; site <https://dcplusplus.sourceforge.net/> | NMDC, ADC | implementation | P1 | implementation | active | 2026-10-07 | stable **0.883** (2025-09-12); Hg on SF | *(manual Hg / release src)* | No first-class GitHub canonical. Script does not auto-clone Hg. |
| AirDC++ Core | <https://github.com/airdcpp/airdcpp-core> | NMDC, ADC, TLS, queue | implementation | P1 | implementation | active | 2026-10-07 | PRs #551/#541/#537 (2026-10-04) | `Examples/References/airdcpp-core/` | Modern DC engine (functional PR evidence). |
| AirDC++ Windows | <https://github.com/airdcpp/airdcpp-windows> | DC UI / transfers | architecture | P1 | architecture | active | 2026-10-07 | release `4.30`; tip 2026-10-04 | `Examples/References/airdcpp-windows/` | Product client; Web/API sibling under `airdcpp-web/*`. |
| EiskaltDC++ | <https://github.com/eiskaltdcpp/eiskaltdcpp> | NMDC, ADC | implementation | P2 | implementation | maintenance | 2026-10-07 | commits through 2026-09; older tags | `Examples/References/eiskaltdcpp/` | Cross-platform secondary reference. |

### Experimental / R&D (isolated)

| Project | Official repository | Domain | Role | Priority | Authority | Active status | Last verified | Verified revision | Local directory | Notes / restrictions |
| --- | --- | --- | --- | ---: | --- | --- | --- | --- | --- | --- |
| Ember | <https://github.com/untaimed18/Ember-P2P> | DHT/security research | experimental | P2 | experimental | active | 2026-10-07 | release v1.7.1 (2026-10-04) | `Examples/References/ember/` | **Not Kad2.** Optional Envy-specific research only. |
| Rucio | <https://github.com/ogarcia/rucio> | daemon/Web/libp2p | experimental / architecture | P2 | experimental | active | 2026-10-07 | tip 2026-10-04 | `Examples/References/rucio/` | Not CERN Rucio. Not ED2K-normative. |
| eMule eSE | <https://github.com/diad87/eMule-eSE-LiveTV> | IPv6, Kad6 | experimental | P3 | experimental | active | 2026-10-07 | eSE 9.1.0 / 9.2.0-rc (2026) | `Examples/References/emule-ese/` | Kad6 must stay distinct from Kad2. |
| NeoKad / NeoShare | NeoLoader-related historical overlays | overlay | experimental | P3 | experimental | historical | 2026-10-07 | see NeoLoader notes | - | Never treat as Kad2. |

---

## Immediate local clones (ED2K / Kad workstream)

Prepare these under `Examples/References/` first:

```text
emule-community
amule
emulebb
emulebb-rust
emule-qt
padmule
morphxt
neoloader
mldonkey
shareaza
```

```powershell
./tools/references/sync-references.ps1 -Group ed2k-immediate
```

Clone BitTorrent, DC, experimental, and the mods archive only when a specific
audit needs them.

---

## Project notes (roles and reuse)

### eMule Community - P0, normative

Primary wire-compatibility reference for ED2K and Kad2: Hello/MuleInfo,
userhash, ClientID, HighID/LowID, callbacks, capability bits, compression,
multipacket, search, Source Exchange, AICH, credits, Kad2
bootstrap/routing/search/publish, firewall check, Buddy, historical NAT,
SecureIdent RSA. Do not copy MFC structure, credit policy, or UI.

### aMule - P0, interoperability

Second live interop target and daemon/GUI/Web/CLI architecture reference
(`amuled`, remote GUI, Web, CLI, REST). Prefer **amule-org/amule** over
**amule-project/amule** (legacy). Do not adopt wx/GTK or EC protocol as a
drop-in Envy API.

### eMuleBB / emulebb-rust / padMule - P1, implementation

Performance, parsers, differential tests, queues/upload, large-library, and
headless/API ideas. Still below eMule Community / aMule for wire disputes.

### eMule Qt / eMule AI - P1, architecture

Incremental core/UI separation (Qt) and modern reachability (AI). Never break
Community/aMule interop for experimental transports.

### MorphXT - P2, historical interop target

Historical mod with concrete Envy <-> MorphXT interop interest. Use SF / mirror /
mods archive; never as modern Kad2 authority.

### NeoLoader / MLDonkey / Shareaza / PeerProject

Multi-protocol and heritage architecture. NeoLoader is **not** protocol
authority. Shareaza/PeerProject inform G1/G2 and Envy lineage; live G1/G2
behaviour is Envy's own tree.

### BitTorrent family

BEP -> libtorrent -> product clients (qBittorrent, Transmission, BiglyBT) ->
aria2-next for engine/API patterns.

### Direct Connect family

NMDC/ADC specs first; DC++ (SF Hg) and AirDC++ / EiskaltDC++ as implementation
references. Listing them does not schedule new Envy protocols.

### Ember / Rucio / eMule eSE

Experimental or architecture R&D only. Never label as Kad2 / eMule standard.

---

## Local checkout workflow

1. Read this registry for authority and restrictions.
2. Sync clones with [`tools/references/sync-references.ps1`](../../tools/references/sync-references.ps1).
3. Record the printed SHA/tag in notes or PR evidence when conclusions depend on it.
4. Keep `Examples/` out of commits (`.gitignore`).

Obsolete URL correction (2026-10-07): documentation that still points at
`amule-project/amule` as the active source should use `amule-org/amule`.

---

## Related Envy documents

- Ecosystem audit (October 2026): [`P2P_ECOSYSTEM_AUDIT_2026-10.md`](P2P_ECOSYSTEM_AUDIT_2026-10.md)
- Decision D-008 (trust order), D-023 (local clone model): `docs/DECISIONS.md`
- Sync helper: `tools/references/README.md`
- Strategic sequence: `docs/DEVELOPMENT_PLAN.md`
- Feature status matrix: `docs/10_dev/status.md`
- Technical roadmap: `docs/10_dev/roadmap.md`
- ED2K / Kad / BitTorrent folders under `docs/30_protocols/`
- IPv6 plan: `docs/ipv6/PLAN.md`
