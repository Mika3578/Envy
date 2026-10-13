# P2P ecosystem audit (October 2026)

Status: research / audit pass (documentation only — no protocol implementation)
Last updated: 2026-10-07
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
| [ModderMule/emule-qt](https://github.com/ModderMule/emule-qt) | active reference | Release [`v0.5.6`](https://github.com/ModderMule/emule-qt/releases/tag/v0.5.6) 2026-10-02; commits 2026-10 hashing/AICH/part-file | #161 core/UI, IPC, REST | Architecture only |
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

## Related documents

- Canonical registry: [`REFERENCE_IMPLEMENTATIONS.md`](REFERENCE_IMPLEMENTATIONS.md)
- Local clone workflow: [`tools/references/README.md`](../../tools/references/README.md)
- Decisions: D-008 (trust order), D-023 (local clones) in `docs/DECISIONS.md`
- Envy status: `docs/10_dev/status.md`
