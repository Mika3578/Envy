# External P2P reference checkouts

Status: active
Last updated: 2026-10-07
Scope: Optional local clones of interoperability / architecture reference projects.
Canonical registry: [docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md](../../docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md)

## Principle

Envy keeps a **Git-tracked registry** of external P2P references and optional
**ignored local clones**. External sources are never vendored into Envy history,
never added as git submodules by default, and never wired into the Envy build.

| Layer | Location | Tracked? |
| --- | --- | --- |
| Policy + full registry | docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md | Yes |
| Clone catalog | 	ools/references/catalog.json | Yes |
| Sync helper | 	ools/references/sync-references.ps1 | Yes |
| Local trees | Examples/References/<id>/ | **No** (entire Examples/ is gitignored) |

Presence of a project in the registry does **not** mean Envy supports that
protocol or feature. Inspiration is not protocol support.

## Local directory

Recommended root (relative to the Envy repo):

`	ext
Examples/References/
    emule-community/
    amule/
    emulebb/
    ...
`

Override with -Root if needed (paths with spaces are supported).

Historical docs may mention older flat paths such as Examples/eMule or
Examples/aMule. Prefer the structured Examples/References/<id>/ layout for
new checkouts.

## Commands

From the repository root (Windows PowerShell):

`powershell
# List groups and project ids
./tools/references/sync-references.ps1 -List

# Recommended set for the next ED2K/Kad workstream
./tools/references/sync-references.ps1 -Group ed2k-immediate

# One project
./tools/references/sync-references.ps1 -Project emule-community

# BitTorrent engine/clients (on demand)
./tools/references/sync-references.ps1 -Group bittorrent

# Show local HEAD without fetching
./tools/references/sync-references.ps1 -Group ed2k-immediate -Status

# Preview actions
./tools/references/sync-references.ps1 -Project amule -WhatIf
`

With no -Group / -Project, the script syncs catalog entries marked
syncDefault: true (the immediate ED2K/Kad set).

## Groups

| Group | Purpose |
| --- | --- |
| ed2k-immediate | Clones for the current ED2K/Kad workstream |
| ed2k | Broader ED2K/Kad set (includes eMule AI, aria2-next, ...) |
| ittorrent | libtorrent, qBittorrent, Transmission, BiglyBT, aria2-next |
| dc | AirDC++ / EiskaltDC++ (does not imply adding ADC/NMDC features) |
| heritage | Shareaza, PeerProject, NeoLoader, MLDonkey |
| experimental | Ember, Rucio, eMule eSE - never Kad2 authority |
| historical | MorphXT mirror + bulk mods archive |

## Update policy

1. Prefer the **official** repository URL recorded in the registry.
2. Record meaningful verification in REFERENCE_IMPLEMENTATIONS.md
   (Last verified / Verified revision) when a comparison changes Envy
   conclusions - do not rely on GitHub updated_at alone.
3. Re-run the sync script before an audit; note the printed sha / tag.
4. Do not commit anything under Examples/.
5. Do not run reference builds from Envy CI.

## Authority hierarchy (summary)

1. Specification / RFC / BEP / primary protocol docs
2. Live interoperability evidence (Envy <-> reference)
3. Established reference implementation (eMule Community, aMule)
4. Other maintained implementations
5. Historical mods
6. Experimental / R&D

Details and per-project restrictions:
[docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md](../../docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md).

## Decision

Local-clone model: docs/DECISIONS.md (D-023). Trust order: D-008.
