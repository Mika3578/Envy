# Protocol documentation

Status: active
Last updated: 2026-09-11
Scope: Index of Envy protocol docs and external references.
Source of truth: specifications first; Envy code second; reference clients third. See `REFERENCE_IMPLEMENTATIONS.md`.

Envy is a multi-network client. Protocol work on ED2K/Kad does not replace BitTorrent, Gnutella, Gnutella2, or Direct Connect.

| Area | Envy docs | Specifications | Reference implementations |
| --- | --- | --- | --- |
| Policy | [REFERENCE_IMPLEMENTATIONS.md](REFERENCE_IMPLEMENTATIONS.md) | Specs listed in that document | eMule Community, aMule, others |
| ED2K | [ed2k/](ed2k/README.md) | eDonkey/eMule notes, aMule wiki, ED2K URI | eMule Community (P0), aMule (P0) |
| Kad | [kad/](kad/README.md) | Kademlia paper; Kad2 via eMule/aMule | eMule Community, aMule; Ember/eSE are not Kad2 |
| BitTorrent | [bittorrent/](bittorrent/README.md) | [BEPs](https://www.bittorrent.org/beps/bep_0000.html) | aria2-next, libtorrent-family (existing Examples notes) |
| G1 / G2 | Shareaza-lineage code under `Envy/G1*`, `Envy/G2*` | Gnutella 0.6 draft; G2/Shareaza notes | Preserve Envy/Shareaza behaviour |
| Direct Connect | `Envy/DC*` | [NMDC](https://nmdc.sourceforge.net/NMDC.html), [ADC](https://adc.sourceforge.io/ADC.html), [ADC-EXT](https://adc.sourceforge.io/ADC-EXT.html) | Preserve Envy/Shareaza behaviour |

Canonical implementation status: [`docs/10_dev/status.md`](../10_dev/status.md).
