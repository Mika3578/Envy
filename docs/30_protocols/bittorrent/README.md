# BitTorrent Documentation

Status: active
Last updated: 2026-11-26
Scope: Envy BitTorrent notes. BEP 52 / v2 is partial. uTP is not wired.

**Specification first:** [BEP index](https://www.bittorrent.org/beps/bep_0000.html) (BEP 3, 5, 9, 10, 11, 14, 15, 27, 28, 29, 32, 52). Engine/API reference: [aria2-next](https://github.com/AnInsomniacy/aria2-next). See [REFERENCE_IMPLEMENTATIONS.md](../REFERENCE_IMPLEMENTATIONS.md). BitTorrent work is not deferred for ED2K.

## Start here
- [BitTorrent v2 plan](BITTORRENT_V2_PLAN.md) (planning; v2 wire not implemented)

## Implementation notes
- **MSE/PE (BEP-10):** `Envy/BTCrypto.h` (`CBTCrypto`, DH + RC4) integrated into `CBTClient`; setting `Settings.BitTorrent.Encryption`. Older “still TODO” wording was stale.
- **Private torrents (BEP-27):** enforcement is split across two complementary changes. `BTDiscoveryPolicy.h` (`BtAllowsPublicDiscovery`) is the single gate; draft PR #525 covers the DHT search/announce paths, private-flag-first import with inactive rejected single trackers (no public default-tracker reassignment), and the metainfo debug dump. This change covers the remaining paths: the extended handshake no longer advertises `ut_pex`, incoming PEX and tracker exchange (BEP-28) are ignored, Envy/Shareaza source exchange is neither requested, served nor accepted, local service discovery (BEP-14) announces are ignored, unsolicited DHT results never populate the source set, cross-network (G1/G2/ED2K/Kad) searches and search-hit sources are blocked, the torrent's embedded DHT node list no longer seeds the host cache, private multi-tracker failover drops the failed tracker's peer set, applying a private torrent to an existing download drops pre-discovery peers, and tracker URLs are logged with announce query strings removed (`Envy/BTTrackerLogRedaction.h`; passkeys never reach logs). Public torrents keep normal DHT/PEX/LSD behavior.
- **v2:** `CBTInfo::IsBitTorrentV2()` currently returns false; `m_oBTHv2` remains commented (`Envy/BTInfo.h`).
- **uTP (BEP-29):** not implemented in Envy code (`Services/LibUTP` is unused).

## Related
- [Status](../../10_dev/status.md) · [Dev docs](../../10_dev/) · [Protocol index](../README.md)
