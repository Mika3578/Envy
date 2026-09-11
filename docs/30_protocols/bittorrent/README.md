# BitTorrent Documentation

Status: active
Last updated: 2026-09-11
Scope: Envy BitTorrent notes. BEP 52 / v2 is partial. uTP is not wired.

**Specification first:** [BEP index](https://www.bittorrent.org/beps/bep_0000.html) (BEP 3, 5, 9, 10, 11, 15, 29, 32, 52). Engine/API reference: [aria2-next](https://github.com/AnInsomniacy/aria2-next). See [REFERENCE_IMPLEMENTATIONS.md](../REFERENCE_IMPLEMENTATIONS.md). BitTorrent work is not deferred for ED2K.

## Start here
- [BitTorrent v2 plan](BITTORRENT_V2_PLAN.md) (planning; v2 wire not implemented)

## Implementation notes
- **MSE/PE (BEP-10):** `Envy/BTCrypto.h` (`CBTCrypto`, DH + RC4) integrated into `CBTClient`; setting `Settings.BitTorrent.Encryption`. Older “still TODO” wording was stale.
- **v2:** `CBTInfo::IsBitTorrentV2()` currently returns false; `m_oBTHv2` remains commented (`Envy/BTInfo.h`).
- **uTP (BEP-29):** not implemented in Envy code (`Services/LibUTP` is unused).

## Related
- [Status](../../10_dev/status.md) · [Dev docs](../../10_dev/) · [Protocol index](../README.md)
