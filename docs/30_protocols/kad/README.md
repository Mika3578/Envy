# Kad Documentation

Status: active
Last updated: 2026-09-19
Scope: Envy Kad2 notes. Opcode matching is not live interop. Kad6/Ember overlays are not Kad2.

**Specification first:** [Kademlia paper](https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf). **Interop second:** eMule Community and aMule Kad2 sources. Ember and eMule eSE extensions are experimental and must stay distinct from Kad2. See [REFERENCE_IMPLEMENTATIONS.md](../REFERENCE_IMPLEMENTATIONS.md).

## Start here
- [Kad2 compatibility report](kad2-compatibility-report.md) (wire/opcode match only)

## Related
- [Status](../../10_dev/status.md) · [Dev docs](../../10_dev/) · [Protocol index](../README.md)

## Initial exchange wire layout and inbound limits

Compared against eMule Community v0.72a `ac3d52eafd88e9f6d9e0c2204c6dbead18db750b` (`SendMyDetails`, `AddContact_KADEMLIA2`, `InTrackListIsAllowedPacket`) and aMule `0bfe11d65bcf4ac8449eb12e98cdd303e9e3dcf6` (`Process2HelloRequest`, `PacketTracking`):

- `HELLO_REQ` and `HELLO_RES` share one body: `<SenderKadID 16><TCPPort 2><Version 1><TagCount 1><Tag>*`, tags as `<Type 1><NameLength 2><Name><Value>`. There is no fixed UDP port field; `TAG_SOURCEUPORT` (0xFC, UINT16) carries it when sent. Envy previously sent a zero ID and a fixed UDP port with no tag count, which the references cannot parse. Envy now sends its own ID, the configured TCP port and no tags, parses the references' layout, skips tags it does not use and rejects truncated bodies. `KadHello.h`.
- A Kad2 request without a body (`BOOTSTRAP_REQ`, `PING`) is exactly the two header bytes. The UDP dispatcher accepts a two-byte datagram only when it is exactly `0xE4 0x01` (`BOOTSTRAP_REQ`) or `0xE4 0x60` (`PING`) (`KadIsBodylessRequest`); every other opcode, protocol byte or length at two bytes is dropped, so no other ED2K UDP packet or Kad opcode can use the short path. Both accepted opcodes are rate limited on receipt.
- Inbound `BOOTSTRAP_REQ` is limited to two per minute per source IP and `HELLO_REQ` to three, as in the references (token bucket, burst equal to the per-minute rate, opcode-specific, 4096 tracked IPs and fail-closed when full). The older `CheckRateLimit` stays as is for the other requests. Envy does not ban on flood, unlike eMule.
- Divergences from the references: inbound `PING` is limited to two per minute per IP, matching `BOOTSTRAP_REQ`; that figure is Envy's choice and was not re-checked against the reference tables. The limiter treats a clock that moves backwards as zero elapsed time (no refill, stamp not moved back) instead of wrapping. `HELLO_REQ` registers its outstanding entry before the send and drops it if the send fails, so a fast `HELLO_RES` is matched.
- Remaining limit: a `HELLO_RES` from the exact endpoint that was sent a `HELLO_REQ` still marks the contact verified. The references additionally use UDP keys and `HELLO_RES_ACK` to prove the address; Envy implements neither, so this is weaker than the references against an off-path spoofer. Not validated against live eMule/aMule (#160); obfuscation is #431.
