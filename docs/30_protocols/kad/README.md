# Kad Documentation

Status: active
Last updated: 2026-11-26
Scope: Envy Kad2 notes. Opcode matching is not live interop. Kad6/Ember overlays are not Kad2.

**Specification first:** [Kademlia paper](https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf). **Interop second:** maintained aMule and eMule-family Kad2 sources ([amule-org/amule](https://github.com/amule-org/amule), [emulebb/emulebb](https://github.com/emulebb/emulebb), [eMuleAI/eMuleAI](https://github.com/eMuleAI/eMuleAI)). [irwir/eMule](https://github.com/irwir/eMule) still has the standard opcode values but is not a maintained tree (single commit, 2016-04-10). Ember and eMule eSE extensions are experimental and must stay distinct from Kad2. See [REFERENCE_IMPLEMENTATIONS.md](../REFERENCE_IMPLEMENTATIONS.md) and the 2026-11-26 survey in [kad-interop.md](kad-interop.md).

## Start here
- [Kad2 compatibility report](kad2-compatibility-report.md) (wire/opcode match only)
- [Kad2 publish interop notes](kad-interop.md) (PUBLISH opcodes, client survey 2026-11-26, layouts for #427 / #428)

## Initial exchange wire layout and inbound limits

Compared against eMule Community v0.72a (`irwir/eMule` `ac3d52eafd88e9f6d9e0c2204c6dbead18db750b`, tag `eMule_v0.72a-community`: `CKademliaUDPListener::SendMyDetails`, `AddContact_KADEMLIA2`, `Process_KADEMLIA2_HELLO_REQ/RES`, `CDataIO::ReadTag`, `CPacketTracking`) and `amule-org/amule` `d043ffa5a6bb7e000ec6d8c3a1f95dfb4f7d4e12` (`KademliaUDPListener.cpp`, `PacketTracking.cpp`, `Tag.cpp`), both read on 2026-10-24. This is source comparison and synthetic tests, not live interoperability (#160).

### HELLO body

- `HELLO_REQ` and `HELLO_RES` share one body: `<SenderKadID 16><TCPPort 2><Version 1><TagCount 1><Tag>*`, tags as `<Type 1><NameLength 2><Name><Value>`. There is no fixed UDP port field. Envy previously sent a zero ID and a fixed UDP port with no tag count, which neither reference can parse. Envy now sends its own ID, the configured TCP port, Kad version 8 and no tags. `KadHello.h`.
- Tags read (union of the two readers): HASH16, STRING, UINT8/16/32/64, FLOAT32, BOOL, BLOB (32-bit length), BSOB (8-bit length), STR1-STR16 and the compact `type|0x80` form with a one-byte name. eMule's Kad reader accepts only HASH, STRING, UINT8-64, FLOAT32 and BSOB; aMule's also BOOL, BLOB and STR1-16.
- **Rejected as a whole** (both references abort on a tag they cannot delimit): unknown tag types, BOOLARRAY (the two sources size it differently), a name or value running past the body, a declared tag count larger than the tags present, and version 0 (aMule). Bytes after the last declared tag are ignored, as in the references.
- `TAG_SOURCEUPORT` (0xFC) is applied in `HELLO_REQ` **and** `HELLO_RES` (`AddContact_KADEMLIA2` is shared), any integer width, ignored when zero. Divergence: a value above 65535 is ignored instead of truncated to 16 bits. Divergence: two valid but different values for `TAG_SOURCEUPORT` or `TAG_KADMISCOPTIONS` in one body reject the HELLO; the references let the last one win. The stored contact IP is always the datagram source, so an advertised port can only point at another port of the same host.
- `TAG_KADMISCOPTIONS` (0xF2): bit 0 UDP firewalled, bit 1 TCP firewalled, bit 2 requests `HELLO_RES_ACK` (meaningful only from version 8 and up). A UDP-firewalled sender is answered but neither added nor verified, as in both references. Envy sends no such tag.

### Version and capability behaviour

- Envy advertises Kad version 8 (eMule v0.72a advertises 10). Version 8 means `TAG_KADMISCOPTIONS` and `HELLO_RES_ACK` exist. Envy has no UDP keys and sends unobfuscated packets with no sender key, so a peer that requests a `HELLO_RES_ACK` from Envy cannot get one (eMule skips the ACK itself when it holds no sender key). It does decrypt the obfuscated datagrams peers send it: `KadUdpDeobfuscate` (`Envy/KadUdpObfuscation.h`, wired into `CDatagrams::OnDatagram`) recovers Kad2 packets encrypted with MD5(our NodeID | 2 random bytes), which is what aMule and eMule use for every reply to a Kad version >= 6 requester. Outgoing Kad encryption and the UDP verify keys (`KadUDPKeys.h`) remain unimplemented, so eMule/aMule may still keep Envy unverified in their routing tables. Advertising a lower version would instead trigger their legacy challenge paths and was not chosen without live evidence.
- Envy does not send `TAG_SOURCEUPORT`, so peers use the datagram source port; this is correct without NAT port remapping on the Kad socket.

### Correlation and replay

- A `HELLO_RES` is accepted only for an outstanding `HELLO_REQ` to the same IP **and port** (the references match the IP only), and the entry is consumed by the first match, so a duplicate or unsolicited `HELLO_RES` is ignored. The entry is registered before the send and withdrawn when the datagram was not sent (`CKademlia::SendPacket` is true only when the datagram layer accepted the packet and `sendto` reported the whole datagram sent). Entries expire after `KAD2_REQUEST_TIMEOUT`.
- A contact enters the routing table as a candidate from a `HELLO_REQ`, and is marked IP-verified only by the solicited `HELLO_RES`.

### Two-byte requests and inbound limits

- A Kad2 request without a body is exactly the two header bytes. The UDP dispatcher accepts a two-byte datagram only when it is exactly `0xE4 0x01` (`BOOTSTRAP_REQ`) or `0xE4 0x60` (`PING`) (`KadIsBodylessRequest`); every other opcode, protocol byte or length at two bytes is dropped. Both accepted opcodes are rate limited on receipt.
- Limits per source IP and opcode: `BOOTSTRAP_REQ` 2, `PING` 2, `HELLO_REQ` 3 per minute. aMule (`InTrackListIsAllowedPacket`) uses exactly these three. eMule v0.72a limits `BOOTSTRAP_REQ` and `PING` to 2 per minute but does **not** track `HELLO_REQ`; Envy keeps aMule's stricter figure. Envy uses a token bucket per (IP, opcode): a bucket of one minute of tokens, each packet costing 60 s divided by the rate, so a source may burst to the rate and then sustain it. eMule uses the same bucket but lets refused packets keep draining it and bans the IP below minus three minutes; aMule counts packets in a sliding window and bans above five times the rate. Divergence: in Envy a refused packet does not deepen the debt and Envy never bans, so a legitimate retry recovers after at most one token interval.
- The bound of 4096 tracked (IP, opcode) entries, fail-closed when full after pruning entries idle for a minute, is Envy's own; the references keep one list entry per source IP without a size bound and clean it every 12 minutes. A clock that moves backwards counts as zero elapsed time. The older `CheckRateLimit` stays as is for the other requests. Source addresses are forgeable, which is why a reply is only sent after the limit check and no reply is larger than the request class allows (`BOOTSTRAP_RES` up to a few hundred bytes remains the amplification the limit is there for).

### Obfuscated Kad datagrams

- Peers that saw our Kad version 8 encrypt their replies (and later all their Kad2 traffic to us) as `<marker plain><random key part 2 plain><RC4(magic 4)><RC4(padLen 1)><RC4(padding)><RC4(receiverVerifyKey 4)><RC4(senderVerifyKey 4)><RC4(Kad datagram)>`, key `MD5(<our KadID 16 as written in HELLO_REQ><random key part>)`; the magic `0x395F2EC1` and both verify keys travel byte-swapped (big-endian wire bytes), and the marker only hints which key to try first (aMule `EncryptSendClient` / `DecryptReceivedClient`). `KadUdpDeobfuscate` (`Envy/KadUdpObfuscation.h`) decrypts these in `CDatagrams::OnDatagram`'s fall-through and re-dispatches the result through the normal ED2K/Kad path; the aggregate `deobf` count in the `Kad2 hello:` status line reports them. The ED2K user-hash key, outgoing encryption, UDP verify keys and `HELLO_RES_ACK` are separate follow-ups; `tests/test_kad_udp_obfuscation.cpp` pins the layout with round-trips and golden vectors.

### Remaining limits

- A `HELLO_RES` from the exact endpoint that was sent a `HELLO_REQ` still marks the contact verified. The references additionally use UDP keys and `HELLO_RES_ACK` to prove the address; Envy implements neither, so this is weaker than the references against an off-path spoofer.
- Kad IDs are exchanged as opaque 16 bytes; eMule serializes them as four little-endian 32-bit words. Distance and bucket handling of Envy's routing table were not re-checked here.
- Not validated against live eMule/aMule (#160); inbound deobfuscation is implemented (#431), outgoing encryption and UDP keys are not.

## Related
- [Status](../../10_dev/status.md) · [Dev docs](../../10_dev/) · [Protocol index](../README.md)
