# ED2K/eMule Source Exchange Interoperability Notes

## Scope
This note documents current Envy behavior for Source Exchange v1/v2 packets and pragmatic compatibility expectations with eMule/aMule style peers.

## Packet Compatibility
- `OP_REQUESTSOURCES` (0x81) and `OP_ANSWERSOURCES` (0x82) remain supported and unchanged on-wire.
- `OP_REQUESTSOURCES2` (0x83) and `OP_ANSWERSOURCES2` (0x84) remain supported and preferred when peer capability negotiation reports SourceEx2 support (`nOpt2` bit 10).
- **Standalone SX2 request (eMule/aMule):** `<Version 1><Options 2><HASH 16>` (19 bytes). Not the legacy Envy hash+file-size encoding (22/26 bytes); that framing is **not supported** after this change — only SourceEx1 fallback remains for incompatible peers.
- **MULTIPACKET SX2 sub-opcode:** the enclosing multipacket already carries the file hash; the `0x83` sub-message adds only version + options (do not prepend another hash).
- **SX2 answer:** `<Version 1><HASH 16><Count 2>` then version-dependent records (v1 = 12 bytes; v2/v3 = 28 with GUID; v4 = 29 with crypt-options byte parsed but obfuscation not initiated by Envy).
- Source list entries remain IPv4: `<ClientID 4><Port 2><ServerIP 4><ServerPort 2>[GUID 16][CryptOptions 1]`.

## Defensive Parsing
- Source answer handlers now validate list body length against count and per-entry size before reading any source tuples.
- Malformed or truncated source packets are rejected through existing bad-packet handling/logging path.

## Current Limitation (Explicit)
- SourceEx and SourceEx2 source tuples are currently IPv4-only on-wire in Envy.
- No IPv6 source tuple encoding/decoding is currently implemented for Source Exchange packets.
- This is intentional for compatibility with the existing legacy ED2K/eMule tuple format and to avoid wire-format regressions in this incremental hardening pass.

Live Envy ↔ eMule Community / aMule Source Exchange behaviour is still **unverified**. Use the opt-in harness in `tools/interop/` (#160) to attach evidence. Specs first, then [eMule Community](https://github.com/irwir/eMule) / [aMule](https://github.com/amule-org/amule): `docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md`.
