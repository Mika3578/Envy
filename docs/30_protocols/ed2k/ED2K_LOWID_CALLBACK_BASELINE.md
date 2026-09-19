# ED2K LowID / C2C callback baseline (phase 1)

Status: **partial** — not complete firewalled / Buddy support.
Related: #87, #160.

## Existing classic server callback (unchanged)

Envy already supports ED2K server-mediated LowID push:

1. LowID `CEDClient::Connect()` → `Neighbours.PushDonkey()` → `ED2K_C2S_CALLBACKREQUEST`
2. Server → `ED2K_S2C_CALLBACKREQUESTED` → `CEDNeighbour::OnCallbackRequested()`
3. `EDClients.PushTo()` sets `m_bCallbackRequested` → `OnRunEx` dials the HighID peer

This path is preserved. Phase 1 does **not** replace it.

## Phase-1 C2C opcodes

| Opcode | Wire | Runtime |
| --- | --- | --- |
| `PUBLICIP_REQ` (0x97) | empty | Answer with connected peer IPv4 (`PUBLICIP_ANSWER`) |
| `PUBLICIP_ANSWER` (0x98) | `<IPv4 4>` LE sockaddr dword | Accept only with outstanding query; optional `Network.AcquireLocalAddress` when public IP still 0 and not LowID-shaped |
| `CALLBACK` (0x99) | `<KadCheck 16><FileHash 16><IP 4><TCPPort 2>` (38 bytes) | Require Kad initialized + KadCheck XOR all-ones == own Kad ID; known file (library **or** any incomplete download via `FindByED2K` without shared-only); Security/Network endpoint checks; `EDClients.PushTo` once (consume guard cleared if PushTo fails so retries remain possible) |
| `REASKCALLBACKTCP` (0x9A) | Buddy reask relay | **Deferred** — needs Buddy; size-audited and ignored |

Helpers: `Envy/Ed2kLowIdCallback.h`. Tests: `tests/test_ed2k_lowid_callback_smoke.cpp`.

## Protocol evidence

- aMule `src/ClientTCPSocket.cpp` (`OP_PUBLICIP_*`, `OP_CALLBACK`, `OP_REASKCALLBACKTCP`)
- aMule `src/BaseClient.cpp` (`SendPublicIPRequest`, `ProcessPublicIPAnswer`)
- aMule `src/kademlia/net/KademliaUDPListener.cpp` (`ProcessCallbackRequest` builds OP_CALLBACK)
- eMule Community `ListenSocket.cpp` / `BaseClient.cpp` (same layouts)

Header comments that document `CALLBACK` as `<HASH><HASH><uint16>` are incomplete; live code uses 38 bytes including IP+port.

## Outbound PUBLICIP_REQ

Sent once after login when `Network.m_pHost` IPv4 is still 0 and the peer is eMule-capable — matching aMule “request when public IP unknown”, not after every Hello.

## Remaining (phase 2 / #160)

- Buddy selection and bond
- `REASKCALLBACKTCP` runtime
- `BUDDYPING` / `BUDDYPONG`
- `FWCHECKUDPREQ` / Kad firewall state
- Direct UDP callback
- Live HighID↔LowID interop scenarios via the opt-in harness (`tools/interop/`, #160) — PUBLICIP, server callback, Buddy CALLBACK (not required CI)

Do not claim complete LowID, firewalled, or eMule compatibility from this slice alone.
