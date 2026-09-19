# Kad2 eMule/aMule Compatibility Report

> **Opcode/format match only (January 2026).** This is not live DHT interoperability. Canonical status: [`docs/10_dev/status.md`](../../10_dev/status.md) (`partial / unverified`). Ember/eSE overlays are **not** Kad2. Preferred live references: [eMule Community](https://github.com/irwir/eMule), [aMule](https://github.com/amule-project/amule) — see [REFERENCE_IMPLEMENTATIONS.md](../REFERENCE_IMPLEMENTATIONS.md).

**Date:** 2026-09-19 (routing-table maintenance slice; original opcode survey January 16, 2026; banner 2026-09-11)
**Reference Implementations:**
- eMule (Examples/eMule/srchybrid; prefer https://github.com/irwir/eMule)
- aMule (Examples/aMule; prefer https://github.com/amule-project/amule)
- Shareaza (Examples/shareaza) - No Kad2 implementation found
- MLDonkey (Examples/mldonkey) - No Kad2 implementation found

**Envy Implementation:** `Envy/KadRoutingTable.h`, `Envy/KadNodesDat.h`, `Envy/Kademlia.h`, `Envy/Kademlia.cpp`, `Envy/EDPacket.h`

## Executive Summary

**Wire/opcode comparison plus local routing-table maintenance.** Several Kad2 opcodes and packet shapes in Envy match eMule/aMule sources inspected at the time. Local XOR zone-tree maintenance (split / LRU / refresh / `/24` diversity) is implemented in `Envy/KadRoutingTable.h` with EnvyTests. That is **not** a claim that Envy is a fully functional Kad2 peer on the live network (firewall/Buddy/callback, UDP keys, and live interop remain open — `docs/10_dev/roadmap.md`). Status remains **partial / unverified**.

Shareaza and MLDonkey were not used as Kad2 references.

---

## Opcode Compatibility

### Verified Opcodes

| Opcode | Value | Envy | eMule | aMule | Status |
|--------|-------|------|-------|-------|--------|
| `KADEMLIA2_BOOTSTRAP_REQ` | 0x01 | ✅ | ✅ | ✅ | **MATCH** |
| `KADEMLIA2_BOOTSTRAP_RES` | 0x09 | ✅ | ✅ | ✅ | **MATCH** |
| `KADEMLIA2_HELLO_REQ` | 0x11 | ✅ | ✅ | ✅ | **MATCH** |
| `KADEMLIA2_HELLO_RES` | 0x19 | ✅ | ✅ | ✅ | **MATCH** |
| `KADEMLIA2_REQ` | 0x21 | ✅ | ✅ | ✅ | **MATCH** |
| `KADEMLIA2_RES` | 0x29 | ✅ | ✅ | ✅ | **MATCH** |
| `KADEMLIA2_PING` | 0x60 | ✅ | ✅ | ✅ | **MATCH** |
| `KADEMLIA2_PONG` | 0x61 | ✅ | ✅ | ✅ | **MATCH** |
| `KADEMLIA_FIND_NODE` | 0x0B | ✅ | ✅ | ✅ | **MATCH** |

**Sources:**
- `Examples/aMule/src/include/protocol/kad2/Client2Client/UDP.h` (opcode definitions)
- `Examples/eMule/srchybrid/kademlia/net/KademliaUDPListener.cpp` (opcodes verified in code)

**Envy:** `Envy/EDPacket.h` lines 318-337

**Verified Clients:**
- ✅ **eMule** - opcode/format match in the inspected sources (not live interop)
- ✅ **aMule** - opcode/format match in the inspected sources (not live interop)
- ⚠️ **Shareaza** - No Kad2 implementation found in Examples (may use different protocol)
- ⚠️ **MLDonkey** - No Kad2 implementation found in Examples (OCaml-based, different architecture)

---

## Packet Format Compatibility

### 1. KADEMLIA2_BOOTSTRAP_REQ

**eMule/aMule Implementation:**
```cpp
// eMule
CSafeMemFile fileIO(0);
SendPacket(fileIO, KADEMLIA2_BOOTSTRAP_REQ, uIP, uUDPPort, ...);

// aMule
CMemFile bio(0);  // Empty body
SendPacket(bio, KADEMLIA2_BOOTSTRAP_REQ, ip, port, 0, cryptTargetID);
```
**Locations:**
- `Examples/eMule/srchybrid/kademlia/net/KademliaUDPListener.cpp:101-103`
- `Examples/aMule/src/kademlia/net/KademliaUDPListener.cpp:104`

**Envy Implementation:**
```cpp
CEDPacket* pPacket = CEDPacket::New(KADEMLIA2_BOOTSTRAP_REQ, ED2K_PROTOCOL_KAD);
// BOOTSTRAP_REQ has empty body according to eMule spec
```
**Location:** `Envy/Kademlia.cpp:309-312`

✅ **COMPATIBLE** - All implementations send empty body

---

### 2. KADEMLIA2_BOOTSTRAP_RES

**eMule/aMule Format:**
```
<KadID(16)><TCPPort(2)><KadVersion(1)><Count(2)><contacts...>
Each contact: <ID(16)><IP(4)><UDP(2)><TCP(2)><Ver(1)>
```
**eMule Implementation:**
```cpp
fileIO.WriteUInt128(CKademlia::GetPrefs()->GetKadID());
fileIO.WriteUInt16(thePrefs.GetPort());
fileIO.WriteUInt8(KADEMLIA_VERSION);
fileIO.WriteUInt16(uNumContacts);
// Each contact: WriteUInt128(ID) + WriteUInt32(IP) + WriteUInt16(UDP) + WriteUInt16(TCP) + WriteUInt8(Ver)
```
**Locations:**
- `Examples/eMule/srchybrid/kademlia/net/KademliaUDPListener.cpp:504-516`
- `Examples/aMule/src/kademlia/net/KademliaUDPListener.cpp:461-475`

**Envy Format:**
```cpp
pResponse->Write(m_ownId, KAD_ID_SIZE);           // 16 bytes
pResponse->WriteShortLE(tcpPort);                 // 2 bytes
pResponse->WriteByte(kadVersion);                 // 1 byte
pResponse->WriteShortLE(contactCount);            // 2 bytes
// Each contact: ID(16) + IP(4) + UDP(2) + TCP(2) + Ver(1)
```
**Location:** `Envy/Kademlia.cpp:427-455`

✅ **COMPATIBLE** - Exact format match with both eMule and aMule

---

### 3. KADEMLIA2_PING / KADEMLIA2_PONG

**eMule/aMule Implementation:**
```cpp
// eMule PONG response
CSafeMemFile fileIO2(2);
fileIO2.WriteUInt16(uUDPPort);  // 2 bytes - observed UDP port
SendPacket(fileIO2, KADEMLIA2_PONG, uIP, uUDPPort, senderUDPKey, NULL);

// eMule PONG reception
if (uLenPacket < 2) throw;  // Minimum 2 bytes
// ReadUInt16() - 2 bytes

// aMule PONG response
CMemFile packetdata(2);
packetdata.WriteUInt16(port);  // 2 bytes - observed UDP port
SendPacket(packetdata, KADEMLIA2_PONG, ip, port, senderKey, NULL);
```
**Locations:**
- `Examples/eMule/srchybrid/kademlia/net/KademliaUDPListener.cpp:1802-1806, 1811`
- `Examples/aMule/src/kademlia/net/KademliaUDPListener.cpp:1523-1524, 1532`

**Envy Implementation:**
```cpp
// PONG response
WORD observedPort = ntohs(pHost->sin_port);
pResponse->WriteShortLE(observedPort);  // 2 bytes

// PONG reception
if (pPacket->GetRemaining() < 2) return;
WORD observedPort = pPacket->ReadShortLE();  // 2 bytes
```
**Location:** `Envy/Kademlia.cpp:539-540, 555`

✅ **COMPATIBLE** - All implementations use 2-byte UDP port format

---

### 4. KADEMLIA2_REQ (FIND_NODE)

**eMule/aMule Format:**
```
<Type(1)><TargetID(16)><ReceiverID(16)>
```
**eMule Validation:**
```cpp
byte byType = fileIO.ReadUInt8();
byType = byType & 0x1F;
if (byType == 0) throw;  // Reject type 0
CUInt128 uTarget;
fileIO.ReadUInt128(uTarget);
CUInt128 uCheck;
fileIO.ReadUInt128(uCheck);
if (GetKadID() == uCheck) {  // Verify receiver ID matches
    // Process request
}
```
**aMule Validation:**
```cpp
uint8_t type = bio.ReadUInt8();
type &= 0x1F;
if (type == 0) throw;  // Reject type 0
CUInt128 target = bio.ReadUInt128();
CUInt128 check = bio.ReadUInt128();
if (GetKadID() == check) {  // Verify receiver ID matches
    // Process request
}
```
**Locations:**
- `Examples/eMule/srchybrid/kademlia/net/KademliaUDPListener.cpp:684-702`
- `Examples/aMule/src/kademlia/net/KademliaUDPListener.cpp:645-659`

**Envy Format:**
```cpp
BYTE searchType = pPacket->ReadByte();
BYTE type = (searchType & 0x1F);
if (type == 0 || type != KADEMLIA_FIND_NODE) return;  // Reject type 0, accept 0x0B
pPacket->Read(targetId, KAD_ID_SIZE);  // 16 bytes
pPacket->Read(receiverId, KAD_ID_SIZE);  // 16 bytes
if (memcmp(receiverId, m_ownId, KAD_ID_SIZE) != 0) return;  // Verify receiver ID
```
**Location:** `Envy/Kademlia.cpp:571-594`

✅ **COMPATIBLE** - Format and validation logic match both eMule and aMule

**Note:** Envy is more restrictive (only accepts FIND_NODE type 0x0B) while eMule/aMule accept any non-zero type. This is acceptable for minimal implementation scope.

---

### 5. KADEMLIA2_RES (FIND_NODE Response)

**eMule/aMule Format:**
```
<TargetID(16)><Count(1)><contacts...>
Each contact: <ID(16)><IP(4)><UDP(2)><TCP(2)><Ver(1)>
```
**eMule Implementation:**
```cpp
fileIO2.WriteUInt128(uTarget);
fileIO2.WriteUInt8(uCount);
// Each contact: WriteUInt128(ID) + WriteUInt32(IP) + WriteUInt16(UDP) + WriteUInt16(TCP) + WriteUInt8(Ver)
```
**Locations:**
- `Examples/eMule/srchybrid/kademlia/net/KademliaUDPListener.cpp:712-723`
- `Examples/aMule/src/kademlia/net/KademliaUDPListener.cpp:669-679, 697-698`

**Envy Format:**
```cpp
pResponse->Write(targetId, KAD_ID_SIZE);  // 16 bytes
pResponse->WriteByte(contactCount);        // 1 byte
// Each contact: ID(16) + IP(4) + UDP(2) + TCP(2) + Ver(1)
```
**Location:** `Envy/Kademlia.cpp:603-622`

✅ **COMPATIBLE** - Exact format match with both eMule and aMule

---

## 6. KADEMLIA_FIREWALLED_REQ / RES (TCP firewall-detection baseline)

Envy constants `KADEMLIA2_FIREWALLED_REQ` (0x50) / `KADEMLIA2_FIREWALLED_RES` (0x58) are the **Kad1 opcodes still used by Kad2**. They are **not** TagList packets. Historical `ED2K_KAD_GAP_ANALYSIS.md` framing (`<TargetID><TCPPort>…`) is wrong.

**eMule/aMule (2026 sources):**
- `FIREWALLED_REQ` (0x50): exact **2 bytes**, little-endian TCP port of the requester (`thePrefs.GetPort()`).
- `FIREWALLED_RES` (0x58): exact **4 bytes**, little-endian IPv4 as observed by the responder (`WriteUInt32(uIP)` host-order).
- `FIREWALLED2_REQ` (0x53, Kad version > 6): min **19 bytes** `<TCPPort 2><UserHash 16><ConnectOptions 1>`. Envy **parses inbound** 0x53 and answers with 0x58; outbound still emits 0x50 (v7+ still accept it).
- `FIREWALLED_ACK_RES` (0x59): empty UDP ACK, **deprecated for Kad ≥ 7** in favor of ED2K TCP `OP_KAD_FWTCPCHECK_ACK` (0xA8). Envy accepts both toward TCP Open; it does **not** open a TCP connect-back in this slice.
- `FIREWALLED_RES` updates public-IP observation only. TCP Open requires two independent ACKs (`IncFirewalled`-style). UDP reachability is a separate tester (`FWCHECKUDPREQ` / `KADEMLIA2_FIREWALLUDP`) and is **not** implemented.

**Envy:** `Envy/KadFirewallCheck.h`, `Envy/Kademlia.cpp` (`OnFirewalledRequest` / `OnFirewalledResponse` / `OnFirewalledAck`), `CEDClient` handles empty 0xA8. State is Kad-specific and does not write `Network.IsFirewalled()`.

**Wire-format impact:** ENVY now consumes/emits the existing Kad2/Kad1 `FIREWALLED_REQ` and `FIREWALLED_RES` (and consumes ACK 0x59 / 0xA8). No proprietary extension.

**Status:** TCP firewall-detection **baseline** (parser + bounded state). UDP firewall verification, Buddy and callback remain incomplete. Live interop **unverified**.

### #160 live harness scenarios (optional, not required CI)

When the #160 eMule/aMule harness lands, add opt-in scenarios:

1. Envy sends `FIREWALLED_REQ` (2-byte TCP port) to a verified eMule/aMule Kad contact.
2. Envy accepts a matching `FIREWALLED_RES` (4-byte IPv4) and records a public-IP observation (one peer is not authoritative).
3. Envy answers inbound `FIREWALLED_REQ` / `FIREWALLED2_REQ` with `FIREWALLED_RES` containing the observed source IPv4.
4. TCP firewall state remains distinct from UDP; do not treat Kad UDP traffic as TCP Open.
5. Capture ACK path: UDP 0x59 (Kad < 7) vs TCP 0xA8 (Kad ≥ 7). Connect-back from Envy is still a later slice.

---

## Protocol Constants Compatibility

### Kademlia Constants

| Constant | eMule Value | aMule Value | Envy Value | Status |
|----------|-------------|-------------|------------|--------|
| `K` (Bucket size) | 10 | 10 | `KAD_K = 10` | ✅ **MATCH** |
| `ALPHA_QUERY` | 3 | 3 | N/A (not used yet) | ⚠️ **N/A** |
| `KAD_ID_BITS` | 128 | 128 | `KAD_ID_BITS = 128` | ✅ **MATCH** |

**Sources:**
- `Examples/eMule/srchybrid/kademlia/kademlia/Defines.h:42` - `#define K 10u`
- `Examples/aMule/src/kademlia/kademlia/Defines.h:47` - `const unsigned int K = 10;`

**Envy:** `Envy/KadRoutingTable.h` (`KAD_K`, `KAD_ID_BITS`, `KAD_KBASE`, `KAD_KK`)

---

## IP Endianness Compatibility

### Storage Format

**eMule/aMule:** IPs stored in network byte order in packets, converted to host order when reading
**Envy:** IPs stored in host order in `KadContact.ip` (first octet in the high byte), converted to network order in `KadContactGetSockAddr()` (`Envy/Kademlia.h`)

**Packet Payload:**
- All implementations use host-order Little Endian in packet payloads
- `WriteUInt32()` / `ReadUInt32()` for IP addresses (eMule/aMule)
- `WriteLongLE()` / `ReadLongLE()` for IP addresses (Envy)

✅ **COMPATIBLE** - Endianness handling matches eMule/aMule convention

---

## Request Tracking (Outtrack List)

**eMule/aMule:** Uses `IsOnOutTrackList()` to verify responses match outstanding requests
**Envy:** Uses `IsRequestOutstanding()` with same logic

**Locations:**
- `Examples/eMule/srchybrid/kademlia/net/KademliaUDPListener.cpp:529, 735` - `IsOnOutTrackList()` checks
- `Examples/aMule/src/kademlia/net/KademliaUDPListener.cpp:2660, 2831` - `IsOnOutTrackList()` checks

✅ **COMPATIBLE** - All implementations track requests and reject unsolicited responses

---

## nodes.dat Import Compatibility

**aMule / eMule Community format (reference):**
- Version 0 (legacy count-first). Current aMule rejects it (“too old”).
- Version 1 — 25-byte records (ID, IPv4, UDP, TCP, Kad version)
- Version 2 — 34-byte records, plus KadUDPKey (uint32 key + uint32 associated IP) and a verified byte
- Version 3 edition 0 — normal contact list, 34-byte records
- Version 3 edition 1 — bootstrap edition, 25-byte records; aMule keeps the 50 XOR-closest Kad2 contacts and does **not** insert the whole list into the routing table

**Envy implementation (`Envy/KadNodesDat.h` + `CHostCache::ImportNodes`):**
- Parses v0 (every contact dropped: no Kad2 version nibble; type < 4 is not imported) and v1/v2/v3
- Unknown versions and v3 editions other than 0/1 fail closed
- Count/size arithmetic is overflow-safe; file cap 256 KiB; max 5000 declared contacts
- v2 UDP-key / verified fields are parsed then discarded (no runtime UDP-key protocol)
- v3 bootstrap edition selects at most 50 XOR-closest valid contacts (also `/24` cap 2)
- Normal files import at most 200 accepted contacts into `HostCache.Kademlia`
- Parser tests: `tests/test_kad_nodes_dat.cpp`
- Remote HTTP download of `https://upd.emule-security.org/nodes.dat` is **not** wired

Endianness (from eMule `WriteUInt32(GetIPAddress())` / `ReadUInt32`+`ntohl`, aMule ports):
- Header integers and ports: little-endian
- IPv4 field: four network-order octets (`203.0.113.5` = `CB 00 71 05`)
- KadUDPKey: two little-endian uint32 values

⚠️ **PARTIAL** — local modern `nodes.dat` parsing is implemented. That is not live Kad bootstrap packet success and not complete Kad interoperability. See `docs/10_dev/status.md`.

---

## Routing-table maintenance (local, 2026-09-19)

**Status:** implemented in production code + deterministic EnvyTests. **Not** live DHT evidence. Kad capability nibble stays 0. Firewall/Buddy/callback are out of this slice.

Previous Envy model used a fixed `KadBucket[128]` array indexed by the highest XOR-distance bit. A full bucket returned false from `AddContact()`; there was no split, replacement, zone refresh, or `/24` diversity.

### Representation

Envy now uses a binary **routing-zone tree** over 128-bit XOR distance from the local Kad ID (`Envy/KadRoutingTable.h`, class `Kad2RoutingTable`), not a fake `Split()` on a fixed array.

| Concept | Envy | aMule / eMule Community |
| --- | --- | --- |
| Zone tree | `KadRoutingZone` + leaf `KadRoutingBin` (`std::unique_ptr` children) | `CRoutingZone` + leaf `CRoutingBin` |
| Leaf capacity | `KAD_K = 10` | `K = 10` (`Defines.h`) |
| Split rule | `level < 127` AND `size == K` AND (`prefixInteger` < KK OR `level < KBASE`); `KBASE=4`, `KK=5`; also `m_zoneCount + 2 <= 1024`. `prefixInteger` is the 128-bit XOR prefix interpreted as an integer (saturates at `UINT32_MAX`; never shifts a uint32 by ≥ 32) | `CRoutingZone::CanSplit()` — same level/KK/KBASE/K test (`RoutingZone.cpp`); aMule stores `uint32 m_uZoneIndex` |
| Redistribute | next XOR bit at `zone.level` (`KadDistanceBit`) | `GetDistance().GetBitNumber(m_level)` |
| Max depth | 127 (`KAD_MAX_LEVEL`) | 127 |
| Closest contacts | gather + sort by full 128-bit XOR (not traversal order) | `GetClosestTo` / distance map |
| FindContact | copy-out (`KadContact&`) — no pointers into bins | raw `CContact*` |

Bootstrap HostCache entries are **not** inserted into leaves. `CKademlia::Bootstrap()` only sends BOOTSTRAP_REQ / FIND_NODE; contacts enter through normal `UpdateContact()` after packet validation.

### Contact sources and `verified`

`AddContact()` does not infer trust. Callers pass `KadContactUpdate`:

| Event | Source | `verified` | LRU / `lastSeen` |
| --- | --- | --- | --- |
| BOOTSTRAP_RES listed contacts | `Candidate` | no | insert only |
| BOOTSTRAP_RES responder | `Observed` | no | alive |
| FIND_NODE listed contacts | `Candidate` | no | insert only |
| Valid FIND_NODE_RES / PONG from a known endpoint | `ObserveAliveByEndpoint` | no | alive |
| HELLO_RES matching an outstanding HELLO_REQ | `Observed` + `markVerified` | **yes** | alive |
| Unsolicited HELLO_RES | ignored | no | no |

`verified` means IP/ID confirmed by **HELLO_RES that matches an outstanding HELLO_REQ** (or `MarkContactVerified`). Unsolicited HELLO_RES does not verify. nodes.dat “verified” bits and third-party listings are not live-verified. Malformed packets do not refresh a contact. FIND_NODE_RES is fail-closed: truncated contact lists are dropped before outstanding-request consume / `ObserveAliveByEndpoint`; a matching TargetID is required.

### LRU, types, replacement

Reference: aMule `CContact::UpdateType` / `CheckingType` (`Contact.cpp`), `CRoutingBin::SetAlive` / `PushToBottom` (front = oldest). Types 0–2 live by age, 3 new, 4 dead. Expire windows: type2 1h, type1 90m, type0 2h, checking +2m, min 10s between type steps.

When a full leaf **cannot** split, current aMule/eMule `CRoutingZone::Add` returns false. Envy keeps that default for a healthy verified incumbent vs an unverified newcomer, and adds a **1-slot replacement cache** (`KAD_REPLACEMENT_CACHE`) so a stale/dead incumbent can be replaced. The cache is overwritten, never grown.

Timing uses injected `uint64_t` milliseconds and wrap-safe `KadElapsedAtLeast`. Production `CKademlia` uses `GetTickCount64()`. Tests inject timestamps; no `Sleep()`.

### Stale-zone refresh

Reference: aMule/eMule `CRoutingZone::OnBigTimer` / `RandomLookup` — refresh when `prefixInteger < KK || level < KBASE || remaining >= 0.8*K`. Interval 1 hour (`KAD_ZONE_REFRESH_INTERVAL_MS`); first `CollectMaintenance` on a leaf **arms** `nextBigTimer = now + 10s` (`KAD_ZONE_REFRESH_START_MS`, aMule `StartTimer`) and does not treat `lastRefresh == 0` as immediately stale; global gap 10s; at most one FIND_NODE refresh and one HELLO ping per `OnTimer` cycle.

Refresh targets are generated **inside the stale leaf’s ID range** (`KadMakeRefreshTarget` / `KadIdInZone`) and sent with existing `SendFindNodeRequest(contact, targetId)` (`KADEMLIA2_REQ` unchanged).

### Subnet diversity / eclipse resistance

Reference: aMule `CRoutingBin::AddContact` / `CheckGlobalIPLimits` / `AdjustGlobalTracking`:

- 2 contacts per IPv4 `/24` **per leaf** (`KAD_MAX_CONTACTS_SUBNET_BIN`)
- 10 contacts per `/24` **globally** (`MAX_CONTACTS_SUBNET` / `KAD_MAX_CONTACTS_SUBNET_GLOBAL`)
- 1 Kad ID per IP (`MAX_CONTACTS_IP`)
- LAN excepted when `allowLan` (`Settings.Experimental.LAN_Mode`)

Mask is host-order `ip & 0xFFFFFF00` (first octet in the high byte). Duplicate Kad IDs update in place and do not inflate counts. Removal decrements.

Search-response `/24` caps (per FIND_NODE reply) are **not** in this PR.

### Security bounds

- Contacts ≤ 2048, zones ≤ 1024, depth ≤ 127, replacement ≤ 1 per leaf
- Iterative leaf walk with a 128-step guard (no unbounded recursion from peer IDs)
- Local Kad ID and zero ID rejected; multicast/broadcast/port 0 rejected; `Security.IsDenied` at the `CKademlia::UpdateContact` boundary
- Same Kad ID + same endpoint: update; same ID + different endpoint: verified incumbent wins; different IDs + same endpoint: reject

### Tests

`tests/test_kad_routing_table.cpp` — XOR distance/order, split/redistribute, unsplittable replacement, LRU, refresh arm-then-fire (`+10s`) + target-in-zone + bounded work, 128-bit prefix / level-40 in-zone (no uint32 shift), `/24` diversity + byte order, LAN exception, adversarial `/24` flood and max depth.

**Wire-format impact: none** — Kad2 packet formats are unchanged; this slice changes local routing-table maintenance.

---

## Known Differences (Acceptable)

### 1. FIND_NODE Type Validation

**eMule/aMule:** Accepts any non-zero type after masking with 0x1F
**Envy:** Only accepts `KADEMLIA_FIND_NODE (0x0B)` for minimal scope

**Impact:** ⚠️ **MINOR** - Envy is more restrictive but still compatible. Other clients can still send FIND_NODE requests with type 0x0B which will be accepted.

### 2. Tag List Support

**eMule/aMule:** Full tag list support in all packets (BOOTSTRAP_RES, HELLO_RES, etc.)
**Envy:** Tag lists not yet implemented (minimal scope)

**Impact:** ⚠️ **MINOR** - Tag lists are optional in eMule protocol. Core functionality works without them. Tag lists are used for advanced features like external port detection and firewall status, but basic Kad2 operation works without them.

---

## Test Recommendations

### Manual Testing Checklist

- [ ] Bootstrap from aMule/eMule nodes
- [ ] Receive and respond to PING requests
- [ ] Send PING and receive PONG responses
- [ ] Handle FIND_NODE requests from eMule clients
- [ ] Send FIND_NODE requests and process responses
- [x] Import nodes.dat from eMule installation (parser + local path; live file from an eMule profile still manual)
- [ ] Verify routing table grows over time
- [ ] Test with multiple eMule/aMule clients simultaneously

### Network Testing

1. **Wireshark Capture:**
   - Capture UDP packets on port 4672
   - Verify opcodes match (0x01, 0x09, 0x60, 0x61, 0x21, 0x29)
   - Verify packet sizes match expected formats

2. **Interoperability:**
   - Connect to live eMule/aMule network
   - Verify Envy appears in other clients' routing tables
   - Verify Envy can discover and communicate with other nodes

---

## Conclusion

Opcode values, BOOTSTRAP/PING/PONG/FIND_NODE layouts, IP endianness notes, and request tracking matched the inspected eMule/aMule sources. Local routing-table maintenance (zone split, LRU/type liveness, bounded replacement, stale-zone FIND_NODE refresh, `/24` diversity) is implemented in `KadRoutingTable.h` with EnvyTests. `HostCache::ImportNodes` parses legacy v0 plus new-format v1/v2/v3 via `KadNodesDat.h`. That is **not** live DHT interoperability (`docs/10_dev/status.md`: partial / unverified).

**Verified Compatibility:**
- ⚠️ **eMule (srchybrid)** — opcode/format match only
- ⚠️ **aMule** — opcode/format match only
- ⚠️ **Shareaza** - No Kad2 implementation found to verify
- ⚠️ **MLDonkey** - No Kad2 implementation found to verify

Intentional scope limits (restrictive FIND_NODE type validation, no tag lists yet) remain. Do not treat this report as production-ready Kad2 interop.

**Status:** opcode/format comparison only; live eMule/aMule DHT interop is **unverified** (`docs/10_dev/status.md`)

---

## Client-Specific Notes

### eMule (srchybrid)
- ⚠️ **Opcode/format match only** (not live interop)
- Uses identical packet formats to aMule
- Same opcode values and validation logic
- Reference: `Examples/eMule/srchybrid/kademlia/net/KademliaUDPListener.cpp`

### aMule
- ⚠️ **Opcode/format match only** (not live interop)
- Uses identical packet formats to eMule
- Same opcode values and validation logic
- Reference: `Examples/aMule/src/kademlia/net/KademliaUDPListener.cpp`

### Shareaza
- ⚠️ **No Kad2 implementation found**
- Searched `Examples/shareaza/` - no KADEMLIA2 opcodes or Kad2-specific code found
- May use different protocol or naming conventions
- **Status:** Cannot verify compatibility (no reference implementation found)

### MLDonkey
- ⚠️ **No Kad2 implementation found**
- Searched `Examples/mldonkey/` - no KADEMLIA2 opcodes or Kad2-specific code found
- MLDonkey is primarily OCaml-based and may use different architecture
- **Status:** Cannot verify compatibility (no reference implementation found)

---

## References

- **eMule Source:** `Examples/eMule/srchybrid/kademlia/net/KademliaUDPListener.cpp`
- **eMule Constants:** `Examples/eMule/srchybrid/kademlia/kademlia/Defines.h`
- **aMule Source:** `Examples/aMule/src/kademlia/net/KademliaUDPListener.cpp`
- **aMule Opcodes:** `Examples/aMule/src/include/protocol/kad2/Client2Client/UDP.h`
- **aMule Constants:** `Examples/aMule/src/kademlia/kademlia/Defines.h`
- **Envy Implementation:** `Envy/KadRoutingTable.h`, `Envy/Kademlia.h`, `Envy/Kademlia.cpp`, `Envy/EDPacket.h`
- **aMule routing:** `src/kademlia/routing/RoutingZone.cpp`, `RoutingBin.cpp`, `Contact.cpp`
- **eMule Community routing:** `kademlia/routing/RoutingZone.cpp` (`CanSplit`, `OnBigTimer`, `RandomLookup`)
