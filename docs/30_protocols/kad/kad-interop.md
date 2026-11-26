# Kad2 publish interop notes

Status: research reference
Survey date: 2026-11-26 (Europe/Paris)
Scope: Source comparison of Kad2 PUBLISH opcodes, packet layouts, and
hardening in maintained ed2k/Kad clients. This is not live DHT
interoperability evidence (#160). Canonical Envy status remains
[`docs/10_dev/status.md`](../../10_dev/status.md).

These notes record a review of [PR #526](https://github.com/Mika3578/Envy/pull/526)
(fixes #514) and a GitHub survey of other clients, so later work on #427
and #428 does not have to rediscover the same facts. Citations below are
to sources actually read on the survey date, pinned to the commit SHA
that was checked out.

## Preferred references

Do **not** treat [irwir/eMule](https://github.com/irwir/eMule) as a
maintained eMule Community tree. The checkout dated 2016-04-10
(`88a8c8f`) is a fork of `SomeSupport/eMule` with a single commit; its
`opcodes.h` values are still the Kad2 standard, but the repo is not
maintained. [emule-community-version/emule-project](https://github.com/emule-community-version/emule-project)
is documentation and config only (no C++ sources).

Prefer these as live Kad2 references (see the client table for SHAs):

- [amule-org/amule](https://github.com/amule-org/amule) — most actively
  maintained aMule tree (the historical `amule-project/amule` repo is
  quieter; last commit there was 2026-06-25).
- [emulebb/emulebb](https://github.com/emulebb/emulebb) — maintained
  eMule 0.70b-line MFC client.
- [eMuleAI/eMuleAI](https://github.com/eMuleAI/eMuleAI) — maintained
  eMule-family fork (advertises Kad version 0x0a).

Older Envy docs that still say "eMule Community" and point at `irwir/eMule`
should be read with that correction.

## What PR #526 changes

#526 (head at the time of review: `a1b9fc2`, 14 files) aligns Envy's Kad2
PUBLISH opcode constants with eMule/aMule, moves them into
`Envy/KadOpcodes.h`, removes invented ACK aliases, and deletes the
non-standard publish handlers and unused senders.

It does **not** implement publication. After #526, inbound standard
PUBLISH packets (`0x43`, `0x44`, `0x45`, `0x4B`, `0x4C`), plus
`HELLO_RES_ACK` (`0x22`) and `SEARCH_NOTES_REQ` (`0x35`), are dropped
unparsed before any handler, reply, rate limit, or routing-table update.
Envy still does not send PUBLISH. Files and sources shared by Envy are
therefore still not findable on the live Kad network. That work is #427
(TagList framing) and #428 (standard publish/store path).

On `develop` before #526, `CKademlia::PublishKeyword` /
`PublishSource` had no application callers (only definitions in
`Kademlia.cpp` / `Kademlia.h`; the legacy `KadProtocol` path is compiled
only under `ENVY_LEGACY_KADEMLIA`, which is never defined). Envy was not
publishing from the UI or library.

### Opcode values before and after #526

| Constant | Envy before (`develop`, `EDPacket.h`) | Envy after (`KadOpcodes.h` in #526) | eMule / aMule |
| --- | --- | --- | --- |
| `KADEMLIA2_PUBLISH_KEY_REQ` | **0x41** | **0x43** | 0x43 |
| `KADEMLIA2_PUBLISH_SOURCE_REQ` | **0x42** | **0x44** | 0x44 |
| `KADEMLIA2_PUBLISH_NOTES_REQ` | 0x43 | **0x45** | 0x45 |
| `KADEMLIA2_PUBLISH_RES` | **0x49** | **0x4B** | 0x4B |
| `KADEMLIA2_PUBLISH_RES_ACK` | **0x4A** (wrong name) | **0x4C** | 0x4C |
| `KADEMLIA2_HELLO_RES_ACK` | **0x1A** | **0x22** | 0x22 |

eMule marks `0x41` and `0x49` as unused ("Old Opcode, don't use") and
`0x42` / `0x4A` as Kad1 `KADEMLIA_PUBLISH_NOTES_*_DEPRECATED`. Kad1 still
uses `KADEMLIA_PUBLISH_REQ` `0x40` and `KADEMLIA_PUBLISH_RES` `0x48`.
eMule's listener silently ignores those deprecated Kad1 opcodes and
throws "Unknown opcode" for a truly unknown byte such as `0x41`.

#526 also removes invented ACK aliases that collided with real opcodes,
notably `SEARCH_KEY_REQ_ACK` = `0x34` (actually `SEARCH_SOURCE_REQ`) and
`REQ_ACK` = `0x22` (actually `HELLO_RES_ACK`).

The old Envy handlers listened on `0x41` / `0x42` / `0x49` and parsed a
proprietary entry layout (see #428). Real eMule/aMule peers send
`0x43` / `0x44` / `0x4B` (and `0x45` for notes), so those packets never
hit the old handlers. Dropping a standard PUBLISH without a reply is the
same posture as a UDP-firewalled eMule/aMule node, and as Shareaza's
stub (below). It is a necessary opcode fix, not the feature "Envy
files appear on Kad".

## Origin of the wrong opcodes

Shareaza already defined the **correct** Kad2 values. In
[ivan386/Shareaza](https://github.com/ivan386/Shareaza) `0c2f2f5`
(2019-08-08), `shareaza/Kademlia.h` L58–64 has
`KADEMLIA2_PUBLISH_KEY_REQ` = `0x43` and `KADEMLIA2_PUBLISH_RES` =
`0x4B`. It does not define `0x4C`, `0x22`, or `0x62`.

The same correct values are still in the upstream Envy tree
[GetEnvy/Envy](https://github.com/GetEnvy/Envy) `7737356` (2026-08-06),
`Envy/Kademlia.h` L55–61.

The wrong `0x41` / `0x42` / `0x43` / `0x49` constants were introduced
**in this fork** by commit
[`0d548d5`](https://github.com/Mika3578/Envy/commit/0d548d5)
(2026-06-15, "feat(ed2k): add Source Exchange v2 and crypto foundations"),
which added them to `Envy/EDPacket.h`. #526 repairs that regression; it
does not fix an inherited Shareaza bug.

## Shareaza and GetEnvy Kad behaviour

Shareaza's `Kademlia.cpp` (`0c2f2f5`) is a stub:

- It can send `BOOTSTRAP_REQ` and a HELLO-style packet, and it answers
  `PING` with `PONG`.
- It handles inbound `BOOTSTRAP_RES`.
- Every other opcode, including `KADEMLIA2_PUBLISH_KEY_REQ` at L201, is
  commented out and falls through.
- It advertises Kad version `0x05` (`Kademlia.h` L28).

The `dht/` tree in Shareaza is jech's BitTorrent mainline DHT, not eMule
Kad2. The quazaa Shareaza fork (2017) and PeerProject (2020) keep the
same stub. GetEnvy/Envy `7737356` still has the same commented-out
PUBLISH cases. Shareaza knew the right opcodes and simply did not
implement publish.

## Maintained clients (survey 2026-11-26)

"Last commit" is the date of the last commit on the default branch of
the checkout, not GitHub's `pushed_at` (which is misleading on forks).
"Agree" means the PUBLISH / ACK / `HELLO_RES_ACK` / `SEARCH_NOTES` /
`FIREWALLUDP` values that were actually read match #526 (`0x22`, `0x35`,
`0x43`, `0x44`, `0x45`, `0x4B`, `0x4C`, `0x62`) unless a gap is noted.

| Client | Last commit | Language | Opcodes agree with #526? | Publish support | Notes read on this survey |
| --- | --- | --- | --- | --- | --- |
| [amule-org/amule](https://github.com/amule-org/amule) `a965e8d` | 2026-11-26 | C++ | Yes ([UDP.h L41–55](https://github.com/amule-org/amule/blob/a965e8d/src/include/protocol/kad2/Client2Client/UDP.h#L41)) | Full storer and publisher. Default Kad version 0x08; 0x0a is gated ([Constants.h L53–54](https://github.com/amule-org/amule/blob/a965e8d/src/include/protocol/kad2/Constants.h#L53)). | Per-IP request limits: PUBLISH_KEY 3/min, SOURCE 2, NOTES 2 ([PacketTracking.cpp L115–150](https://github.com/amule-org/amule/blob/a965e8d/src/kademlia/net/PacketTracking.cpp#L115)). Flood-ban path is described as applying only to keyed packets. `CheckTagRecords` parses every record before applying any ([KademliaUDPListener.cpp L113–123](https://github.com/amule-org/amule/blob/a965e8d/src/kademlia/net/KademliaUDPListener.cpp#L113)). |
| [emulebb/emulebb](https://github.com/emulebb/emulebb) `e854150` | 2026-11-03 | C++ (MFC 0.7.x) | Yes ([Opcodes.h L566–608](https://github.com/emulebb/emulebb/blob/e854150/srchybrid/Opcodes.h#L566)) | Full (eMule 0.70b lineage) | Same `PacketTracking` / `InTrackListIsAllowedPacket` design as aMule. |
| [eMuleAI/eMuleAI](https://github.com/eMuleAI/eMuleAI) `a2f05dc` | 2026-07-25 | C++ | Yes ([Opcodes.h L782–820](https://github.com/eMuleAI/eMuleAI/blob/a2f05dc/srchybrid/Opcodes.h#L782)). Kad version 0x0a. | Full | Token buckets: KEY 4/min, SOURCE 3, NOTES 2 ([PacketTracking.cpp L131–139](https://github.com/eMuleAI/eMuleAI/blob/a2f05dc/srchybrid/kademlia/net/PacketTracking.cpp#L131)). |
| [ModderMule/emule-qt](https://github.com/ModderMule/emule-qt) `b00babd` | 2026-11-26 | C++/Qt | `KADEMLIA2_PUBLISH_KEY_REQ` is used in `Search.cpp` / `KademliaUDPListener.cpp`; literal values were not re-read in this pass | Full (rmule's notes describe it as Kad v10) | Not used as a primary reference here. |
| [emulebb/emulebb-rust](https://github.com/emulebb/emulebb-rust) `0f14286` | 2026-11-25 | Rust | Yes ([constants.rs L107–138](https://github.com/emulebb/emulebb-rust/blob/0f14286/crates/emulebb-kad-proto/src/constants.rs#L107)) | Full store, UDP obfuscation, publish snapshot | Stock caps: 1000 sources/file, 150 notes/file, 100 publishers/keyword, 50 000 files per keyword index, 60 000 keyword entries ([kad_store/mod.rs L50–66](https://github.com/emulebb/emulebb-rust/blob/0f14286/crates/emulebb-index/src/kad_store/mod.rs#L50), [keyword.rs L20–30 and L237–245](https://github.com/emulebb/emulebb-rust/blob/0f14286/crates/emulebb-index/src/kad_store/keyword.rs#L237)). |
| [njMule/njMule](https://github.com/njMule/njMule) `4314838` | 2026-11-26 | Rust | Yes ([opcodes.rs L180–200](https://github.com/njMule/njMule/blob/4314838/njmule-engine/src/protocol/packet/opcodes.rs#L180)) | Publisher, index, and notes modules present | Limits: KEY 4/min, SOURCE 3, NOTES 2 ([packet_tracking.rs L25–40](https://github.com/njMule/njMule/blob/4314838/njmule-engine/src/kad/packet_tracking.rs#L25)). Responses accepted only for a matching outbound request. Fuzz targets exist for Kad decoders. |
| [untaimed18/Ember-P2P](https://github.com/untaimed18/Ember-P2P) `b46fc6c` | 2026-11-25 | Rust/Tauri | Yes ([messages.rs L19–29](https://github.com/untaimed18/Ember-P2P/blob/b46fc6c/src-tauri/src/network/kad/messages.rs#L19)) | Publishes and stores | Per-opcode limits apply to **requests only**. A comment in [protection.rs L150–206](https://github.com/untaimed18/Ember-P2P/blob/b46fc6c/src-tauri/src/network/kad/protection.rs#L150) records that rate-limiting `PUBLISH_RES` (`0x4B`) made confirmations stay at zero. Also caps decompression work per IP and globally. |
| [i234dev/MyMule](https://github.com/i234dev/MyMule) `98d062c` | 2026-11-21 | Go | Yes ([packet.go L33–53](https://github.com/i234dev/MyMule/blob/98d062c/internal/kad/packet.go#L33)) | Stores and answers publishes | Unkeyed publishes are held pending and kept only if the claimed address answers a ping, with caps on pending IPs, items, and bytes ([store.go L25–45 and L55–135](https://github.com/i234dev/MyMule/blob/98d062c/internal/kad/store.go#L25)). Limits match aMule: SOURCE/NOTES 2, KEY 3 ([handlers.go L47–79](https://github.com/i234dev/MyMule/blob/98d062c/internal/kad/handlers.go#L47)). |
| [Lazark0x/rmule](https://github.com/Lazark0x/rmule) `27e6f1d` | 2026-11-02 | Rust | Yes, with a per-opcode parity table | KEY and SOURCE publisher/storer; NOTES refused gracefully; `0x4C` sent only when requested | Claims captured aMule 2.3.3 fixtures: aMule accepted rmule's `0x43` and answered `0x4B` ([kad-udp.md L81–85](https://github.com/Lazark0x/rmule/blob/27e6f1d/docs/protocol/parity/kad-udp.md#L81), [captured_keyword_answers.rs L36](https://github.com/Lazark0x/rmule/blob/27e6f1d/crates/rmule-kad/tests/kad/captured_keyword_answers.rs#L36)). The storer credits the datagram source IP, not an IP claimed in the payload. This interop evidence was not re-run here. |
| [laurentgeynet-ux/eMule-Rust](https://github.com/laurentgeynet-ux/eMule-Rust) `fbbea83` | 2026-10-18 | Rust | Yes ([opcodes.rs L30–47](https://github.com/laurentgeynet-ux/eMule-Rust/blob/fbbea83/crates/mule-protocol/src/kad/opcodes.rs#L30)) | Decoders for KEY, SOURCE, NOTES, and RES | Size caps (50 contacts, 300 sources, 150 notes, 32 tags). |
| [XiaoYouChR/Kelpie](https://github.com/XiaoYouChR/Kelpie) `c3c475a` | 2026-10-02 | Go | Values that exist agree ([packets.go L15–34](https://github.com/XiaoYouChR/Kelpie/blob/c3c475a/internal/wire/kad/packets.go#L15)) | Only `SEARCH_SOURCE` (`0x34`), `PUBLISH_SOURCE` (`0x44`), and `PUBLISH_RES` (`0x4B`) | Downloader-oriented subset; no keyword publish. |
| [a-pavlov/jed2k](https://github.com/a-pavlov/jed2k) `bc10ef8` | 2023-09-03 | Java | Yes ([PacketCombiner.java L53–72](https://github.com/a-pavlov/jed2k/blob/bc10ef8/core/src/main/java/org/dkf/jed2k/protocol/kad/PacketCombiner.java#L53)) | Handlers for `0x43`, `0x44`, `0x4B` (L139–141) | `Kad2PublishKeysReq` is `<keyword id><u16 count><entries>`. Not recently maintained. |
| [qmule/libed2k](https://github.com/qmule/libed2k) `5408c65` | 2016-06-02 | C++ | Yes ([packet_struct.hpp L217–231](https://github.com/qmule/libed2k/blob/5408c65/include/libed2k/packet_struct.hpp#L217)) | Opcode table only; no publish handlers were found | Stale. |
| [ygrek/mldonkey](https://github.com/ygrek/mldonkey) `0d44635` (and [carlonluca/mldonkey](https://github.com/carlonluca/mldonkey) `bcd1a39`, 2026-11-18) | 2025-01-28 / 2026-11-18 | OCaml | n/a | Kad1 only | `donkeyProtoKademlia.ml` uses `0x30` / `0x38` / `0x40` / `0x48`. No Kad2 opcodes were found. Not a Kad2 reference. |
| [ivan386/Shareaza](https://github.com/ivan386/Shareaza) `0c2f2f5` | 2019-08-08 | C++ | Yes for `0x43`/`0x44`/`0x45`/`0x4B`; no `0x4C`, `0x22`, `0x62` | None (stub) | Ancestor of Envy; see above. |
| [GetEnvy/Envy](https://github.com/GetEnvy/Envy) `7737356` | 2026-08-06 | C++ | Yes (`Kademlia.h` L55–61) | None (same stub) | Upstream Envy still has the correct constants. |

Other recent GitHub repositories from the same search (tiny clones, UIs
around aMule, or ed2k-link generators) were not used as protocol
references.

## Wire layouts (for #427 / #428)

Read from aMule `Process2Publish*` / `Search.cpp` / `SafeFile.cpp` and
from eMule-family `Process_KADEMLIA2_PUBLISH_*`. rmule's parity table
matches these layouts; it is corroboration, not a second specification.

### Tag format

Each tag is:

```text
<Type 1><NameLength 2><Name bytes>[cut at first NUL]<Value>
```

`CFileDataIO::ReadTag` in amule-org `a965e8d`
([SafeFile.cpp L383–470](https://github.com/amule-org/amule/blob/a965e8d/src/SafeFile.cpp#L383))
accepts HASH16, STRING, UINT64/32/16/8, FLOAT32, and BSOB. An unknown
type rejects the packet. A TagList is `<Count 1>` followed by that many
tags.

Envy's current `WriteEntryTags` / `ReadEntryTags` uses a private layout
`<SourceID 16><IP 4><UDP 2><TCP 2><TagCount 1>[<TagId 1><TagLen 2><raw>]*`.
That structure has no counterpart in the clients above and must not
survive #427.

### PUBLISH packets

- **`KADEMLIA2_PUBLISH_KEY_REQ` (`0x43`)**:
  `<KeywordHash 16><Count 2>[<FileHash 16><TagList>]*`.
  aMule packs at most 50 files per packet (`Search.cpp` STOREKEYWORD
  path). The storer reads the 16-bit count, optionally pre-parses all
  records (`CheckTagRecords`), then indexes each file under the keyword.
- **`KADEMLIA2_PUBLISH_SOURCE_REQ` (`0x44`)**:
  `<FileHash 16><SourceID 16><TagList>`.
  Tags include `TAG_SOURCETYPE`, `TAG_SOURCEPORT`, optional
  `TAG_SOURCEUPORT`, `TAG_FILESIZE`, and `TAG_ENCRYPTION`. The storer
  should credit the **datagram source IP**, not an IP claimed in the
  payload (rmule documents this; aMule issue
  [#2315](https://github.com/amule-org/amule/issues/2315) notes that some
  handlers still trust the source IP when the receiver key is not
  checked — only the issue discussion was read, not a live test).
- **`KADEMLIA2_PUBLISH_NOTES_REQ` (`0x45`)**:
  `<FileHash 16><SourceID 16><TagList>` (filename, rating, comment,
  size).
- **`KADEMLIA2_PUBLISH_RES` (`0x4B`)**:
  `<TargetHash 16><Load 1>[Options 1]`.
  eMule/aMule send this after a successful (or "full but still ack")
  store. They stay silent when UDP-firewalled or when the target is
  outside the XOR search tolerance (except LAN).
- **`KADEMLIA2_PUBLISH_RES_ACK` (`0x4C`)**:
  empty body. Sent only when the `0x4B` options byte has bit 0 set
  **and** the peer provided a UDP key (eMule
  `Process_KADEMLIA2_PUBLISH_RES`).

aMule and eMule also refuse to index, and do not send a `0x4B`, when
`CUDPFirewallTester::IsFirewalledUDP(true)` is true, so as not to give
the publisher a false success.

## Hardening checklist (before Envy ever stores publishes)

Copy these behaviours from the maintained clients before implementing a
storer role. Outbound HighID `PUBLISH_SOURCE` can come first, but a
storer without the items below is weaker than every maintained client in
the table.

1. **Parse the whole packet before applying any record** (aMule
   `CheckTagRecords`). A truncated later tag must not commit earlier
   entries.
2. **Per-IP request limits, not response limits.** Use aMule's figures
   unless a later reference is chosen: PUBLISH_KEY 3/min, SOURCE 2,
   NOTES 2 (BOOTSTRAP 2, PING 2, HELLO_REQ 3 already exist in Envy).
   Ember's experience: never rate-limit `PUBLISH_RES` (`0x4B`).
3. **Ban only keyed packets**, so a spoofed source cannot get an honest
   peer banned (aMule comment on `MassiveFlood`; MyMule states the same
   rule).
4. **Store the datagram source IP**, never an IP from the payload.
5. **XOR distance / SEARCHTOLERANCE** and **do not store when UDP
   firewalled**.
6. **Stock caps** (emulebb-rust constants, described as matching stock
   eMule): 1000 sources per file, 150 notes per file, 100 publishers per
   keyword, 50 000 files per keyword, 60 000 keyword entries overall.
7. **Ping-verification for unkeyed publishes** (MyMule): hold the entry
   with bounded pending IPs/items/bytes; keep it only if the claimed
   address answers. Drop unkeyed publishes that carry no sender key.
8. **No storer role without UDP keys, obfuscation, and a UDP firewall
   tester.** Envy has none of these today. Until they exist, leaving
   PUBLISH dropped unparsed (#526) is the safe default.

## Open questions

- **Kad version 8 and `HELLO_RES_ACK` (`0x22`).** Envy advertises
  `KADEMLIA_VERSION` 8 (`Envy/Kademlia.h`). eMule defines version 8 as
  `TAG_KADMISCOPTIONS` and `KADEMLIA2_HELLO_RES_ACK`. #526 drops inbound
  `0x22` because Envy has no UDP keys. Envy already sends no
  `TAG_KADMISCOPTIONS` (see [kad/README.md](README.md)), so it should not
  *request* an ACK. Peers that see version 8 might still send or expect
  one. The existing HELLO notes already warn that eMule/aMule may keep
  Envy unverified. Confirm that Envy never sets misc-options bit 2, and
  decide later whether advertising a lower version is better — not
  without live evidence (#160).
- **`FIREWALLUDP` (`0x62`)** stays `Unknown` in Envy. eMule, aMule,
  MyMule, Kelpie, and rmule handle it as part of the UDP firewall tester.
  Fine until that tester exists.
- **`SEARCH_NOTES_REQ` (`0x35`)** is dropped by #526. eMule still
  answers it. Acceptable until notes are in scope.
- **No live Envy interop test** against eMule or aMule (#160). The only
  third-party packet captures mentioned above are rmule's, and they were
  not replayed here.
- **rmule fixtures and licence.** rmule is GPL-3; Envy is
  AGPL-3.0-or-later. Do not copy rmule's captured datagrams into this
  tree until a maintainer confirms licence compatibility and required
  attribution. The layouts above were taken from aMule/eMule sources,
  not by copying those fixtures.

## Recommended implementation order

1. Merge #526 (correct opcodes; fail closed on PUBLISH).
2. **#427** — standard TagList codec, with golden vectors, used first
   for SEARCH answers. Retire `WriteEntryTags` / `ReadEntryTags`.
3. **#428** — outbound `PUBLISH_SOURCE` (`0x44`) for a HighID node only
   (types 1/4). No storer yet.
4. Outbound keyword publish (`0x43`), still no storer.
5. Storer role last, and only together with the hardening checklist
   (keys, obfuscation, firewall tester, caps, parse-before-apply).

#526 is a prerequisite, not a substitute, for #427 and #428.
