# Kad Documentation

Status: active
Last updated: 2026-10-24
Scope: Envy Kad2 notes. Opcode matching is not live interop. Kad6/Ember overlays are not Kad2.

**Specification first:** [Kademlia paper](https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf). **Interop second:** eMule Community and aMule Kad2 sources. Ember and eMule eSE extensions are experimental and must stay distinct from Kad2. See [REFERENCE_IMPLEMENTATIONS.md](../REFERENCE_IMPLEMENTATIONS.md).

## Start here
- [Kad2 compatibility report](kad2-compatibility-report.md) (wire/opcode match only)

## Initial exchange wire layout and inbound limits

Compared against eMule Community v0.72a (`irwir/eMule` `ac3d52eafd88e9f6d9e0c2204c6dbead18db750b`, tag `eMule_v0.72a-community`: `CKademliaUDPListener::SendMyDetails`, `AddContact_KADEMLIA2`, `Process_KADEMLIA2_HELLO_REQ/RES`, `CDataIO::ReadTag`, `CPacketTracking`) and `amule-org/amule` `d043ffa5a6bb7e000ec6d8c3a1f95dfb4f7d4e12` (`KademliaUDPListener.cpp`, `PacketTracking.cpp`, `Tag.cpp`), both read on 2026-10-24. This is source comparison and synthetic tests, not live interoperability (#160).

### HELLO body

- `HELLO_REQ` and `HELLO_RES` share one body: `<SenderKadID 16><TCPPort 2><Version 1><TagCount 1><Tag>*`, tags as `<Type 1><NameLength 2><Name><Value>`. There is no fixed UDP port field. Envy previously sent a zero ID and a fixed UDP port with no tag count, which neither reference can parse. Envy now sends its own ID, the configured TCP port, Kad version 8 and no tags. `KadHello.h`.
- Tags read (union of the two readers): HASH16, STRING, UINT8/16/32/64, FLOAT32, BOOL, BLOB (32-bit length), BSOB (8-bit length), STR1-STR16 and the compact `type|0x80` form with a one-byte name. eMule's Kad reader accepts only HASH, STRING, UINT8-64, FLOAT32 and BSOB; aMule's also BOOL, BLOB and STR1-16.
- **Rejected as a whole** (both references abort on a tag they cannot delimit): unknown tag types, BOOLARRAY (the two sources size it differently), a name or value running past the body, a declared tag count larger than the tags present, and version 0 (aMule). Bytes after the last declared tag are ignored, as in the references.
- `TAG_SOURCEUPORT` (0xFC) is applied in `HELLO_REQ` **and** `HELLO_RES` (`AddContact_KADEMLIA2` is shared), any integer width, ignored when zero. Divergence: a value above 65535 is ignored instead of truncated to 16 bits. Divergence: two valid but different values for `TAG_SOURCEUPORT` or `TAG_KADMISCOPTIONS` in one body reject the HELLO; the references let the last one win. The stored contact IP is always the datagram source, so an advertised port can only point at another port of the same host.
- `TAG_KADMISCOPTIONS` (0xF2): bit 0 UDP firewalled, bit 1 TCP firewalled, bit 2 requests `HELLO_RES_ACK` (meaningful only from version 8 and up). A UDP-firewalled sender is answered but neither added nor verified, as in both references. Envy sends no such tag.

### Version and capability behaviour

- Envy advertises Kad version 8 (eMule v0.72a advertises 10). Version 8 means `TAG_KADMISCOPTIONS` and `HELLO_RES_ACK` exist. Envy has no UDP keys and no obfuscation, so it sends unobfuscated packets with no sender key; a peer that requests a `HELLO_RES_ACK` from Envy cannot get one (eMule skips the ACK itself when it holds no sender key). Consequence: eMule/aMule may keep Envy unverified in their routing tables. Advertising a lower version would instead trigger their legacy challenge paths and was not chosen without live evidence. Not validated live.
- Envy does not send `TAG_SOURCEUPORT`, so peers use the datagram source port; this is correct without NAT port remapping on the Kad socket.

### Correlation and replay

- A `HELLO_RES` is accepted only for an outstanding `HELLO_REQ` to the same IP **and port** (the references match the IP only), and the entry is consumed by the first match, so a duplicate or unsolicited `HELLO_RES` is ignored. The entry is registered before the send and withdrawn when the datagram was not sent (`CKademlia::SendPacket` is true only when the datagram layer accepted the packet and `sendto` reported the whole datagram sent). Entries expire after `KAD2_REQUEST_TIMEOUT`.
- A contact enters the routing table as a candidate from a `HELLO_REQ`, and is marked IP-verified only by the solicited `HELLO_RES`.

### Two-byte requests and inbound limits

- A Kad2 request without a body is exactly the two header bytes. The UDP dispatcher accepts a two-byte datagram only when it is exactly `0xE4 0x01` (`BOOTSTRAP_REQ`) or `0xE4 0x60` (`PING`) (`KadIsBodylessRequest`); every other opcode, protocol byte or length at two bytes is dropped. Both accepted opcodes are rate limited on receipt.
- Limits per source IP and opcode: `BOOTSTRAP_REQ` 2, `PING` 2, `HELLO_REQ` 3 per minute. aMule (`InTrackListIsAllowedPacket`) uses exactly these three. eMule v0.72a limits `BOOTSTRAP_REQ` and `PING` to 2 per minute but does **not** track `HELLO_REQ`; Envy keeps aMule's stricter figure. Envy uses a token bucket per (IP, opcode): a bucket of one minute of tokens, each packet costing 60 s divided by the rate, so a source may burst to the rate and then sustain it. eMule uses the same bucket but lets refused packets keep draining it and bans the IP below minus three minutes; aMule counts packets in a sliding window and bans above five times the rate. Divergence: in Envy a refused packet does not deepen the debt and Envy never bans, so a legitimate retry recovers after at most one token interval.
- The bound of 4096 tracked (IP, opcode) entries, fail-closed when full after pruning entries idle for a minute, is Envy's own; the references keep one list entry per source IP without a size bound and clean it every 12 minutes. A clock that moves backwards counts as zero elapsed time. The older `CheckRateLimit` stays as is for the other requests. Source addresses are forgeable, which is why a reply is only sent after the limit check and no reply is larger than the request class allows (`BOOTSTRAP_RES` up to a few hundred bytes remains the amplification the limit is there for).

### Remaining limits

- A `HELLO_RES` from the exact endpoint that was sent a `HELLO_REQ` still marks the contact verified. The references additionally use UDP keys and `HELLO_RES_ACK` to prove the address; Envy implements neither, so this is weaker than the references against an off-path spoofer.
- Kad IDs are exchanged as opaque 16 bytes; eMule serializes them as four little-endian 32-bit words. Distance and bucket handling of Envy's routing table were not re-checked here.
- Not validated against live eMule/aMule (#160); obfuscation is #431.

## Bootstrap candidate retry scheduling (issue #430)

`CKademlia::Bootstrap()` snapshots the Kad host cache and uses
`KadBootstrapRotation` for bounded, progressively rotating selection, so a
cold start walks the whole cache instead of re-sampling its leading entries.

**Cycle and batch.** The periodic caller is `CKademlia::OnTimer`, driven by
`CMainWnd::OnTimer`. That code counts whole seconds and runs when
`tNow > tLast5SecInterval + 5`, i.e. once per six one-second timer ticks: about
every 6 s and, with a steady clock, never closer than 5 s (the previous call may
fall late in its second, the next early in the following one). `OnTimer` calls
`Bootstrap()` while the routing table holds fewer than five contacts, and each
cycle sends at most two bootstrap requests while the table is empty and at most
three once it holds contacts.

`Bootstrap()` also enforces a minimum spacing between cycles: 5 s while the
table is empty, 30 s once it holds contacts. The 5 s cold-start spacing does not
bind on the periodic path, since the timer is already slower, and only holds
back the discrete `ConnectTo(PROTOCOL_KAD)` entry. The 30 s spacing does bind
there: a table with one to four contacts bootstraps at most every 30 s.

The sustained cold-start rate is set by the outstanding-request budget, not by
the tick: nine usable slots (one of the ten stays free for other Kad traffic),
each held for the 30-second request timeout. Against peers that never answer
that is **0.25-0.30 requests/second**, measured by driving the production request
lifecycle through the selection loop and asserted by
`kad_response_cold_start_rate_budget_bound`; a 5 s tick or a batch of three gave
the same rate when measured. eMule and aMule send one request every 2 seconds
while `GetNumContacts() == 0` and every 15 seconds afterwards, with no
per-request timeout, so Envy is slower at cold start than both, not equal. That
is still enough to give every entry of a 50-entry list its first request in
about 160 seconds.

The batch is bounded by the free budget **before** candidates are selected
(`KadBootstrapBatchLimit`), and nothing is selected when the budget is full.
`Select()` advances the rotation cursor past every candidate it scans, so
selecting first and cutting the send loop on the budget skipped untried peers
until the cursor wrapped the cache: a 50-entry cold start then took about 460
seconds to contact everyone instead of about 160. The status line reports the
cycles the full budget blocked, and bootstrap registrations the retry policy
refused, as `budget_blocked`. From the rotation cycle that means a full
protected map, since `Select()` already defers endpoints still in flight or
answered; it has no per-candidate metric.

**Retry and backoff.** Genuine 30-second timeouts enter per-UDP-endpoint
backoff starting at 60 seconds, doubling to a ten-minute cap. Capacity eviction
or explicit removal cancels correlation without adding a failure or cooldown.
A correlated `BOOTSTRAP_RES` completes only the answered endpoint and clears
its penalty, preserving independent pending requests and their later timeouts.
The references consume a one-shot candidate list; Envy's retry/backoff is
local policy for a persistent host cache, not a Kad2 wire requirement.

**Response correlation.** Use one unconsumed request for the sender IP within
180 seconds, preferring the requested UDP endpoint. Otherwise accept a reply
from any UDP source port only when exactly one eligible request exists for
that IP. Remove the original outstanding slot even for an alternate-port
reply, or consume the late-response credit if its 30-second slot has expired.
Both references match IP/opcode without comparing ports and consume one
tracking entry in `CPacketTracking::IsOnOutTrackList`.

There is no transaction ID in this reply. With concurrent requests to ports
of one IP, an alternate-port reply is inherently ambiguous: Envy refuses to
guess. Retain the completed endpoint and observed reply port as replay markers
until the original 180-second window closes, and defer reusing that endpoint
until then. A duplicate from either port cannot consume another request.
A recent cancelled request has no observed reply port: it also prevents
IP-only fallback to another endpoint until its window expires; exact matching
of the independent requested endpoint remains available. Protect recent
unconsumed and cancelled history from capacity eviction for the same reason.
These ambiguity/replay guards deliberately tighten the references' IP-only
rule. A changed source port remains accepted for a unique request. A later
reply after a fresh request to the same endpoint is indistinguishable from an
old datagram on this wire protocol. Contacts still pass normal admission,
security and subnet checks; no additional verification is inferred.

All bootstrap retry/correlation and outstanding-request timestamps use
`GetTickCount64()` milliseconds. Prune non-pending retry state once its
acceptance window has elapsed and it has stayed idle for a further maximum backoff past
its cooldown, so an unresponsive peer keeps its backoff level instead of restarting at
60 seconds when the cap expires. Each
scan is bounded by the 2048-entry map; pending requests and all recent correlation/cancellation/replay history
are protected under capacity pressure. A full protected map prevents sending
another bootstrap instead of silently losing its correlation state. A cleanup
triggered only on selection with modulo-32-bit ages would still mistake a
whole-counter-cycle-old request for a recent one after inactivity.

**Response bounds.** A reply whose announced contact count cannot fit in the
datagram (`count * 25` above the bytes after the 21-byte header) is malformed: it
is counted as `malformed`, applies nothing, not even the responder, and is not
correlated, so it neither completes nor consumes a genuine request, which stays in
flight and can still be answered or time out. This follows current
`amule-org/amule` (`ea85d0d`, #2054, 2026-10-24), which validates the whole list
with `CHECK_PACKET_SANE_COUNT(numContacts, 25)` before adding even the responding
peer. eMule Community v0.72a has no such check: it reads the list incrementally,
so a short read throws after the contacts already added are kept. The two
references therefore differ only on a malformed body; both emit at most 20
contacts and write a count equal to what they carry, so no honest peer is
affected and Envy takes the stricter, more recent rule. An earlier revision of
this document said both references keep the framed prefix; that is no longer true
of aMule. A body too short for the fixed 21-byte header is malformed the same way.

A fully framed list above 20 contacts is read up to the local bound of 20 (an
allocation cap; neither reference enforces a receive bound) and counted as
`partial`, never as `valid_responses`. A reply is `valid_responses` only when its
list is fully framed and within the bound. Counters other than `malformed` move
only after the sender has been correlated, so unsolicited datagrams cannot move
`valid_responses` or `partial` (they can move `malformed` and `rejected`, as any
UDP sender can). A `partial` reply consumes its request exactly as a complete one
does; both references remove the tracked request before parsing.

Contacts learned from a bootstrap response enter the routing table as
unverified candidates. The reference clients instead mark every contact of a
bootstrap response **verified** while their routing table is empty, as a
deliberate trade to speed up connecting. Envy does not copy that shortcut:
`verified` here means protocol evidence equivalent to a `HELLO_RES` from that
endpoint, and `FindClosestContacts` does not require it, so cold-start
contacts are usable for searches without weakening the eviction rules that
protect verified contacts.

The initial simultaneous FIND_NODE burst to unconfirmed bootstrap
contacts is deferred until normal routing-table maintenance.

The status log emits one aggregate Kad line per minute: cache candidates,
deferred/invalid candidates, sent/expired bootstrap requests, received
fully framed (`valid_responses`) and `partial` responses, accepted contacts,
`malformed` and `rejected` (uncorrelated: unsolicited, duplicate, ambiguous or past the 180 s window)
responses, `contacts_refused` (contacts of a correlated response that routing
admission refused: address policy, per-IP and per-/24 diversity, table full),
requests the datagram layer
refused (`send_failed`), cycles skipped because the request budget was full
(`budget_blocked`), source searches without contacts, and routing-table count. No endpoints, contents, IDs or payloads are included in that status
line.

**Limitations:** UDP availability, packet dispatch and Kad2 obfuscation
are not fixed by this policy. Unclassified UDP traffic is not evidence
of Kad traffic (#431). Envy still populates routing leaves only from
bootstrap responses, while the reference clients add the contacts of a
normal (non-bootstrap-edition) `nodes.dat` straight into the routing table
and let ordinary maintenance verify them — so a host cache full of dead
entries leaves Envy with no second path to a populated table. Kad2 remains
**partial / unverified** until eMule/aMule exchange tests in #160 show
sustained routing and searches. A full Kad completion claim remains blocked
by #86.

**Needs real-peer validation under #160** (not provable by the deterministic
tests): whether live eMule/aMule peers answer `BOOTSTRAP_REQ` from the cache
endpoints at all (a silent endpoint is a timeout, not a rotation defect);
whether replies arrive from the requested UDP port or an alternate one behind
NAT; whether the ambiguity, replay and cancellation guards on IP-only fallback
drop honest replies the references would accept; whether `contacts_refused` stays low on real
responses (routing diversity, address policy); and whether unverified
candidates become usable contacts once HELLO handling (#502) lands.

### Bootstrap behaviour compared

Legend: **[code]** verified by reading the named source; **[test]** covered by a
deterministic test in this repository; **[hyp]** hypothesis, not yet verified.
`develop` is the state before this change.

| Function | Envy `develop` | Envy (this change) | eMule Community 0.72a | aMule (current) | Assessment |
| --- | --- | --- | --- | --- | --- |
| Candidate source | First 20 entries of `HostCache.Kademlia` **[code]** | Whole cache, snapshotted under its lock **[code]** | Routing table for a normal `nodes.dat`; `s_liBootstrapList` (50 XOR-closest) only for a bootstrap-edition file **[code]** | Same, `s_bootstrapList` **[code]** | Envy's cache-wide snapshot is sound; the missing routing-table path is the real gap (#86) |
| Rotation | None — leading prefix re-sampled **[code]** | Deterministic cursor across cycles **[code] [test]** | List consumed head-first, popped, never retried **[code]** | Same **[code]** | Equivalent coverage; neither reference randomises the order, so a deterministic cursor is faithful |
| Cold-start cadence | 3 requests / 30 s **[code]** | At most 2 requests per cycle of about 6 s (never closer than 5 s) while routing is empty, then 3 / 30 s. Sustained 0.25-0.30 requests/s, set by the 9-slot budget × 30 s timeout **[code] [test]** | 1 request / 2 s while `GetNumContacts() == 0`, else 1 / 15 s **[code]** | Same **[code]** | Below the 0.5 requests/s reference rate, not equal to it; enough for a first request to every entry of a 50-entry list in about 160 s. A larger batch or a 5 s tick would not change the rate, since the budget binds. The 3-per-30 s cycle afterwards is 0.1 requests/s, above the references' 0.067, so it is left unchanged |
| Concurrent requests | Bounded by the 10-slot outstanding map **[code]** | The batch is clamped to the free budget (9 usable slots) **before** selection, so no candidate is selected and left untried **[code] [test]** | One bootstrap in flight at a time **[code]** | Same **[code]** | Envy is more parallel but strictly bounded |
| Request timeout | 30 s (`KAD2_REQUEST_TIMEOUT`) **[code]** | Unchanged **[code] [test]** | No per-request timeout; candidate is discarded on send **[code]** | Same **[code]** | Envy-specific, needed because its cache persists |
| Backoff | None **[code]** | 60 s doubling to 10 min, bounded map of 2048 endpoints **[code] [test]** | None **[code]** | None **[code]** | Envy addition, not a wire requirement; keeps a persistent cache from hammering dead peers |
| Late response | Rejected after 30 s **[code]** | Accepted for 180 s after the request **[code] [test]** | 180 s track list **[code]** | Same **[code]** | Now matches both references |
| Response correlation | IP + UDP port + type **[code]** | One request within 180 s: exact endpoint preferred, unique IP fallback; replay/ambiguity guards **[code] [test]** | Sender IP + opcode, no port **[code]** | Same **[code]** | Accept changed ports without guessing between independent requests; ambiguity/replay guards are intentional local policy |
| Contact-count bound | Reject if count > 100 **[code]** | Read at most 20 contacts; a fully framed list above 20 is counted as `partial` **[code] [test]** | No receive bound; sends at most 20 **[code]** | Same; rejects a count the datagram cannot hold (`CHECK_PACKET_SANE_COUNT`, `ea85d0d`) **[code]** | Envy stays bounded; the 20 is a sender bound in both references, a local allocation cap here |
| Malformed contact list | Partial contact ends the loop, earlier ones kept **[code]** | Count the datagram cannot hold: `malformed`, nothing applied, request not consumed **[code] [test]** | Request removed before parsing; the read throws at EOF and contacts already added are kept **[code]** | Request removed before parsing, then the whole list is rejected before any contact, responder included, is added **[code]** | The references differ only on a body no honest peer sends; Envy follows current aMule, and a malformed reply cannot burn a genuine request |
| Routing insertion | `UpdateContact`, unverified candidate **[code]** | Unchanged **[code] [test]** | `Add(..., verified = GetNumContacts() == 0, ...)` — verified while the table is empty **[code]** | Same **[code]** | Deliberate divergence: Envy keeps `verified` meaning `HELLO_RES` evidence; `FindClosestContacts` does not require it |
| Routing seeded from `nodes.dat` | No **[code]** | No (out of scope) **[code]** | Yes, for a normal `nodes.dat` **[code]** | Yes **[code]** | **Open gap, tracked under #86** — bootstrap responses are Envy's only path to a populated table |
| UDP obfuscation | Not implemented (#431) **[code]** | Unchanged **[code]** | Obfuscates its request when the peer's Kad version ≥ 6; answers a plain request in clear **[code]** | Same **[code]** | A plain request still gets a clear reply, so obfuscation is not a cold-start blocker **[code]** |
| Diagnostics | One unconditional line per cycle **[code]** | One aggregate line per minute with `valid_responses`, `partial`, `rejected`, `contacts_refused`, `malformed`, `send_failed` and `budget_blocked`; no endpoints or payloads **[code]** | Per-packet debug logging behind debug levels **[code]** | Same **[code]** | Envy's aggregate form is privacy-safe and lets a live run tell budget starvation from silence |
| Tests | None for bootstrap selection | The real response-handler body (`KademliaBootstrap.inl`) is exercised by `test_kad_bootstrap_response.cpp`; rotation and the budget helper by `test_kad_bootstrap_rotation.cpp`, and the cold-start cadence by driving that same request lifecycle through the selection loop in the response fixture. 79 with the routing-table suite; mutation checks of the new guards are all caught **[test]** | No automated tests (`SelfTest.cpp` covers neither Kad nor bootstrap) **[code]** | Large Kad unit-test suite under `unittests/tests/`, but none covering bootstrap selection or retry **[code]** | Envy has the stronger coverage of this specific path; live interop still pending (#160) |

Live interoperability remains unproven either way: every row above is a
source-level or unit-test claim, never a live-traffic measurement.

### Measured convergence (simulation, not live traffic)

Does the lower cold-start rate (about 0.3 against the references' 0.5 requests/s)
delay convergence? A deterministic simulation on a simulated clock drives the
production request lifecycle (`KademliaBootstrap.inl`, `KadBootstrapRotation.h`)
with the Kad timer every 6 s, against a model of the reference scheduler
(`CKademlia::Process` in eMule v0.72a and aMule master: one request per 2 s while
the table is empty, one per 15 s otherwise, no in-flight budget, each candidate
asked once, reply correlated on the sender IP for 180 s). Responsive peers answer
with 20 contacts spread over distinct /24 networks; peers are chosen by a fixed
hash, so a run is reproducible. One run per row; the reference column is a model
of the source, not a measurement of a running client.

| Scenario (cache size, responsive share) | Envy first contact | Reference model | Envy requests / peak in flight |
| --- | --- | --- | --- |
| 20 peers, none answer, 30 min | none; 6 requests per peer on the 60 s to 10 min backoff | none; list exhausted after 20 | 120 / 9 |
| 20 or 50 or 500 peers, 10% | 12.3 s | 10.3 s | 6 / 6 |
| 20 or 50 peers, 50% or 90% | 0.3 s | 0.3 s | 2 / 2 |
| 50 peers, 50%, replies delayed 5 s | 5.0 s | 5.0 s | 2 / 2 |
| 50 peers, 50%, half reply from port + 1 | 0.3 s | 0.3 s | 2 / 2 |
| 500 peers, 1% | 240.3 s (74 peers asked) | never (list capped at 50) | 74 / 9 |
| 2000 peers, 10% | 12.3 s | 10.3 s | 6 / 6 |
| Routing table holds 3 contacts, 50 peers, 10% | 30.3 s | 80.3 s | 6 / 3 |

Findings: time to the first usable contact differs from the reference schedule by
about 2 s here (less than one Kad timer cycle), because it is set by how many
peers must be asked before one answers, and Envy asks two per 6 s cycle against
one per 2 s. A first reply carries up to 20 contacts, so five admitted contacts
arrive with the first reply. The 0.5 request/s figure is not the bottleneck, and
the budget never exceeds 9 requests in flight. After losing contacts Envy
recovers faster than the reference (three peers per 30 s against one per 15 s)
and, unlike the one-shot reference list, it keeps trying a large dead cache with
backoff instead of giving up, with fair coverage: in 30 minutes of silence a
50-peer cache is asked 267 times (5 or 6 per peer), a 500-peer cache is covered
once (540 requests, 1 or 2 per peer), and a 2000-peer cache would need about
two hours at this rate (the cache is bounded by the host-cache size limit), always with
at most 9 requests in flight and at most 2048 tracked endpoints. Restart: `Init()` clears the retry history, so a
restarted client asks every cached peer again, as the references do with a fresh
list. No change to the cadence is warranted, so none was made. The deterministic
regression is `kad_response_first_contact_vs_reference`; the other rows come from
a scratch driver that is not part of the repository.

### Reference sources compared

- aMule, `amule-org/amule` (the active upstream since the project moved off
  `amule-project`). Rows above were first verified at
  `6b0500cb743a361cb8c1b4f3df713524064dfb06`; the response-parsing rows were
  re-read on 2026-10-24 at `d043ffa5a6bb7e000ec6d8c3a1f95dfb4f7d4e12`, which
  contains `ea85d0d` (#2054, "reject impossible counts, truncated Kad records").
  Links below keep the first revision:
  [`src/kademlia/kademlia/Kademlia.cpp`](https://github.com/amule-org/amule/blob/6b0500cb743a361cb8c1b4f3df713524064dfb06/src/kademlia/kademlia/Kademlia.cpp)
  (bootstrap cycle),
  [`src/kademlia/net/KademliaUDPListener.cpp`](https://github.com/amule-org/amule/blob/6b0500cb743a361cb8c1b4f3df713524064dfb06/src/kademlia/net/KademliaUDPListener.cpp)
  (reply shape, 20-contact sender bound),
  [`src/kademlia/net/PacketTracking.cpp`](https://github.com/amule-org/amule/blob/6b0500cb743a361cb8c1b4f3df713524064dfb06/src/kademlia/net/PacketTracking.cpp)
  (request correlation),
  [`src/kademlia/routing/RoutingZone.cpp`](https://github.com/amule-org/amule/blob/6b0500cb743a361cb8c1b4f3df713524064dfb06/src/kademlia/routing/RoutingZone.cpp)
  (bootstrap-edition `nodes.dat`, 50 XOR-closest contacts).
- eMule Community 0.72a (`VERSION_MJR 0` / `VERSION_MIN 72` / build 28),
  `irwir/eMule` branch `v0.72a` at
  `ac3d52eafd88e9f6d9e0c2204c6dbead18db750b`: the same four files under
  `srchybrid/kademlia/`: [packet tracking](https://github.com/irwir/eMule/blob/ac3d52eafd88e9f6d9e0c2204c6dbead18db750b/srchybrid/kademlia/net/PacketTracking.cpp),
  [UDP listener](https://github.com/irwir/eMule/blob/ac3d52eafd88e9f6d9e0c2204c6dbead18db750b/srchybrid/kademlia/net/KademliaUDPListener.cpp).
  Both branch HEADs were rechecked on 2026-10-20. eMule `master`
  (`88a8c8f2d782849642880ea616cdca60b01bd8c7`, initial import in 2016)
  is older than v0.72a and is not the maintained comparison. aMule packet
  tracking already uses a 64-bit clock; eMule v0.72a uses 32-bit ticks.

### State regression coverage

`tests/test_kad_bootstrap_response.cpp` compiles the same handler and request
lifecycle bodies from `Envy/KademliaBootstrap.inl`, using the real request
metadata and retry policy. Packet storage, the clock and contact admission
are adapters; sockets, `OnPacket` dispatch and the real security/admission
boundary are not exercised by that fixture. Routing admission is covered
separately by `test_kad_routing_table.cpp`. EnvyTests includes these cases on
x64 and Win32: exact/alternate ports, unsolicited/duplicate/late/expired
responses, independent ports, ambiguous fallback, true timeout vs capacity
or explicit cancellation, late replies after eviction with another port pending,
inactivity beyond both half and full 32-bit cycles,
short headers, malformed contact counts (never applied, never consuming a request),
the local contact cap, and time to a first contact against the reference schedule,
plus that unsolicited datagrams of any framing never move a response counter and
that a reply above the local bound is counted as `partial`, not as valid, while
consuming its request like a complete one. Fixtures use
the Windows temp directory with scoped cleanup and bounded child paths.

## Related
- [Status](../../10_dev/status.md) · [Dev docs](../../10_dev/) · [Protocol index](../README.md)
