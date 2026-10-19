# Kad Documentation

Status: active
Last updated: 2026-10-20
Scope: Envy Kad2 notes. Opcode matching is not live interop. Kad6/Ember overlays are not Kad2.

**Specification first:** [Kademlia paper](https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf). **Interop second:** eMule Community and aMule Kad2 sources. Ember and eMule eSE extensions are experimental and must stay distinct from Kad2. See [REFERENCE_IMPLEMENTATIONS.md](../REFERENCE_IMPLEMENTATIONS.md).

## Start here
- [Kad2 compatibility report](kad2-compatibility-report.md) (wire/opcode match only)

## Bootstrap candidate retry scheduling (issue #430)

`CKademlia::Bootstrap()` snapshots the Kad host cache and uses
`KadBootstrapRotation` for bounded, progressively rotating selection, so a
cold start walks the whole cache instead of re-sampling its leading entries.

**Cycle and batch.** While the routing table is empty, send at most two
bootstrap requests per cycle of at least five seconds; afterwards, use three
per 30 seconds. The timer has a five-second floor. The peak cold-start rate
is therefore at most 0.4 requests/second, below the references' one request
per two seconds. Both cycles reserve one of the ten outstanding slots for
other traffic. Against silent peers, nine bootstrap slots and a 30-second
request timeout further bound throughput to at most nine requests per
30 seconds; other Kad traffic can reduce it further.

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
`GetTickCount64()` milliseconds. Prune non-pending retry state older than the
maximum backoff once its acceptance window and cooldown have elapsed. Each
scan is bounded by the 2048-entry map; pending requests and all recent correlation/cancellation/replay history
are protected under capacity pressure. A full protected map prevents sending
another bootstrap instead of silently losing its correlation state. A cleanup
triggered only on selection with modulo-32-bit ages would still mistake a
whole-counter-cycle-old request for a recent one after inactivity.

**Response bounds.** At most 20 contacts are read from a response, and only
those the datagram actually framed. An over-counted or short contact list is
clamped and counted, not discarded: both reference clients read the announced list without a receive count cap,
adding contacts incrementally; a short read throws after already-added contacts
remain. Envy precomputes the fully framed prefix instead of relying on an
exception, retaining usable contacts without attempting a partial read. Trailing bytes
remain ignored. A body too short for the fixed 21-byte header is rejected as
malformed before any outstanding request is consumed.

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
well-framed responses, accepted contacts, malformed/clamped/rejected
responses or contacts, source searches without contacts, and routing-table
count. No endpoints, contents, IDs or payloads are included in that status
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

### Bootstrap behaviour compared

Legend: **[code]** verified by reading the named source; **[test]** covered by a
deterministic test in this repository; **[hyp]** hypothesis, not yet verified.
`develop` is the state before this change.

| Function | Envy `develop` | Envy (this change) | eMule Community 0.72a | aMule (current) | Assessment |
| --- | --- | --- | --- | --- | --- |
| Candidate source | First 20 entries of `HostCache.Kademlia` **[code]** | Whole cache, snapshotted under its lock **[code]** | Routing table for a normal `nodes.dat`; `s_liBootstrapList` (50 XOR-closest) only for a bootstrap-edition file **[code]** | Same, `s_bootstrapList` **[code]** | Envy's cache-wide snapshot is sound; the missing routing-table path is the real gap (#86) |
| Rotation | None — leading prefix re-sampled **[code]** | Deterministic cursor across cycles **[code] [test]** | List consumed head-first, popped, never retried **[code]** | Same **[code]** | Equivalent coverage; neither reference randomises the order, so a deterministic cursor is faithful |
| Cold-start cadence | 3 requests / 30 s **[code]** | At most 2 requests / cycle of at least 5 s while routing is empty, then 3 / 30 s **[code] [test]** | 1 request / 2 s while `GetNumContacts() == 0`, else 1 / 15 s **[code]** | Same **[code]** | Faster than the old cold start but below the reference rate: at most 0.4 req/s peak and nine in-flight slots per 30-second timeout; no proof that cadence alone fixes cold start |
| Concurrent requests | Bounded by the 10-slot outstanding map **[code]** | Same, one slot reserved **[code]** | One bootstrap in flight at a time **[code]** | Same **[code]** | Envy is more parallel but strictly bounded; acceptable |
| Request timeout | 30 s (`KAD2_REQUEST_TIMEOUT`) **[code]** | Unchanged **[code] [test]** | No per-request timeout; candidate is discarded on send **[code]** | Same **[code]** | Envy-specific, needed because its cache persists |
| Backoff | None **[code]** | 60 s doubling to 10 min, bounded map of 2048 endpoints **[code] [test]** | None **[code]** | None **[code]** | Envy addition, not a wire requirement; keeps a persistent cache from hammering dead peers |
| Late response | Rejected after 30 s **[code]** | Accepted for 180 s after the request **[code] [test]** | 180 s track list **[code]** | Same **[code]** | Now matches both references |
| Response correlation | IP + UDP port + type **[code]** | One request within 180 s: exact endpoint preferred, unique IP fallback; replay/ambiguity guards **[code] [test]** | Sender IP + opcode, no port **[code]** | Same **[code]** | Accept changed ports without guessing between independent requests; ambiguity/replay guards are intentional local policy |
| Contact-count bound | Reject if count > 100 **[code]** | Read at most 20 framed contacts, clamp and count the rest **[code] [test]** | No receive bound; keeps the framed prefix; sends at most 20 **[code]** | Same **[code]** | Envy stays bounded while no longer discarding a usable answer |
| Truncated contact list | Partial contact ends the loop, earlier ones kept **[code]** | Framed prefix kept, anomaly counted **[code] [test]** | Read throws at EOF, contacts already added are kept **[code]** | Same **[code]** | Equivalent |
| Routing insertion | `UpdateContact`, unverified candidate **[code]** | Unchanged **[code] [test]** | `Add(..., verified = GetNumContacts() == 0, ...)` — verified while the table is empty **[code]** | Same **[code]** | Deliberate divergence: Envy keeps `verified` meaning `HELLO_RES` evidence; `FindClosestContacts` does not require it |
| Routing seeded from `nodes.dat` | No **[code]** | No (out of scope) **[code]** | Yes, for a normal `nodes.dat` **[code]** | Yes **[code]** | **Open gap, tracked under #86** — bootstrap responses are Envy's only path to a populated table |
| UDP obfuscation | Not implemented (#431) **[code]** | Unchanged **[code]** | Obfuscates its request when the peer's Kad version ≥ 6; answers a plain request in clear **[code]** | Same **[code]** | A plain request still gets a clear reply, so obfuscation is not a cold-start blocker **[code]** |
| Diagnostics | One unconditional line per cycle **[code]** | One aggregate line per minute, no endpoints or payloads **[code]** | Per-packet debug logging behind debug levels **[code]** | Same **[code]** | Envy's aggregate form is privacy-safe and sufficient |
| Tests | None for bootstrap selection | 14 deterministic rotation tests; 52/52 with routing-table regressions **[test]** | No automated tests (`SelfTest.cpp` covers neither Kad nor bootstrap) **[code]** | Large Kad unit-test suite under `unittests/tests/`, but none covering bootstrap selection or retry **[code]** | Envy has the stronger coverage of this specific path; live interop still pending (#160) |

Live interoperability remains unproven either way: every row above is a
source-level or unit-test claim, never a live-traffic measurement.

### Reference sources compared

- aMule, `amule-org/amule` (the active upstream since the project moved off
  `amule-project`), `master` at `6b0500cb743a361cb8c1b4f3df713524064dfb06`:
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
short headers, partial contact lists and the local contact cap. Fixtures use
the Windows temp directory with scoped cleanup and bounded child paths.

## Related
- [Status](../../10_dev/status.md) · [Dev docs](../../10_dev/) · [Protocol index](../README.md)
