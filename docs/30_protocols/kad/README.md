# Kad Documentation

Status: active
Last updated: 2026-10-12
Scope: Envy Kad2 notes. Opcode matching is not live interop. Kad6/Ember overlays are not Kad2.

**Specification first:** [Kademlia paper](https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf). **Interop second:** eMule Community and aMule Kad2 sources. Ember and eMule eSE extensions are experimental and must stay distinct from Kad2. See [REFERENCE_IMPLEMENTATIONS.md](../REFERENCE_IMPLEMENTATIONS.md).

## Start here
- [Kad2 compatibility report](kad2-compatibility-report.md) (wire/opcode match only)

## Bootstrap candidate retry scheduling (issue #430)

`CKademlia::Bootstrap()` snapshots the Kad host cache and uses
`KadBootstrapRotation` for bounded, progressively rotating selection, so a
cold start walks the whole cache instead of re-sampling its leading entries.

**Cycle and batch.** While the routing table is still empty the timer permits
at most two bootstrap requests per 4-second cycle; once it holds contacts the
cycle returns to three requests per 30 seconds. Both cycles stay inside the
existing maximum-outstanding-request budget and reserve one slot for other Kad
traffic. The cold-start rate (0.5 requests/second) is the rate the reference
clients use: eMule and aMule retry bootstrap every 2 seconds while
`GetNumContacts() == 0` and every 15 seconds afterwards, until Kad is
connected. Envy's Kad timer ticks at 5 seconds, which sets the floor on how
short its cycle can be.

**Retry and backoff.** Unanswered requests enter per-UDP-endpoint backoff
starting at 60 seconds, doubling up to a 10-minute cap. A correlated
`BOOTSTRAP_RES` clears the penalty for every endpoint of that IP. The
reference clients have no equivalent penalty because they pop each candidate
off a one-shot bootstrap list and never retry it; the backoff is Envy policy
for a host cache that persists across sessions, not a Kad2 wire requirement.

**Response correlation.** An exact endpoint match on a tracked outstanding
request is tried first. Failing that, a response is still correlated when its
sender IP was asked for a bootstrap within the last 180 seconds, on whatever
UDP source port it arrives. That mirrors
`CPacketTracking::IsOnOutTrackList`, which both reference clients key on
sender IP and opcode with a 180-second window and no port comparison: a reply
can legitimately arrive from a UDP port other than the one the contact
advertised, and a source port is trivially forged, so requiring it would
reject honest answers without adding spoofing resistance. Admitted contacts
still pass the normal routing-admission, security and subnet checks.

**Response bounds.** At most 20 contacts are read from a response, and only
those the datagram actually framed. An over-counted or short contact list is
clamped and counted, not discarded: both reference clients consume whatever
prefix of the announced list arrived and keep those contacts, so dropping the
whole response would cost an otherwise usable peer its answer. Trailing bytes
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
| Cold-start cadence | 3 requests / 30 s **[code]** | 2 requests / 4 s while routing is empty, then 3 / 30 s **[code] [test]** | 1 request / 2 s while `GetNumContacts() == 0`, else 1 / 15 s **[code]** | Same **[code]** | Was the main divergence. Cold start is now 0.5 req/s, the reference rate; the 3-per-30 s cycle afterwards is 0.1 req/s, already above eMule/aMule's 0.067 req/s in that state, so it is left unchanged |
| Concurrent requests | Bounded by the 10-slot outstanding map **[code]** | Same, one slot reserved **[code]** | One bootstrap in flight at a time **[code]** | Same **[code]** | Envy is more parallel but strictly bounded; acceptable |
| Request timeout | 30 s (`KAD2_REQUEST_TIMEOUT`) **[code]** | Unchanged **[code] [test]** | No per-request timeout; candidate is discarded on send **[code]** | Same **[code]** | Envy-specific, needed because its cache persists |
| Backoff | None **[code]** | 60 s doubling to 10 min, bounded map of 2048 endpoints **[code] [test]** | None **[code]** | None **[code]** | Envy addition, not a wire requirement; keeps a persistent cache from hammering dead peers |
| Late response | Rejected after 30 s **[code]** | Accepted for 180 s after the request **[code] [test]** | 180 s track list **[code]** | Same **[code]** | Now matches both references |
| Response correlation | IP + UDP port + type **[code]** | Exact endpoint, else sender IP within 180 s on any port **[code] [test]** | Sender IP + opcode, no port **[code]** | Same **[code]** | Port matching rejected honest NATed replies and added no spoofing resistance |
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
  [`src/kademlia/kademlia/Kademlia.cpp`](https://github.com/amule-org/amule/blob/master/src/kademlia/kademlia/Kademlia.cpp)
  (bootstrap cycle),
  [`src/kademlia/net/KademliaUDPListener.cpp`](https://github.com/amule-org/amule/blob/master/src/kademlia/net/KademliaUDPListener.cpp)
  (reply shape, 20-contact sender bound),
  [`src/kademlia/net/PacketTracking.cpp`](https://github.com/amule-org/amule/blob/master/src/kademlia/net/PacketTracking.cpp)
  (request correlation),
  [`src/kademlia/routing/RoutingZone.cpp`](https://github.com/amule-org/amule/blob/master/src/kademlia/routing/RoutingZone.cpp)
  (bootstrap-edition `nodes.dat`, 50 XOR-closest contacts).
- eMule Community 0.72a (`VERSION_MJR 0` / `VERSION_MIN 72` / build 28),
  `irwir/eMule` branch `v0.72a` at
  `ac3d52eafd88e9f6d9e0c2204c6dbead18db750b`: the same four files under
  `srchybrid/kademlia/`. Behaviour matches aMule on every point above.

## Related
- [Status](../../10_dev/status.md) · [Dev docs](../../10_dev/) · [Protocol index](../README.md)
