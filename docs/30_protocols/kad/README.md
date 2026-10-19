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
