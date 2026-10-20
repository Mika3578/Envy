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

**Cycle and batch.** The periodic caller is `CKademlia::OnTimer`, driven by
`CMainWnd::OnTimer`. That code counts whole seconds and runs when
`tNow > tLast5SecInterval + 5`, i.e. once per six one-second timer ticks:
about every 6 s and, with a steady clock, never closer than 5 s (the previous
call may fall late in its second, the next early in the following one). Each cycle sends at most two
bootstrap requests while the routing table is empty and at most three
afterwards. `Bootstrap()` also enforces a minimum spacing of 5 s (cold start) or
30 s, which does not bind on the periodic path and only holds back the discrete
`ConnectTo(PROTOCOL_KAD)` entry.

The sustained rate is set by the outstanding-request budget, not by the tick:
nine usable slots (one of the ten stays free for other Kad traffic), each held
for the 30-second request timeout. Against peers that never answer that is
**0.25-0.30 requests/second**, measured by simulating the gate chain and
asserted by `kad_bootstrap_cold_start_rate_budget_bound`; a 5 s tick or a batch
of three gave the same rate when measured. eMule and aMule send one request every 2 seconds
while `GetNumContacts() == 0` and every 15 seconds afterwards, with no
per-request timeout, so Envy is slower at cold start than both, not equal.
That is still enough to give every entry of a 50-entry list its first request in
about 160 seconds.

The batch is bounded by the free budget **before** candidates are selected
(`KadBootstrapBatchLimit`), and nothing is selected when the budget is full.
`Select()` advances the rotation cursor past every candidate it scans, so
selecting first and cutting the send loop on the budget skipped untried peers
until the cursor wrapped the cache: a 50-entry cold start then took about 460
seconds to contact everyone instead of about 160. The skipped peers are the
`budget_blocked` and untried candidates the status line makes visible.

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
used up to what it carries and counted as `partial`, not discarded: both reference clients read the announced list without a receive count cap,
adding contacts incrementally; a short read throws after already-added contacts
remain. Envy precomputes the fully framed prefix instead of relying on an
exception, retaining usable contacts without attempting a partial read. Trailing bytes
remain ignored. A body too short for the fixed 21-byte header is rejected as
malformed before any outstanding request is consumed.

This tolerance is not needed for well-behaved senders, which announce exactly
what they write; it only applies to a malformed or capped reply, and it is
never silent. A reply is counted as `valid_responses` only when its announced
list is fully framed and within the local bound of 20; otherwise it is counted
as `partial`. Both are counted only after the sender has been correlated with a
request, so unsolicited datagrams cannot move either counter. A partial reply
still consumes its request exactly as a complete one does, as the references do:
they remove the tracked request before parsing, and keep the contacts already
added when a short list hits end-of-file.

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
`malformed` and `rejected` (unsolicited) responses, requests the datagram layer
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
| Contact-count bound | Reject if count > 100 **[code]** | Read at most 20 framed contacts; the rest is counted as `partial` **[code] [test]** | No receive bound; keeps the framed prefix; sends at most 20 **[code]** | Same **[code]** | Envy stays bounded and no longer discards a usable answer; the 20 is a sender bound in both references, a local allocation cap here |
| Truncated contact list | Partial contact ends the loop, earlier ones kept **[code]** | Framed prefix kept; counted as `partial`, never as `valid_responses`, and only once the sender is correlated; request consumed **[code] [test]** | Request removed before parsing; the read throws at EOF and contacts already added are kept **[code]** | Same **[code]** | Same data outcome as both references, with an honest counter. The tolerance is not needed for well-behaved senders, which announce exactly what they write |
| Routing insertion | `UpdateContact`, unverified candidate **[code]** | Unchanged **[code] [test]** | `Add(..., verified = GetNumContacts() == 0, ...)` — verified while the table is empty **[code]** | Same **[code]** | Deliberate divergence: Envy keeps `verified` meaning `HELLO_RES` evidence; `FindClosestContacts` does not require it |
| Routing seeded from `nodes.dat` | No **[code]** | No (out of scope) **[code]** | Yes, for a normal `nodes.dat` **[code]** | Yes **[code]** | **Open gap, tracked under #86** — bootstrap responses are Envy's only path to a populated table |
| UDP obfuscation | Not implemented (#431) **[code]** | Unchanged **[code]** | Obfuscates its request when the peer's Kad version ≥ 6; answers a plain request in clear **[code]** | Same **[code]** | A plain request still gets a clear reply, so obfuscation is not a cold-start blocker **[code]** |
| Diagnostics | One unconditional line per cycle **[code]** | One aggregate line per minute with `valid_responses`, `partial`, `rejected`, `malformed`, `send_failed` and `budget_blocked`; no endpoints or payloads **[code]** | Per-packet debug logging behind debug levels **[code]** | Same **[code]** | Envy's aggregate form is privacy-safe and lets a live run tell budget starvation from silence |
| Tests | None for bootstrap selection | The real response-handler body (`KademliaBootstrap.inl`) is exercised by `test_kad_bootstrap_response.cpp`; rotation, budget and cadence by `test_kad_bootstrap_rotation.cpp`. 79 with the routing-table suite; mutation checks of the new guards are all caught **[test]** | No automated tests (`SelfTest.cpp` covers neither Kad nor bootstrap) **[code]** | Large Kad unit-test suite under `unittests/tests/`, but none covering bootstrap selection or retry **[code]** | Envy has the stronger coverage of this specific path; live interop still pending (#160) |

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
short headers, partial contact lists and the local contact cap, plus that
unsolicited datagrams of any framing never move a response counter and that a
partial reply is counted as `partial`, not as valid, while consuming its request
like a complete one. Fixtures use
the Windows temp directory with scoped cleanup and bounded child paths.

## Related
- [Status](../../10_dev/status.md) · [Dev docs](../../10_dev/) · [Protocol index](../README.md)
