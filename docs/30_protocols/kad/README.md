# Kad Documentation

Status: active
Last updated: 2026-10-11
Scope: Envy Kad2 notes. Opcode matching is not live interop. Kad6/Ember overlays are not Kad2.

**Specification first:** [Kademlia paper](https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf). **Interop second:** eMule Community and aMule Kad2 sources. Ember and eMule eSE extensions are experimental and must stay distinct from Kad2. See [REFERENCE_IMPLEMENTATIONS.md](../REFERENCE_IMPLEMENTATIONS.md).

## Start here
- [Kad2 compatibility report](kad2-compatibility-report.md) (wire/opcode match only)

## Bootstrap retry policy (issue #430)

The Kad2 UDP bootstrap path now rotates through cached candidates instead of
revisiting the same leading entries on each retry. The scheduler takes at most
three candidates per cycle, retains bounded per-endpoint in-flight state,
and applies a bounded 60-second to 10-minute backoff after an unanswered
request times out. Valid correlated bootstrap responses clear the retry
penalty; truncated responses do not consume the tracked request.

The once-per-minute Kad2 status summary aggregates cache, deferred/invalid
candidates, outbound bootstrap attempts, expired requests, valid and malformed
responses, rejected contacts, and searches with no routing contacts. These
counts distinguish scheduler exhaustion from lack of validated responses but
**cannot** alone prove remote UDP reachability or explain encrypted packets.

This is a retry/reliability improvement, **not** a claim that Kad2 bootstrap
or search fully interoperates with eMule/aMule. Live peer interoperability,
routing/contact admission, and UDP obfuscation are tracked separately
(#160, #86, #431).

## Related
- [Status](../../10_dev/status.md) · [Dev docs](../../10_dev/) · [Protocol index](../README.md)

## Bootstrap candidate retry scheduling (issue #430)

`CKademlia::Bootstrap()` now snapshots the Kad host cache and uses
`KadBootstrapRotation` for bounded, progressively rotating selection.
The timer permits at most three bootstrap requests per 30-second cycle,
using the existing maximum-outstanding-request budget. Unanswered
requests enter per-UDP-endpoint backoff starting at 60 seconds, doubling
up to a 10-minute cap. A complete, correlated `BOOTSTRAP_RES` clears
the endpoint penalty; truncated responses cannot consume a pending request.
The initial simultaneous FIND_NODE burst to unconfirmed bootstrap
contacts is deferred until normal routing-table maintenance.

The status log emits one aggregate Kad line per minute: cache candidates,
deferred/invalid candidates, sent/expired bootstrap requests, received
well-framed responses, malformed/rejected responses or contacts, source
searches without contacts, and routing-table count. No endpoints,
contents, IDs or payloads are included in that status line.

**Limitations:** UDP availability, packet dispatch and Kad2 obfuscation
are not fixed by this policy. Unclassified UDP traffic is not evidence
of Kad traffic (#431). Kad2 remains **partial / unverified** until
eMule/aMule exchange tests in #160 show sustained routing and searches.
A full Kad completion claim remains blocked by #86.

The bounded queue behavior follows the retained-contact progression
in [aMule's Kademlia implementation](https://github.com/amule-project/amule/blob/master/src/kademlia/kademlia/Kademlia.cpp)
and the reply shape in
[aMule's UDP listener](https://github.com/amule-project/amule/blob/master/src/kademlia/net/KademliaUDPListener.cpp);
the timeouts are local policy rather than claimed Kad2 protocol constants.
