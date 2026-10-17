# Kad Documentation

Status: active
Last updated: 2026-10-12
Scope: Envy Kad2 notes. Opcode matching is not live interop. Kad6/Ember overlays are not Kad2.

**Specification first:** [Kademlia paper](https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf). **Interop second:** eMule Community and aMule Kad2 sources. Ember and eMule eSE extensions are experimental and must stay distinct from Kad2. See [REFERENCE_IMPLEMENTATIONS.md](../REFERENCE_IMPLEMENTATIONS.md).

## Start here
- [Kad2 compatibility report](kad2-compatibility-report.md) (wire/opcode match only)

## Bootstrap candidate retry scheduling (issue #430)

`CKademlia::Bootstrap()` now snapshots the Kad host cache and uses
`KadBootstrapRotation` for bounded, progressively rotating selection.
The timer permits at most three bootstrap requests per 30-second cycle,
using the existing maximum-outstanding-request budget. Unanswered
requests enter per-UDP-endpoint backoff starting at 60 seconds, doubling
up to a 10-minute cap. A complete, correlated `BOOTSTRAP_RES` clears
the endpoint penalty; truncated or over-counted responses cannot consume a
pending request. The response contact count is capped at 20, matching the
eMule/aMule Kad2 bootstrap response bound; trailing bytes remain ignored for
compatibility with the existing parser.
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

## Related
- [Status](../../10_dev/status.md) · [Dev docs](../../10_dev/) · [Protocol index](../README.md)
