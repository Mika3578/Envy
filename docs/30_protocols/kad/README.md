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
