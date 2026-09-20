# External reachability probe — design (not implementation)

Status: **design only**. Do not implement, deploy a PHP service, or open a code PR until this design is reviewed for abuse.

- **Date:** 2026-09-20
- **Inspiration:** Shareaza `ConnectionTest/` (historical PHP). **Do not import it.**
- **Depends on:** dual-stack sockets (D-020) for an IPv6 probe; not on HTTPS restoration.
- **Priority:** P3 after IPv6 listen/connect. Must not outrank P0 ED2K/Kad.

## Goal

```text
ENVY  →  authenticated probe request
      →  maintainer-controlled tester
      →  TCP connect to claimed listener
      →  UDP echo/challenge to claimed datagram port
      →  optional IPv6 counterparts
      →  structured result (reachable / firewalled / indeterminate)
```

This diagnoses NAT/firewall — it is not a substitute for MiniUPnP/PCP (D-009) and not a STUN clone unless we later adopt a standard.

## Why not Shareaza PHP

- Unauthenticated UDP invites amplification and spoofing.
- No modern token/challenge, retention, or abuse budget.
- PHP + ad-hoc sockets is an extra ops stack ENVY does not want.
- Shareaza’s client also used brittle “open URL, parse HTML” flows.

Any future server should be a small dedicated service (language TBD) with a documented protocol, not in-tree PHP.

## Probe protocol (draft)

1. Client obtains a **short-lived token** over HTTPS from the tester (aux stack B / WinINet — not P2P TLS). Rate-limited per IP and per installation id.
2. Tester returns `{token, tcp_nonce, udp_nonce, expiry, tester_endpoints[]}`.
3. Client already listening: tester **connects to client:port** (TCP) and sends nonce; client answers on that connection.
4. UDP: tester sends nonce to client:port; client echoes `H(token||nonce||port)` so a spoofed source cannot complete the test by flooding.
5. Result: `tcp_v4`, `udp_v4`, `tcp_v6`, `udp_v6` ∈ {ok, refused, timeout, mismatch, unsupported}.
6. Client never publishes raw probe logs containing foreign IPs beyond what the tester already saw.

No “open relay”, no arbitrary connect-to-IP API (SSRF). The tester only connects **back to the source IP** of the token request (or a signed alternative that still belongs to that client). Connecting to a user-supplied third-party address is **forbidden**.

## Abuse prevention

| Risk | Mitigation |
| --- | --- |
| TCP connect scanner | Connect-back to requester IP only; port must be the P2P listen port declared at token issue |
| UDP amplification | Small requests; response ≤ request; require prior HTTPS token; drop unsigned datagrams |
| Spoofed UDP | Echo must include token-bound MAC; source IP must match token |
| Token stuffing | Per-IP and per-device budget (e.g. 3 tests / 10 min) |
| IPv6 scanning | Same connect-back rule on AAAA |
| SSRF / NAT hairpin tricks | No user-supplied target host; reject RFC1918/ULA/link-local/loopback targets on the **tester** side |
| Log retention | Store outcome + truncated IP + time; purge ≤ 14 days unless abuse investigation |
| Auth | Optional account later; v1: token + rate limit is enough |
| Privacy | Do not log payloads; do not share results with other peers |

## Diagnostics (client UX, later)

Show separately: bind success, UPnP/PCP mapped, **external TCP**, **external UDP**, IPv4 vs IPv6. Indeterminate ≠ firewalled.

## What this pass does **not** do

- No server code, no client `ConnectionTest`, no URL in `DefaultServices.dat`.
- No required CI using a public tester.
- No reuse of Shareaza’s `Shareaza.com` endpoints.

## Exit criteria before any implementation PR

- Security review of connect-back + UDP MAC.
- Tester operated by the project (or explicitly deferred).
- Client feature flag default OFF.
- Tests: fake tester on loopback (see test strategy); never production HTTPS in required CI.
