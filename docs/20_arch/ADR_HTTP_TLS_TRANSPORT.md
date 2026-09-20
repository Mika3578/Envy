# D-021 — HTTP/TLS transport (transfer vs auxiliary)

Status: **Proposed** (docs only; no new TLS client).

- **Date:** 2026-09-20
- **Issues:** overlap [#88](https://github.com/Mika3578/Envy/issues/88) (HTTPS trackers); no dedicated P2P-HTTPS issue (do not open one solely to pair this ADR)
- **Plan:** `docs/20_arch/HTTPS_TLS_RESTORATION_PLAN.md`
- **Audit:** `docs/20_arch/AUDIT_SHAREAZA_IPV6_HTTPS_2026-09.md`
- **Remote inbound TLS:** out of scope (D-017 — reverse proxy / later `http.sys` TLS)

## Context

ENVY has two HTTP stacks (**code**, `develop` 2026-09-20):

| Stack | Classes | TLS |
| --- | --- | --- |
| **Transfer engine** | `CDownloadTransferHTTP`, `CDownloadSource`, `CEnvyURL` | None. `https://` → `PROTOCOL_HTTP` port 80 |
| **Auxiliary WinINet** | `CHttpRequest` | OS SSL when URL is `https://` |

Shareaza added a third path: OpenSSL on `CConnection` (`PROTOCOL_SSL`, `CDownloadTransferHTTPS`). That path had **no certificate or hostname verification**, blocking `SSL_connect`, and **IPv6 HTTPS used plaintext TCP**. Do not restore it.

vcpkg already lists OpenSSL. That is **not** evidence it is the transfer TLS engine: `Connection.cpp` has no `SSL_connect`.

## Decision (split)

Do **not** force one library for both stacks.

### A. Transfer engine (files, G1/G2 HTTP sources, web seeds, Range)

**Chosen: Schannel (Windows SSPI)** as a TLS *filter* on an already-connected TCP socket, then reuse `CDownloadTransferHTTP` (Range, Tiger, gzip, chunked, redirect cap).

Reasons:

- Windows 10 1809+ is the product OS.
- Certificate store and system distrust updates come from Windows.
- Hostname checks and SNI are first-class.
- TLS 1.2 required; TLS 1.3 used when the OS offers it.
- No second HTTP parser.
- AGPL-safe; no OpenSSL license/process issues on the P2P socket.

Do **not** clone `DownloadTransferHTTPS.cpp`. Do **not** call the protocol `PROTOCOL_SSL` unless a wire id is still required internally; prefer “HTTP over TLS” on `PROTOCOL_HTTP` with a TLS transport flag.

IPv6: TLS rides the dual-stack socket layer (D-020). Shareaza’s “IPv6 HTTPS without SSL_connect” is a defect, not a model.

### B. Auxiliary web services (update, GWC, HTTP(S) trackers, metadata)

**Chosen: keep `CHttpRequest` / WinINet.**

Reasons:

- Already fetches `https://` catalogues, VersionChecker, Update Servers, Discovery webcache, HTTP trackers.
- #88 HTTPS **trackers** can enable `https://` in `BTInfo` without a P2P TLS stack.
- Body caps already exist on several of these paths.

**WinHTTP** is the fallback if WinINet cannot meet a future requirement (HTTP/2, stricter redirect policy, better test seams). Do not migrate aux services in the first TLS foundation PR.

**libcurl** is allowed only if a later portable EnvyCore HTTP client needs a non-Win32 backend (D-012/D-015). It is **not** the Windows transfer engine.

**OpenSSL** is rejected for both stacks unless a future non-Windows transfer port has no Schannel/Secure Transport equivalent. Shareaza’s in-process `SSL*` on `CConnection` stays forbidden.

## Comparison (Windows today)

| Criterion | Schannel | WinINet (`CHttpRequest`) | WinHTTP | libcurl | OpenSSL-on-socket |
| --- | --- | --- | --- | --- | --- |
| OS cert store | Yes | Yes | Yes | Optional (Schannel/OpenSSL backends) | DIY |
| Hostname / SNI | Yes | Yes | Yes | Yes if configured | Shareaza: no |
| TLS 1.2 / 1.3 | OS | OS | OS | Backend | DIY versions |
| IPv6 | Via our sockets | OS stack | OS stack | Backend | Shareaza broken |
| Proxy | Manual / WinHTTP APIs | IE/WinINet proxy | WinHTTP proxy | curl proxy | DIY |
| Redirects | App (existing cap 5) | WinINet | WinHTTP | curl | App |
| HTTP Range / streaming / resume | Existing HTTP engine | Awkward for P2P Range/Tiger | Possible | Possible; second engine | Shareaza cloned HTTP |
| EnvyCore later | Windows-only impl | Windows-only | Windows-only | Stronger portable | Extra dep |
| Maintenance | OS | Already in tree | New wrapper | New dep + tests | High (CVE surface) |
| Testability | Local TLS fixture + Schannel | Integration-ish | Similar | Easy with curl | Easy, wrong defaults |

## Security defaults (transfer)

Required before calling the stack “HTTPS support”:

- Verify server certificate against the Windows store.
- Verify hostname (CN/SAN); fail closed on mismatch.
- SNI = hostname from URL (not IP literal unless documented).
- No TLS < 1.2.
- No HTTPS → HTTP redirect (fail closed). HTTP → HTTPS may be allowed with a hop cap.
- Timeouts and cancellation on handshake and body.
- Bound headers / `Content-Length` / chunked (existing HTTP caps).
- Do not disable revocation checks without an explicit setting defaulting to system policy.

## Compatibility

| Surface | Impact |
| --- | --- |
| IPv4 HTTP downloads | Unchanged |
| `https://` downloads | Today: silent port 80. After parse fix: fail closed until TLS exists; after TLS: real HTTPS |
| Aux HTTPS | Unchanged (WinINet) |
| Remote | Unchanged (D-017) |
| Disk / plugins | None |
| Win32 / x64 | Schannel available on both |

## Follow-up

1. Stop silent scheme downgrade (security, can land before Schannel).
2. `net/https-transport-foundation` — Schannel session + local tests.
3. `transfer/https-download-support` — wire into `CDownloadTransferHTTP`.
4. `BTInfo` `https://` trackers via stack B (#88) — independent of Schannel.
