# HTTPS / TLS restoration plan

Status: plan (not implemented). Complements D-021.

- **Date:** 2026-09-20
- **Audit:** `docs/20_arch/AUDIT_SHAREAZA_IPV6_HTTPS_2026-09.md`
- **ADR:** `docs/20_arch/ADR_HTTP_TLS_TRANSPORT.md`
- **Tests:** `docs/40_quality/testing/NETWORK_IPV6_HTTPS_TEST_STRATEGY.md`

Do not announce HTTPS downloads as supported. Auxiliary `https://` fetches via WinINet already exist.

## Historical Shareaza (reference, `master` `f24b0ce`)

| Piece | Behaviour |
| --- | --- |
| `CShareazaURL::ParseHTTPS` | Port 443, `PROTOCOL_SSL` |
| `CDownloadSource::CreateTransfer` | `CDownloadTransferHTTPS` for SSL |
| `CDownloadTransferHTTPS` | HTTP contract (Range, Tiger, metadata) + `SSLConnectTo` |
| `CConnection` | OpenSSL `SSL*` / `BIO*`; `SSL_connect` after TCP |
| Certificate checks | **Absent** |
| IPv6 + HTTPS | `Initiate` IPv6 uses `ConnectToIPv6` **without** TLS |
| Trackers | Announce URLs still built as `http://` |
| Aux WinINet | Same idea as ENVY `CHttpRequest` |

Do not copy OpenSSL-on-`CConnection`.

## Current ENVY (`develop` 2026-09-20)

### Transfer engine — **no TLS**

`CEnvyURL::ParseHTTP` strips a leading `https://`, resolves with `INTERNET_DEFAULT_HTTP_PORT` (80), sets `PROTOCOL_HTTP`. `CreateTransfer` has no SSL branch. `CDownloadTransferHTTP::Initiate` calls `ConnectTo` in the clear.

Redirect `Location:` is fed back through the same parser (hop cap 5 in `DownloadWithSources.cpp`), so `https://` locations also become HTTP:80.

`PROTOCOL_SSL` is not in ENVY `PROTOCOLID`.

### Auxiliary WinINet — **TLS possible**

`CHttpRequest::SetURL` accepts `http` and `https`. Used by VersionChecker, Update Servers, Discovery GWC POST/GET, HTTP BitTorrent trackers (after `BTInfo` allows the URL). Cert/SNI policy is Windows/WinINet, not ENVY-owned. Not unit-tested here.

### Other paths (not download TLS)

| Path | Role |
| --- | --- |
| `ShellExecute` on some UI `https://` | Opens the system browser |
| HTML Remote | Cleartext on P2P HTTP port (D-017: dedicated API port later) |
| `vcpkg` OpenSSL | Present; unused as P2P TLS client |
| DC `adcs://` | Skipped until #163 (separate from HTTPS files) |

### BitTorrent

- `BTInfo` **rejects** `https://` tracker URLs (ToDo comment) — #88.
- Web seeds that are `https://` hit `CEnvyURL` and become HTTP:80.
- UDP trackers unchanged.

## Feature gaps vs needs

| Need | Status | Stack |
| --- | --- | --- |
| Download `https://` file / G1/G2 HTTP source | Missing (downgrade) | A — transfer |
| BT web seed HTTPS | Missing (downgrade) | A |
| HTTP Range / resume / Tiger over TLS | HTTP exists; TLS missing | A |
| Redirect HTTPS→HTTP | Would succeed today via downgrade — **must fail closed** | A |
| HTTPS trackers | Rejected in `BTInfo` | B — WinINet |
| GWC / update / hublist HTTPS | Partial (WinINet) | B |
| Remote inbound HTTPS | Not this track | D-017 |
| P2P handshake TLS (GGEP TLS) | Commented in Shareaza and ENVY | Reference only |

## Phased work (after this documentation)

0. **Docs / ADR** (this file + D-021). No code.
1. **Fail closed on download `https://`** until a TLS client exists (stops silent cleartext). Behaviour change; small; security. Optional early PR.
2. **Schannel foundation** (`net/https-transport-foundation`): handshake, verify, SNI, timeouts, local tests. No download engine yet.
3. **Transfer integration** (`transfer/https-download-support`): URL keeps scheme; `CDownloadTransferHTTP` reads/writes through TLS; redirects; Range/resume.
4. **HTTPS trackers** (#88): `BTInfo` allow `https://`; still `CHttpRequest`. Independent of step 2–3.
5. Web seed HTTPS after step 3.
6. G1/G2 HTTPS sources after step 3.

Never mix Remote TLS or ADCS into these PRs.

## Compatibility / rollback

- IPv4 HTTP downloads stay default.
- Flag or compile-time is not required for fail-closed parse; TLS itself can be a setting later.
- Rollback: revert the integration PR; fail-closed parse is still safer than silent port 80.

## Open questions

- Exact Schannel hostname API (`Schannel` vs `WinVerifyTrust` vs `SSL_CERT`).
- Whether download TLS should honour WinINet proxy settings.
- How often real G1/G2 sources are `https://` vs `http://` (product priority vs trackers).
