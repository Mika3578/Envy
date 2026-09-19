# Audit: Remote API / *arr / Torznab (2026-09)

Status: audit (evidence-based). Not a compatibility claim.

- **Date:** 2026-09-19
- **Fork:** `Mika3578/Envy`
- **Base (original audit):** `origin/develop` `a47d42e7f21eefa269e3e59de41c32fa65d1e7be` (`feat(uploads): transfer settings foundation + Fair-Use 10% limit (#227)`)
- **Base (reverified):** `origin/develop` `93f623ca0251aa9dddaa751633361dbe7e689088` after `#248` (NMDC Network lock). Remote/API inventory unchanged (**code**).
- **This work branch:** `cursor/remote-api-architecture-2f11`

Evidence classes used below:

| Tag | Meaning |
| --- | --- |
| **code** | Verified in this fork’s source |
| **external** | Verified in a current upstream file or spec |
| **hypothesis** | Reasonable but not proven |
| **recommendation** | Proposed decision |
| **action** | Done in this change set |

Do not read “a class/route exists” as “supported”.

---

## Current state

### Fork / process (**code** + GitHub API)

| Item | Verified value |
| --- | --- |
| Default branch | `develop` |
| HEAD used for this audit | original `a47d42e`; reverified on `93f623c` |
| Open development PRs | 2 (`#242` this audit, `#243` Crashpad draft) — under the max-3 cap |
| Live rulesets | `Protect develop` (`16457466`), `Protect main` (`16457407`) |
| CI | Two-speed Actions (`build.yml`, `pr-gate.yml`, CodeQL, Format, Documentation, …) |
| Tests | `tests/EnvyTests` smoke suite (MSVC); Remote JS tests under `Remote/tests` |

Relevant **open issues already covering part of this mission** (do not duplicate):

| Issue | Overlap |
| --- | --- |
| [#161](https://github.com/Mika3578/Envy/issues/161) | EnvyCore boundary + headless/remote-control API |
| [#91](https://github.com/Mika3578/Envy/issues/91) | UI-free parser/state-machine test seam |
| [#232](https://github.com/Mika3578/Envy/issues/232) | Core-owned tags/categories + later rules |
| [#231](https://github.com/Mika3578/Envy/issues/231) | Multi-hash content identity (`hashes[]`) |
| [#229](https://github.com/Mika3578/Envy/issues/229) | Fuzz/sanitizer coverage for untrusted parsers |
| [#82](https://github.com/Mika3578/Envy/issues/82) | Bound size-trusting parsers |
| [#177](https://github.com/Mika3578/Envy/issues/177)–[#180](https://github.com/Mika3578/Envy/issues/180) | Portability / headless sequencing |

No existing issue named Radarr, Prowlarr, Jackett, Torznab, qBittorrent Web API, or Transmission RPC. (**GitHub search**, 2026-09-19.)

### Inventory (implementation class)

| Surface | Class | Evidence |
| --- | --- | --- |
| HTML Remote UI (`/remote/…`) | **partial / implemented** as a browser control surface | `Envy/Remote.cpp` GET-only HTML templates |
| JSON `/api/downloads` etc. | **absent** in C++ | `Remote/api-specification.md` is design-only; `CRemote::PageSwitch` has no `/api` routes (**code**) |
| `Remote/api-specification.md` + `envy-modern.js` | **obsolete design / unused backend** | JS calls `/api/*`; server never implements them (**code**) |
| `docs/API.md` | **partial** pointer | Already warns the spec is unverified |
| Headless daemon | **absent** | `docs/KNOWN_LIMITATIONS.md`, `#161` |
| EnvyCore service layer | **absent** | MFC globals `Downloads`, `DownloadGroups`, `theApp` |
| Native REST `/api/v1` | **absent** | — |
| qBittorrent / Transmission adapter | **absent** | Vendor IDs `qB`/`TR` in `BTClient.cpp` are peer-client names only |
| Torznab / Newznab / Prowlarr / Jackett | **absent** | No indexer client |
| RSS automation | **absent** | Historical roadmap mention only |
| OpenAPI | **absent** (planned file added with this PR) | — |
| Dedicated HTTP API port | **absent** | Remote is multiplexed on the P2P HTTP upload listener |
| JSON library | **absent** | No nlohmann/rapidjson/cJSON (**code**, `vcpkg.json`) |
| Outbound HTTP | **partial** | `CHttpRequest` / WinINet + `LimitContentLength` |
| XML parse | **partial** | `CXMLElement::FromString` (no depth/size caps); bounded DC walker in `HostBrowser.cpp` |
| Magnet / `.torrent` add | **implemented** in core | `CEnvyURL::Parse` + `CDownloads::Add` |
| Pause/resume/remove | **implemented** in core | `CDownload::Pause/Resume/Remove` |
| Download groups (folder + filters) | **partial** category analogue | `CDownloadGroup` — not *arr categories |
| Tags | **absent** | `#232` |
| Transfer state enum | **partial (this PR)** | `Envy/TransferState.h` — mapping only, not wired to `CDownload` yet |
| Auth (Remote HTML) | **partial** | PBKDF2 (#79), CSRF (#77), rate limit, IP policy |
| `Settings.Remote.BindAddress` | **dead setting** | Default `127.0.0.1` is stored, never applied to a socket (**code**) |

### Where things live today (**code**)

```text
UI (MFC Wnd/Dlg/Ctrl)     Remote HTML (CRemote)
        \                       /
         \                     /  includes WndMain, CtrlDownloads
          v                   v
     CDownloads / CDownload / CDownloadGroup     CUploads
                      |
              protocol engines (BT, ED2K, G1/G2, DC, HTTP)
```

| Concern | Primary types | UI-coupled? |
| --- | --- | --- |
| Session / app | `CEnvyApp`, `Settings` | Yes (startup creates MFC shell) |
| BitTorrent | `CBTInfo`, `CDownloadWithTorrent` | Core usable without windows |
| Transfers | `CDownloads`, `CDownload`, `CTransfers` | Core; Remote still calls `CDownloadsCtrl::IsFiltered` |
| Magnet/URL | `CEnvyURL` | Core |
| Groups | `CDownloadGroups` | Core + Remote tabs |
| Search | `CQuerySearch` | Remote `PageNewSearch` **posts `WM_OPENSEARCH` to `CMainWnd`** |
| HTTP inbound | `CUploads::OnAccept` → `CRemote` | Same listen port as P2P HTTP |
| HTTP outbound | `CHttpRequest` | Optional `HWND` notify |
| Config | `CSettings` | MFC `CString` |

**Verified coupling that blocks treating Remote as an API:**

- `CRemote::OnHeadersComplete` accepts **GET only** (`Remote.cpp`). No POST body, no multipart `.torrent` upload.
- Handshake cap **4096 bytes**.
- Download ids in HTML are **pointer `%p`** — not stable across restarts. Core already has `CDownload::m_nSerID` and hash finders (`FindByBTH`, `FindBySHA1`, …).
- New search requires `CMainWnd`.
- Upload queue expand uses `CUploadsCtrl` iterators.

Core operations that **can** be called without windows (still MFC types): `Downloads.Add(CEnvyURL)`, `Pause`, `Resume`, `Remove`, progress/size/status predicates, group folder `GetCompletedPath`.

---

## Missing pieces

1. Application services that return portable DTOs (no `CWnd`, no `CString` on the public EnvyCore boundary — D-013).
2. Dedicated API listener (localhost by default), not the P2P HTTP port.
3. HTTP/1.1 with POST, JSON, auth token, limits — not GET query actions.
4. Stable transfer id + `hashes[]` (see `#231`).
5. Native REST contract actually served.
6. qBittorrent Web API **subset** (not a clone) if *arr download-client is required before a native Radarr plugin exists.
7. Torznab **client** (search only).
8. Categories as first-class policy objects (`#232`); groups are not enough.
9. Path sandbox for save/content paths.
10. Tests that do not start MFC: HTTP parser, JSON DTO, Torznab XML, Radarr call sequence.
11. OpenAPI generated from **implemented** routes only (this PR ships a `planned` stub).

---

## Arr integration contract

Sources (**external**, 2026-09-19):

- [Radarr `QBittorrent.cs` develop](https://raw.githubusercontent.com/Radarr/Radarr/develop/src/NzbDrone.Core/Download/Clients/QBittorrent/QBittorrent.cs)
- [Radarr `QBittorrentProxyV2.cs` develop](https://raw.githubusercontent.com/Radarr/Radarr/develop/src/NzbDrone.Core/Download/Clients/QBittorrent/QBittorrentProxyV2.cs)
- [Radarr `QBittorrentTorrent.cs` develop](https://raw.githubusercontent.com/Radarr/Radarr/develop/src/NzbDrone.Core/Download/Clients/QBittorrent/QBittorrentTorrent.cs)
- [Radarr `TransmissionProxy.cs` develop](https://raw.githubusercontent.com/Radarr/Radarr/develop/src/NzbDrone.Core/Download/Clients/Transmission/TransmissionProxy.cs)
- [Radarr `TransmissionBase.cs` develop](https://raw.githubusercontent.com/Radarr/Radarr/develop/src/NzbDrone.Core/Download/Clients/Transmission/TransmissionBase.cs)

Official API docs (**external**):

- qBittorrent WebUI API v2: <https://github.com/qbittorrent/qBittorrent/wiki/WebUI-API-(qBittorrent-4.1)>
- Transmission RPC: <https://github.com/transmission/transmission/blob/main/docs/rpc-spec.md>

Sonarr/Lidarr/Readarr reuse the same Servarr download-client pattern (**hypothesis**, high confidence from shared NzbDrone lineage). First adapter therefore helps those apps **if** the subset matches.

### Radarr → qBittorrent (what Radarr actually calls)

| Radarr function | Endpoint | Expected data | Envy can supply today? | Work |
| --- | --- | --- | --- | --- |
| Probe API v2 | `GET /api/v2/app/webapiVersion` | Version string; 404 = not v2; 403 = auth required | No HTTP API | API host + version string |
| Client version | `GET /api/v2/app/version` | Trim leading `v` | Product version exists | Map `version.json` |
| Auth cookie | `POST /api/v2/auth/login` form `username`/`password` | Body `Ok.` + cookies | HTML form login only | Cookie SID **or** Bearer (Radarr supports both) |
| Auth Bearer | `Authorization: Bearer` | 401/403 on failure | No | Native API key can back this |
| Test + DHT/queue/ratio | `GET /api/v2/app/preferences` | `save_path`, DHT, queueing, max ratio/seed time/action | Settings exist, different names | DTO map; do not invent qBit keys |
| List queue | `GET /api/v2/torrents/info?category=` | `hash`, `name`, `size`, `progress`, `eta`, `state`, `category`/`label`, `save_path`, `content_path`, `ratio`, limits, `last_activity` | Partial on `CDownload` / `CBTInfo` | Must implement `content_path` correctly |
| Torrent present | `GET /api/v2/torrents/properties?hash=` | 200 vs error | `FindByBTH` | Hex hash case: Radarr uses **lower** on calls, **upper** as `DownloadId` |
| Files | `GET /api/v2/torrents/files?hash=` | `{ name }` | `CBTInfo::CBTFile` | Path separators: Radarr assumes `/` even on Windows |
| Add magnet/URL | `POST /api/v2/torrents/add` `urls` | `Ok.` / empty / `Fails.` | `Downloads.Add(CEnvyURL)` | Form + category + paused/stopped + seed limits |
| Add `.torrent` | same, multipart `torrents` | file bytes | Need torrent load path | Size limit; no POST on current Remote |
| Remove | `POST /api/v2/torrents/delete` `hashes`, `deleteFiles` | — | `Remove()` deletes `.pd`; data vs keep-file is not the qBit contract | Explicit delete-data flag |
| Set category | `POST /api/v2/torrents/setCategory` | — | Groups, not categories | `#232` MVP |
| Create category | `POST /api/v2/torrents/createCategory` | Radarr Test creates missing category | No | `#232` |
| List categories | `GET /api/v2/torrents/categories` | `{ name: { savePath } }` | Group folder | Map |
| Share limits | `POST /api/v2/torrents/setShareLimits` | ratio / seeding time | Partial BT seeding settings | Per-torrent limits |
| Queue top | `POST /api/v2/torrents/topPrio` | 409 if queueing off | `CDownloads::Move` | Optional |
| Force start | `POST /api/v2/torrents/setForceStart` | — | `Boost()` is not qBit force start | Implement or reject ForceStart in UI docs |

Radarr completion / import (**external**, `QBittorrent.GetItems` / `GetImportItem`):

- `DownloadId` = torrent hash **upper-case**.
- Completed qBit states: `pausedUP`, `stoppedUP`, `uploading`, `stalledUP`, `queuedUP`, `forcedUP`.
- API ≥ 2.6.1: `content_path` must **differ** from `save_path` or Radarr marks Warning (path error) and will not import.
- Older APIs: first file name’s top directory + `save_path`.
- Unknown qBit `state` → Radarr **Downloading** (not Completed). Envy adapters must still never emit `*UP` for unknown Envy states (**recommendation**, encoded in `TransferState.h`).

Minimum qBit version Radarr accepts: API 1.5 / qBit 3.2.4; labels need 1.6+; categories API 2.0+. Declare a **2.8.1** webapiVersion only if share-limits-on-add and `content_path` are real. Do **not** declare 2.11 unless `stopped` vs `paused` is implemented.

### Radarr → Transmission (summary)

| Function | RPC method | Notes |
| --- | --- | --- |
| Auth | POST `/rpc` + `X-Transmission-Session-Id` CSRF (409 Conflict) | Extra session dance |
| Version | `session-get` | `rpc-version`, `version` |
| Add | `torrent-add` `filename` or base64 `metainfo` | `download-dir`, `labels`, `paused` |
| List | `torrent-get` fields listed in proxy | `hashString`, `downloadDir`, `leftUntilDone`, `status`, `isFinished`, … |
| Remove | `torrent-remove` `delete-local-data` | |
| Seed limits | `torrent-set` | |
| Queue | `queue-move-top` | |
| Labels | `torrent-set` `labels` | Not per-label save path |

Output path = `downloadDir` + torrent `name` (colon → `_`). Weaker than qBit `content_path` for multi-file layouts.

Transmission 4.x JSON-RPC 2.0 transition (**external** docs) is a **future divergence risk** if Envy emulates Transmission.

---

## Compatibility comparison

| Solution | Advantages | Disadvantages | Surface | Maintenance | Risk |
| --- | --- | --- | --- | --- | --- |
| ENVY native only | Clean multi-protocol contract; OpenAPI; no fake identity | Radarr has **no** Envy download client; users cannot pick Envy in *arr until someone writes a plugin | Medium (our API) | Low | Low technically; **zero *arr UX** until a plugin exists |
| qBittorrent adapter | Radarr/Sonarr/Lidarr already speak it; categories + `content_path`; Bearer **or** cookie; REST | Must match quirks (paused vs stopped, eta 8640000, `Fails.`, 409 on prio); never claim full qBit | Bounded subset (~15 endpoints) | Medium (track Radarr + qBit) | Medium (behavior drift) |
| Transmission adapter | Smaller method set | CSRF session id; labels ≠ category save path; weaker file path; JSON-RPC 2.0 fork | Small methods, more session semantics | Medium-high | Medium-high |

**Decision (D-018, recommendation → recorded):** first compatibility adapter is **qBittorrent Web API v2 subset for *arr**, after a native Envy API exists. Label it exactly:

`qBittorrent Web API compatibility subset for *arr integration`

Never “qBittorrent-compatible” or “Radarr-supported” until fixtures (and preferably a live Radarr) pass.

Native API remains the source of truth. The adapter is a translation layer on `EnvyApiServices`, not a second core.

---

## Torznab contract

ENVY is a **Torznab consumer**, not a Torznab server, in the MVP. Search stays independent of the download-client API.

Sources (**external**):

- Torznab 1.3 draft: <https://torznab.github.io/spec-1.3-draft/torznab/Specification-v1.3.html>
- Prowlarr Torznab definition: `Prowlarr/src/NzbDrone.Core/Indexers/Definitions/Torznab/Torznab.cs`
- Jackett exposes `/api/v2.0/indexers/<id>/results/torznab/` with `t=caps` / `t=search` (Jackett README)

MVP:

| Function | Required | Notes |
| --- | --- | --- |
| `t=caps` | Yes | Categories, searching modes, limits |
| `t=search` | Yes | `q`, `cat`, `offset`, `limit` |
| `t=tvsearch` / `t=movie` | Later | Drive from caps `supportedParams` |
| Attributes | seeders, peers, size, magneturl, infohash | Fail soft on unknown attrs |
| Errors | HTTP 401/403/429/5xx + XML `<error>` | No auto-retry storms |

Security (**recommendation**): do not use `CXMLElement::FromString` as-is (`XML.cpp` skips `<!DOCTYPE …>` but has **no** depth/size/entity caps). Reuse the **bounded walker** pattern from `CHostBrowser::LoadDC` (`HostBrowser.cpp`). No XXE, no DTD fetch, no local file URLs. HTTP body cap + redirect cap via `CHttpRequest::LimitContentLength`. Never concatenate base URL + query; use a real URL builder.

Do not auto-download magnet/torrent URLs from indexer XML without the same path/scheme validation as manual add.

---

## Proposed architecture

```text
External software
        |
        +----------------------------+
        |                            |
   ENVY Native API             Compatibility APIs
   /api/v1/...                 /api/v2/...  (qBit subset)
        |                       (Transmission later)
        |                            |
        +-------------+--------------+
                      |
               EnvyApiServices
                      |
        +-------------+-------------+
        |                           |
 TransferService              SessionService
        |                     (config, limits)
        |
   CDownloads / protocol engines
```

Torznab (separate):

```text
Prowlarr / Jackett --Torznab--> TorznabIndexer : IIndexer
                                      |
                               IndexerService
                                      |
                         Unified Search (core)
                                      |
                         UI and/or GET /api/v1/search
```

Rules:

- Download engine must not depend on Torznab.
- Torznab must not depend on MFC windows.
- Public HTTP must not call `CMainWnd` / `CDownloadsCtrl`.
- Existing HTML Remote may later consume native API; do not grow `/remote` query-actions as the *arr surface.

Layers: HTTP transport → parser → routing → auth → serialization → DTO → application services → core → adapters / Torznab client.

---

## Security model

P0 before any non-localhost bind.

| Topic | Current Remote (**code**) | Native API (**recommendation**) |
| --- | --- | --- |
| Enable default | `Remote.Enable` false | API disabled or localhost-only |
| Bind | **Not applied** (`BindAddress` unused). Remote rides P2P HTTP accept | Dedicated port; default `127.0.0.1` and `[::1]`; never silent `0.0.0.0` |
| IPv6 | `IN_ADDR` only; `::1` not in allowlist | Dual-stack loopback first |
| Auth | Cookie session + PBKDF2 password | API token (high entropy) mandatory off-localhost; optional user/pass **only** for qBit adapter |
| CSRF | Required for mutating GET keys | Token/Bearer APIs: CSRF N/A; cookie browser UI: keep CSRF |
| CORS | N/A (HTML) | Disabled by default |
| Limits | 10 req / 60 s; 4096 handshake | Header/body/JSON/torrent size, conn count, timeouts |
| Paths | Not an API | Allowlist roots; reject `..`, mixed slash tricks, `\\?\` smuggling |
| Logs | Avoid dumping passwords | Never log tokens |
| TLS | Not implemented | Reverse proxy first; http.sys TLS later if cheap |

qBit adapter auth: implement **only** what Radarr uses (login cookie and/or Bearer). Do not weaken native token policy to match qBit defaults.

---

## Dependency decision (D-017)

`vcpkg.json` today: zlib, bzip2, sqlite3, miniupnpc, openssl, optional gtest. **No** HTTP server library, **no** JSON library.

| Option | Role | License / size | Verdict |
| --- | --- | --- | --- |
| HTTP Server API (`http.sys`) | Inbound API | OS, Win10 1809+ | **Preferred server** for Windows API host: real HTTP, TLS optional, no new dep |
| Existing `CRemote` homemade parser | Inbound | In-tree | **Reject** for JSON API (GET-only, 4 KiB, query-as-RPC, P2P port) |
| cpp-httplib / Crow / Drogon / Boost.Beast | Inbound | Extra deps | **Reject** unless a later ADR revisits |
| `CHttpRequest` (WinINet) | Outbound Torznab | In-tree | **Reuse** with `LimitContentLength` |
| OpenSSL (already in vcpkg) | TLS | Existing | Keep for future; do not roll a custom HTTPS server in MVP |
| New JSON library | DTO | Would need D-discussion | **Defer**. First routes can use a tiny bounded writer; add a library only in a dedicated PR |
| `CXMLElement` | Torznab XML | In-tree | **Unsafe as-is** for untrusted indexer XML |
| Bounded walker (HostBrowser/DC) | XML | In-tree | **Reuse pattern** for Torznab |

---

## Native API sketch (not frozen)

Compare qBit REST, Transmission RPC, Radarr API, aria2 JSON-RPC: Envy is **multi-protocol**, so the native contract is transfer-centric, not torrent-centric.

Planned (OpenAPI `docs/api/openapi.yaml`, all `x-envy-status: planned` until served):

- `GET /api/v1/system/status`
- `GET /api/v1/system/version`
- `GET /api/v1/transfers`
- `GET /api/v1/transfers/{id}`
- `POST /api/v1/transfers/{id}/pause|resume`
- `DELETE /api/v1/transfers/{id}` (`deleteData`)
- `GET /api/v1/transfers/{id}/files|trackers`
- `POST /api/v1/downloads/magnet`
- `POST /api/v1/downloads/torrent`
- `GET/POST /api/v1/categories` (depends `#232`)
- `GET /api/v1/session`, `/statistics`
- `GET /api/v1/indexers`, `/search` (Torznab; later)

Common transfer DTO (multi-protocol):

`id`, `protocol`, `name`, `state`, `progress`, `size`, `downloaded`, `uploaded`, `download_rate`, `upload_rate`, `eta`, `save_path`, `category`, `tags`, `error`, `created_at`, `completed_at`, `hashes[]`

`hashes[]` typed (algorithm + digest). Merge contents only with cryptographic proof (`#231`). BT adapter may expose v1 infohash because *arr requires it; native id stays opaque (`m_nSerID` or a new ULID).

Events (`transfer.completed`, …): **planned, not MVP**. Radarr polls. No webhooks for fashion.

ENVY → Radarr API: **out of MVP**.

---

## PR decomposition

| PR | Content | Depends |
| --- | --- | --- |
| **1 (this)** | Audit + ADR D-017/D-018 + `TransferState` mapping + planned OpenAPI | — |
| **2** | `TransferService` read model (list/detail/files/paths) without HTTP; wrap `CDownloads` behind portable DTOs | 1, `#91`/`#161` |
| **3** | API host skeleton: http.sys or dedicated listener, localhost, `/status` `/version`, token auth, limits, tests | 2 |
| **4** | Transfer read routes | 3 |
| **5** | Magnet/torrent add, pause/resume, delete (+ deleteData) | 4 |
| **6** | Categories MVP (`#232` slice) | 5 |
| **7** | qBit subset adapter + in-process Radarr call-sequence tests | 5–6 |
| **8** | Documented live Radarr smoke (manual); fix path/state bugs | 7 |
| **9** | Torznab caps parser + fixtures | independent of 7; needs outbound HTTP |
| **10** | Torznab search + IndexerService | 9 |
| **11** | Hardening: fuzz (`#229`), OpenAPI implemented-only, extra limits | 3+ |

Do not combine 3–10. Do not refactor the BT engine “to make API easier”.

---

## Tests required (later PRs)

Native API: status, good/bad auth, magnet valid/malformed, torrent valid/truncated/too large, unknown id, pause/resume, delete ± data, invalid JSON, bad Content-Length, oversize, unknown method/route/content-type.

Radarr sequence: connect, auth, version, add, get, files/properties, progress, completion (`content_path`), remove.

Torznab fixtures: caps, empty search, magnet, torrent URL, malformed/truncated/huge XML, unknown attrs, 401/403/429/500, timeout, redirect, bad URL.

Fuzz: HTTP (if we parse), JSON DTO, Torznab XML, URL, magnet, torrent upload, state mapping (started in PR1).

---

## Issue plan (create only if missing)

Create **three** new issues (merged from the 15-item brainstorm). Comment on `#161`/`#232`/`#231`/`#229` rather than cloning them.

## GitHub issues

Created 2026-09-19 (**action**):

| Issue | Title |
| --- | --- |
| [#239](https://github.com/Mika3578/Envy/issues/239) | Native ENVY Remote API `/api/v1` |
| [#240](https://github.com/Mika3578/Envy/issues/240) | qBittorrent Web API v2 subset for *arr |
| [#241](https://github.com/Mika3578/Envy/issues/241) | Torznab indexer client (caps + search) |

Do not duplicate #161 (EnvyCore/headless), #232 (tags/categories), #231 (hashes), #91 (test seam), #229 (fuzz).

Accidental probe issue [#238](https://github.com/Mika3578/Envy/issues/238) (`test`) could not be closed with this token (create-only). Maintainer should close it as not planned.

---

## First PR scope (action)

- Documentation listed above.
- `Envy/TransferState.h` + EnvyTests: classify Envy predicates; map to qBit/Transmission; **unknown never looks complete**.
- **Not** in this PR: HTTP server, adapters, Torznab, MFC extraction.

---

## Blockers

- Full `EnvyTests` / MSBuild not runnable on this Linux Cloud Agent (Windows/MSVC). Linux `g++ -std=c++20` ran `test_transfer_state_smoke.cpp`: **21 passed / 0 failed** (reverified after `#248` rebase).
- Amazon Q review claimed paused-vs-completed priority was unverifiable. **Rejected:** `CDownload::GetDownloadStatus()` tests `IsPaused()` at `Download.cpp:382` before `IsCompleted()` at `Download.cpp:389`. `test_transfer_state_paused_wins` encodes that order.
- Live Radarr/Prowlarr/Jackett not in this environment.
- Accidental issue #238 cannot be closed with this integration token (create-only). Maintainer should close it as not planned.
- Protect develop still requires a non-author GitHub **APPROVED** review. Bot comments are not that review.
