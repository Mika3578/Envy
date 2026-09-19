# Remote API architecture

Living document. Status vocabulary: **implemented** / **partial** / **experimental** / **planned** / **unsupported**.

Canonical audit (2026-09): [`AUDIT_REMOTE_API_2026-09.md`](AUDIT_REMOTE_API_2026-09.md). Decisions: D-017 (HTTP stack), D-018 (first *arr adapter).

## Three interfaces (do not mix)

| Role | Direction | Status |
| --- | --- | --- |
| **A. ENVY native control API** | Clients → Envy (session, transfers, add magnet/torrent, pause/resume/delete) | **planned** |
| **B. Download-client compatibility** | *arr → Envy pretending a **subset** of qBittorrent Web API v2 | **planned** (not “qBittorrent-compatible”) |
| **C. Torznab indexer client** | Envy → Prowlarr/Jackett/other Torznab | **planned** (search only) |

HTML Remote (`/remote/`, `Envy/Remote.cpp`) is a **partial** browser UI on the P2P HTTP port. It is **not** A, B, or C.

`Remote/api-specification.md` is an **obsolete design** (JS expects JSON `/api/*`; C++ never serves it).

## Target layering

```text
HTTP transport → parser → routing → auth → JSON DTO
        → EnvyApiServices (TransferService, SessionService, IndexerService)
                → Envy core (CDownloads / engines)
```

Compatibility adapters sit **above** EnvyApiServices. Torznab sits beside TransferService under IndexerService. The download engine must not depend on Torznab.

New service interfaces follow D-013 (no MFC/Win32 on portable boundaries). Historical `CDownload` stays as-is until extraction PRs.

## Native API

Versioned REST under `/api/v1/`. Machine-readable contract: [`docs/api/openapi.yaml`](../api/openapi.yaml) (`x-envy-status: planned` until a route is served).

Auth: disabled or localhost-only by default; high-entropy API token; no silent `0.0.0.0`; IPv4+IPv6 loopback; CORS off.

Transfer `state` uses `Envy/TransferState.h` (`queued`, `metadata`, `checking`, `downloading`, `stalled`, `paused`, `completed`, `seeding`, `error`, `moving`, `unknown`). Do not publish localized `GetDownloadStatus()` strings.

Identity: opaque `id` plus `hashes[]`. BitTorrent v1 infohash is adapter-facing; native API must not assume SHA-1 forever (`#231`, `#88`).

Events/webhooks: **planned**, not MVP. *arr polls.

## HTTP stack (D-017)

- **Inbound API:** Windows HTTP Server API (`http.sys`) on a dedicated port — **planned**.
- **Do not** extend `CRemote` GET/query RPC for *arr.
- **Outbound (Torznab):** existing `CHttpRequest` + `LimitContentLength`.
- **No** cpp-httplib/Crow/Drogon/Boost.Beast in this track.
- JSON library: deferred until a dedicated dependency PR.

## Existing Remote HTML (partial)

Implemented: login (PBKDF2), CSRF on mutating query keys, rate limit, IP allow policy (LAN/WAN/CIDR), list/pause/resume/cancel downloads, add URI, search via `CMainWnd`.

Gaps / risks:

- GET only; no `.torrent` POST.
- Multiplexed on the P2P upload listener (`CUploads::OnAccept`).
- `Settings.Remote.BindAddress` default `127.0.0.1` is **not bound** (dead setting).
- IPv6 loopback not in the allowlist (`IN_ADDR` only).
- Download ids are pointers.

Keep hardening that UI, but do not advertise it as the automation API.

## PR sequence

See the audit § PR decomposition. PR1 is this documentation plus `TransferState` mapping tests.

## GitHub issues

| Issue | Role |
| --- | --- |
| [#161](https://github.com/Mika3578/Envy/issues/161) | EnvyCore / headless parent |
| [#239](https://github.com/Mika3578/Envy/issues/239) | Native `/api/v1` |
| [#240](https://github.com/Mika3578/Envy/issues/240) | qBittorrent Web API v2 subset for *arr |
| [#241](https://github.com/Mika3578/Envy/issues/241) | Torznab client |
| [#232](https://github.com/Mika3578/Envy/issues/232) | Categories/tags |
| [#231](https://github.com/Mika3578/Envy/issues/231) | `hashes[]` identity |
| [#91](https://github.com/Mika3578/Envy/issues/91) | Test seam |
| [#229](https://github.com/Mika3578/Envy/issues/229) | Fuzz later |

Do not file clones of the rows above. Full bodies live on GitHub; accidental `#238` (`test`) should be closed by a maintainer.
