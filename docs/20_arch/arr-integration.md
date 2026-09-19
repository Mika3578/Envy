# *arr download-client integration

Status: **planned**. Envy is **not** a Radarr/Sonarr download client today.

Do not write “compatible Radarr” or “qBittorrent-compatible API” until interoperability tests pass. Use:

**qBittorrent Web API compatibility subset for *arr integration**

Audit with endpoint tables: [`AUDIT_REMOTE_API_2026-09.md`](AUDIT_REMOTE_API_2026-09.md). Architecture: [`remote-api.md`](remote-api.md). Adapter choice: D-018.

## Flow (MVP)

```text
Prowlarr/Jackett --Torznab--> (optional Envy search)
Radarr --download client API--> Envy transfer (BitTorrent)
Envy core downloads
Radarr polls hash/state/content_path
Radarr imports from the completed path
```

Envy must not know “Radarr movie” vs “Sonarr series”. Category strings (`radarr`, `sonarr`, `lidarr`, `manual`) are ordinary Envy categories (`#232`).

## Why qBittorrent first

Verified against current Radarr `develop` (2026-09-19): Radarr already implements a large, tested qBit v2 client (`QBittorrentProxyV2` + `QBittorrent.cs`) including Bearer tokens, categories with save path, and `content_path` import. Transmission RPC is smaller but weaker on paths and carries session-id CSRF plus a JSON-RPC 2.0 transition risk.

Sonarr/Lidarr/Readarr are expected to follow the same Servarr client (hypothesis). A correct qBit **subset** is the cheapest *arr on-ramp. A first-party Envy plugin in Radarr remains possible later; it is not MVP.

## Critical path rules

- Infohash: accept mixed case; store canonical hex; Radarr `DownloadId` is upper-case.
- `content_path` must not equal `save_path` for finished torrents (Radarr API ≥ 2.6.1).
- Windows paths: qBit-style `/` separators in file names; UNC `//` vs `\\` as Radarr already special-cases.
- Completion mapping: only `TransferState` completed/seeding (and paused-complete) may become qBit `*UP` / `uploading`. `unknown` → `error`.
- Single-file vs multi-file vs subfolder vs Unicode vs incomplete vs move: must be fixture-tested before any support claim.

## Manual live check (later)

Not run in this environment. When available: Radarr download-client = qBittorrent, host `127.0.0.1`, Envy subset port, category `radarr`, add a magnet, wait for import, remove with/without data.
