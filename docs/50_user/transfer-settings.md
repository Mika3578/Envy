# Transfer settings (Uploads / Downloads)

Status: **partial** (foundation PR — terminology, validation, mapping)
Last updated: 2026-09-19
Scope: Settings → Internet → Uploads (`CUploadsSettingsPage`) and the shared
bandwidth-limit token used on Settings → Internet → Downloads.
Source of truth: `Envy/PageSettingsUploads.cpp`, `Envy/TransferSettingsLimits.h`,
`Envy/Settings.cpp`, `Envy/Uploads.cpp`, `Envy/UploadQueues.cpp`.

Do not write “complete transfer UI” or “full qBittorrent-style limits”. This
page records what the engine actually does.

## Status vocabulary

| Term | Meaning |
| --- | --- |
| implemented | UI control is bound to a preference the core reads |
| partial | Core has the behaviour; UI is incomplete or easy to misread |
| planned | Next-PR proposal; not in this change |
| not implemented | No core consumer (must not look like a live control) |

---

## Uploads page mapping

Dialog: `IDD_SETTINGS_UPLOADS` (`Envy/Envy.rc`). Class: `CUploadsSettingsPage`.
Preferences persist through `CSettings::Item` (Windows registry). Absent keys
load the defaults below.

| UI control | Preference | Default | Unit | Range | Core consumer | Protocols | Persistence | Special values | State |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Limit sharing in hub mode | `Uploads.HubUnshare` | true | bool | — | `CUploads::GetBandwidthLimit` scales by `Bandwidth.HubUploads` % when G2 hub or G1 ultrapeer | G1/G2 hub role; the scaled cap then applies to all upload queues | registry `Uploads\HubUnshare` | — | implemented |
| Share new partial downloads | `Uploads.SharePartials` | true | bool | — | `CDownload` constructor `m_bShared`; ignored for many live ED2K/BT cases (see tooltip) | HTTP/Gnutella path; ED2K/BT often ignore | registry | — | partial (documented caveats) |
| Share preview files | `Uploads.SharePreviews` | true | bool | — | `CEDClient` preview send; `CLocalSearch` preview advertisement | ED2K + Gnutella browse/search | registry | — | implemented |
| Fair-Use mode | `Uploads.FairUseMode` | false | bool | — | **none** | — | registry (kept for old profiles) | — | **not implemented** (checkbox disabled) |
| Max uploads per host | `Uploads.MaxPerHost` | **2** (not 64) | count | 1–64 | `CUploads::AllowMoreTo` / `CanUploadFileTo` / `EnforcePerHostLimit`; HTTP `X-PerHost` | all upload transfers (HTTP, ED2K, DC, BT upload objects in `CUploads`) | registry; load + Apply clamp | 0 and &gt;64 clamped to 1..64 | implemented |
| User-Agent filter | `Uploads.BlockAgents` | `Mozilla`, `Foxy` | substring set | — | `Security.cpp` agent match | HTTP-style User-Agent | registry pipe list | empty = no extra blocks | implemented |
| Bandwidth Limit combo | `Bandwidth.Uploads` | **0** | bytes/s | 0 or parsed volume | `CUploads::GetBandwidthLimit`; queue point split; `CConnection::OnWrite` meter | global (all protocols sharing `Uploads` limiter) | registry `Bandwidth\Uploads` | **0 / Unlimited / MAX / NONE = unlimited** (no extra cap beyond `Connection.OutSpeed`) | implemented |
| Throttle combo | `Uploads.ThrottleMode` | false (Average) | bool | Average=0, Maximum=1 | `TCPBandwidthMeter::CalculateLimit` (`bMaxMode`); also +1 point fudge in `CUploadQueue::GetBandwidthLimit` | sockets using the output meter | registry | false = average (soft), true = maximum (strict, never exceed) | implemented |
| Queue list | `UploadQueues` XML/profile (not a single DWORD) | `CreateDefault()` by uplink | mix | per-queue | `CUploadQueue` match + slot/bandwidth points | HTTP vs ED2K queues; BT has a separate torrent queue object | `UploadQueues.Save()` on New/Edit/Delete/drag (**immediate**) | — | implemented (engine unchanged in this PR) |

### Not on this page (core exists)

| Setting | Default | Where used | UI today |
| --- | --- | --- | --- |
| `Bandwidth.Downloads` | 0 (unlimited) | download limiter | Settings → Downloads |
| `Downloads.MaxFiles` / `MaxTransfers` / `MaxFileTransfers` | 200 / 100 / 40 | active download caps | Settings → Downloads |
| `BitTorrent.UploadCount` | 4 (2–20) | BT unchoke / torrent upload slots | BitTorrent settings, **not** Uploads |
| `Bandwidth.HubIn/Out`, `LeafIn/Out`, `PeerIn/Out`, `UdpOut`, `Request` | various | G1/G2 neighbour pipes | Advanced settings, **not** Uploads |
| `Connection.InSpeed` / `OutSpeed` | wizard / connection page | physical cap used when Bandwidth.* is 0 or larger | Settings → Connection |
| Scheduler night/day bandwidth | writes `Bandwidth.Uploads/Downloads` | `Scheduler.cpp` | Scheduler window |
| `Uploads.ChunkSize`, `Clampdown*`, `FreeBandwidth*`, `QueuePoll*` | see settings reference | upload engine | Advanced only |
| Bind interface / VPN leak / IPv6 dual-stack | — | **not implemented** as transfer settings | see `docs/ipv6/` and network docs |

### Immediate vs Apply

- Queue New / Edit / Delete / drag-and-drop call `UploadQueues.Save()` immediately (French skin text “(Effet immédiat)” refers to **queue reordering**, not the bandwidth combo).
- Hub unshare, partials, previews, max-per-host, agent filter, bandwidth, throttle apply on **Apply/OK**.

---

## Defaults (do not change without protocol evidence)

| Value | Why it stays |
| --- | --- |
| `MaxPerHost = 2` | Historical Shareaza/Envy default. 64 is the **maximum**, not the default. Raising it increases per-IP upload slots and can hurt fairness. |
| `Bandwidth.Uploads = 0` | Unlimited extra cap; effective send rate still bounded by `Connection.OutSpeed`. |
| `ThrottleMode = false` | Average/soft limiter (Shareaza heritage). Strict mode is opt-in. |
| `FairUseMode = false` | Unused. |

---

## Inconsistencies found (this audit)

1. **Fair-Use checkbox had no `DDX` and no core reader** — decorative UI. Now disabled; value still persisted.
2. **`MAX` was a hardcoded English combo token** — French UI showed `MAX`. Display is now localized `Unlimited` / `Illimité`; `MAX`/`NONE` still parse as unlimited.
3. **`ParseVolume("MAX")` returned 0 only because parsing failed** — same as garbage text. Unlimited tokens are now recognized explicitly; unknown text still fails validation when the field is “limited”.
4. **`static_cast<DWORD>(ParseVolume(...))` truncated QWORD** — overflow now clamps to `DWORD` max.
5. **`MaxPerHost` Apply did not clamp** — spin range 1–64, but the edit could store 0 or &gt;64 until next load. Apply now clamps (load already did).
6. **`AllowMoreTo` uses `nCount <= MaxPerHost`** while **`CanUploadFileTo` uses `nCount < MaxPerHost`** — off-by-one between accept paths. **Not changed** (queue/engine risk). Follow-up.
7. **SharePartials** does not mean “always share incomplete files on every network” (tooltip).
8. **Queue order is first-match** (`SelectQueue`). Overlaps are deterministic (list order / drag priority) but easy to misconfigure. Engine unchanged.
9. Docs previously described Fair-Use as a live 10% media limit and ThrottleMode as a generic “enable throttling” bit.

---

## Benchmark (concepts only — do not copy UIs)

| Concept | Benefit | Envy backend today | This PR | Next PR? |
| --- | --- | --- | --- | --- |
| Global upload cap | Predictable uplink | `Bandwidth.Uploads` | clearer Unlimited + validation | — |
| Global download cap | Same | `Bandwidth.Downloads` | same token on Downloads page | — |
| Alt-speed / scheduler | Day/night caps | Scheduler writes bandwidth DWORDs | no UI change | expose status on Uploads? low priority |
| Max active downloads | Avoid overload | `Downloads.MaxFiles` / `MaxTransfers` | already on Downloads | Simple-mode summary |
| Max active uploads | Slot cap | Queue `m_nMinTransfers`/`m_nMaxTransfers` + `BitTorrent.UploadCount` | do not invent a fake global | Simple-mode only if a real global exists (it does not) |
| Connections global / per torrent | qBittorrent-style | Connection limits + BT settings, incomplete | — | later, only mapped settings |
| Per-IP upload cap | Anti-hog | `MaxPerHost` (transfers, not TCP) | renamed to match | do not pretend it is connections |
| Per-protocol bandwidth | Isolate BT vs ED2K | neighbour Hub/Leaf/Peer pipes; **not** a full per-protocol byte cap | — | only if we wire a real limiter |
| VPN leak / bind | Privacy | **not implemented** | — | not until sockets support it |
| IPv6 | Dual-stack | partial helpers | — | `docs/ipv6/PLAN.md` |
| UPnP / NAT-PMP | Reachability | MiniUPnP implemented (NAT-PMP/PCP planned) | — | not this page |
| ADC / I2P / WebTorrent | extra nets | ADC hub **not implemented**; do not add | — | out of scope |

---

## Planned UX (not in this PR)

### Simple mode (later)

- Download cap: Unlimited / value
- Upload cap: Unlimited / value
- Max active downloads (map existing `Downloads.Max*` — do not invent)
- Max active uploads: **only if** a true global exists; today it does not (queues + `BitTorrent.UploadCount`)

### Advanced mode (later, backend-gated)

- Per-protocol / per-transfer bandwidth **if** a limiter is added
- Connections: global, per protocol, per transfer, per host — only existing keys
- Upload slots / queue / min per slot / priority (queue properties already exist)
- Bind / IPv4/IPv6 / proxy / VPN leak — **not supported** until implemented
- Scheduler alternate limits — Scheduler already writes bandwidth; do not duplicate until product design is clear

Keep Small/Large/Partial/eDonkey queues. Do not delete them for a “modern” simple page.

### Suggested follow-up PRs

1. **Uploads host off-by-one** — prove `AllowMoreTo` vs `CanUploadFileTo` vs `EnforcePerHostLimit` with a regression test, then one behaviour.
2. **Simple-mode summary strip** on Uploads/Downloads showing the two global caps + download MaxFiles/MaxTransfers (read-only or the existing controls, no new prefs).
3. **Queue criteria documentation + overlap preview** (still no engine rewrite).
4. **Expose `BitTorrent.UploadCount` next to queues** with an explicit “BitTorrent only” label.
5. Bind / IPv6 / VPN leak — blocked on core, not UI.

---

## Tests

`tests/test_transfer_settings_limits_smoke.cpp` covers defaults, unlimited tokens
(including legacy `MAX`/`NONE` and a localized `Illimité`), DWORD overflow,
MaxPerHost clamp (0, 1, 64, 65, negative), absent-key fallback, and
Fair-Use-not-implemented.

Live MFC Apply/immediate queue save is not executed in EnvyTests (no dialog
host). Wire-format impact: **none**.
