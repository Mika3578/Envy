# Bootstrap sources versus discovered hosts

Status: active
Last updated: 2026-09-19
Scope: Cold-start catalogues shipped with Envy. Not a claim that every protocol is complete.

**Bootstrap sources ≠ discovered peers/servers.** Envy already keeps those layers apart:

| Layer | Files | Role |
| --- | --- | --- |
| A. Shipped catalogue | `Data/DefaultServices.dat`, `Data/DefaultServers.dat` | Minimal sources for a new install or wiped local cache |
| B. Learned runtime data | `Discovery.dat`, `HostCache.dat` | GWC URLs, ED2K servers, G1/G2 hosts, BT DHT nodes, Kad contacts learned while running |
| C. Last-known-good remote catalogue | *planned* | Refresh A independently of the binary, never blocking startup |

Do not copy B back into A. Do not compile bootstrap IPs into `.cpp` / `.h`. The old `CDiscoveryServices::AddDefaults()` built-in string list is **commented out**; if the data files are missing, Envy does not invent a second C++ list.

Status vocabulary: catalogue refresh is **implemented** for the shipped files; remote last-known-good is **planned**; Kad remote `nodes.dat` is **planned** and does **not** make Kad2 complete.

## Cold-start by protocol

| Network | Status | Cold-start path |
| --- | --- | --- |
| ED2K | implemented (list download) | `DefaultServices.dat` `D` URLs → `server.met` import into HostCache. No static server IPs. |
| Kad2 | partial | `HostCache.Kademlia` only. Empty cache → `CKademlia::Bootstrap()` exits. No shipped `K` hosts. Remote `nodes.dat` not wired (ImportNodes accepts old format and new-format version 1 only; eMule-Security currently publishes version 2). See #86 / #160. |
| Gnutella 1 | implemented (bootstrap) | gtk-gnutella UHCs (`U uhc:…`) plus multi-network GWCs. |
| Gnutella2 | implemented (bootstrap) | Independent GWCs (jayl.de, bj.ddns.net, 4octets, trillinux). |
| DC NMDC | implemented (hublist) | Three HTTPS hublists. `adc://` / `adcs://` skipped until #163. |
| ADC/ADCS | not implemented | `adc://` / `adcs://` rows are ignored; NMDC rows in the same hublists are still imported. Do not treat import as ADC support. |
| BitTorrent DHT | implemented (bootstrap) | `DefaultServers.dat` `B` DNS routers loaded into HostCache. `CDHT::Connect` inserts cached node IDs; if none exist it sends BEP 5 `find_node` to up to 8 HostCache BitTorrent hosts (blocking DNS capped at 3 names; empty cache reloads `DefaultServers.dat`). No extra C++ DNS list. If the catalogue file is missing or every name fails DNS, DHT still marks connected and waits for later PEX/tracker nodes — D-012 forbids compiling `router.bittorrent.com` (or any replacement) into `.cpp`. Successful nodes persist in `HostCache.dat`. |

## Shipped sources (audited 2026-09-18)

### ED2K `server.met`

| URL | Operator | HTTPS | Notes |
| --- | --- | --- | --- |
| `https://upd.emule-security.org/server.met` | eMule-Security | yes | Official list; 12 servers, `0xE0`, last-modified 2026-09-18 16:04 UTC |
| `https://shortypower.org/server.met` | shortypower | yes | Independent; 30 servers, `0x0E`, last-modified 2026-09-18 20:59 UTC |

Removed: static IPs in `DefaultServers.dat` (TV Underground / eDonkey Server No1–3 / 2019 Peerates IP); `peerates.net` (last-modified 2021); `gruk.org` (HTML, not `.met`); `emule-server.de` (last-modified 2009); `www.emule-security.org/server.met` (404). Setting `eDonkey.ServerListURL` default is the eMule-Security HTTPS URL.

### Gnutella 1 UHC

From gtk-gnutella `devel/src/core/uhc.c` (not HTTP GWC):

- `uhc:useast.gnutella.dyslexicfish.net:3558`
- `uhc:uswest.gnutella.dyslexicfish.net:3558`
- `uhc:uk.gnutella.dyslexicfish.net:3558`
- `uhc:au.gnutella.dyslexicfish.net:3558`
- `uhc:1.uhc.gtk-gnutella.nl:19104`
- `uhc:2.uhc.gtk-gnutella.nl:4876`

Removed: `uhc.gtk-gnutella.nl:15749` (obsolete port); HTTP GWC rows that pointed at UDP UHC ports `:3558` / `:3559`.

### Gnutella / G2 GWebCache

Live `hostfile=1` responses on 2026-09-18 (HTTP; TLS name mismatch on `midian.jayl.de`):

| URL | Type | Operator |
| --- | --- | --- |
| `http://midian.jayl.de/g2/bazooka.php` | M | jayl.de |
| `http://bj.ddns.net/beacon/gwc.php` | M | bj.ddns.net |
| `http://gweb3.4octets.co.uk/gwc.php` | M | 4octets |
| `http://dkac.trillinux.org/dkac/dkac.php` | 2 | trillinux (G2 only) |

Removed as dead or parked: `cache.getenvy.com/*` (lander), `gwctest.zapto.org`, `disobscure.velum-ultra.com`, `tenafly5k.com`, `gwc.centrump2p.com`, `cache.ce3c.be`, `cache.ibel.de`, `k33bz.com` (HTTP 500). `skulls.gwc.dyslexicfish.net` is an HTML directory, not a queryable GWC.

### Direct Connect hublists (NMDC)

| URL | Operator | Mix |
| --- | --- | --- |
| `https://dchublist.org/hublist.xml.bz2` | dchublist.org | 249 hubs; NMDC + some ADC/ADCS |
| `https://dchublist.ru/hublist.xml.bz2` | dchublist.ru | 92 hubs; NMDC |
| `https://te-home.net/?do=hublist&get=hublist.xml.bz2` | Team Elite | 240 hubs; mixed |

`DC.HubListURL` default is the dchublist.org HTTPS URL. `dchublist.com` 301s to Team Elite; `tankafett.biz` 301s to an HTML page, not `hublist.xml.bz2`.

### BitTorrent DHT routers

| Host | Reference |
| --- | --- |
| `dht.transmissionbt.com:6881` | Transmission `tr-dht.cc` |
| `router.bittorrent.com:6881` | still in qBittorrent defaults |
| `dht.libtorrent.org:25401` | libtorrent bootstrap node |

Removed: `router.utorrent.com`, `router.bitcomet.com` (no DNS), `dht.aelitis.com` (Vuze). Persistence of working nodes remains `CDHT::Disconnect` → `HostCache.dat`.

`CHostCacheList::Add` stores unresolved DNS names with `m_pAddress = INADDR_ANY` (`Network.Resolve(..., FALSE)` does not call DNS). `CHostCacheMap` is a `std::multimap`, so the three shipped `B` rows all insert under `0.0.0.0` without dropping later names; `Find(IN_ADDR)` returns NULL for `INADDR_ANY` by design; `CDHT::Connect` iterates `m_HostsTime` and still copies all three. Debug `ASSERT(m_Hosts.size() == m_HostsTime.size())` remains true. Rewriting HostCache keying for hostname-only rows is a follow-up, not this catalogue slice.

## Remaining C++ network addresses (not this catalogue)

Justified runtime / product URLs, **not** P2P bootstrap:

- `WEB_SITE`, `UPDATE_URL`, `UPDATE_URL_ALT` in `Envy.h` - website and version check
- Schema `xmlns` and `getenvy.com` copyright comments
- `BitTorrent.DefaultTracker` - torrent tracker default, not DHT bootstrap

## Follow-ups (not this slice)

- Parser hardening for `server.met` / `nodes.dat` / hublist BZip2 / GWC (size, inflate, entry caps) — P0 potential; see #82 and related importer PRs
- Kad remote `nodes.dat` type + ImportNodes v2/v3 + empty-cache path — only with #86/#160; do not announce Kad complete
- Last-known-good remote catalogue (async, ETag, atomic replace, never block startup)
- Scheduled GitHub workflow that **reports** source health and never auto-merges `develop`

## Wire-format impact

None. Catalogue files and HostCache/Discovery loaders are local. DHT still uses BEP 5 `find_node` toward bootstrap routers.
