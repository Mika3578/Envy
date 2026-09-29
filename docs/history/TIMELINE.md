# Envy release and era timeline

Labels:

- **Historical** — what was claimed or shipped at the time (cite dated sources).
- **Current** — what the maintained fork documents today (cite `docs/10_dev/status.md`).

Full evidence table: [`SOURCES.md`](SOURCES.md).

## Pre-Envy lineage (context)

| Era | Period | Notes | Label |
| --- | --- | --- | --- |
| Shareaza active development | 2000s–2010s | Reference client for G1/G2 heritage in Envy | Historical context |
| PeerProject | ~2008–2019 | Shareaza-lineage fork; predecessor branding to Envy | Historical |

## GetEnvy / upstream Envy (tagged releases)

| Version / tag | Date (UTC) | Source | Major themes (historical) | Label |
| --- | --- | --- | --- | --- |
| `1.0.0.0.Pre` | 2016-04-08 | [GitHub](https://github.com/GetEnvy/Envy/releases/tag/1.0.0.0.Pre) | Early public preview on GitHub | Historical |
| `1.0.0.0` | 2016-09-02 | [GitHub](https://github.com/GetEnvy/Envy/releases/tag/1.0.0.0) | First numbered 1.0.0.0 tag | Historical |
| `1.0 RC`, `1.0` | 2017-01 | [GitHub](https://github.com/GetEnvy/Envy/releases) | 1.x stabilization | Historical |
| `2.0` | 2019-08-01 | [GitHub](https://github.com/GetEnvy/Envy/releases/tag/2.0) | Announced as major polished fork; forum post cites ~2 years of work | Historical |
| `3.0` | 2020-01-04 | [GitHub](https://github.com/GetEnvy/Envy/releases/tag/3.0) | Continued upstream tagging | Historical |
| `4.0` | 2020-01-22 | [GitHub](https://github.com/GetEnvy/Envy/releases/tag/4.0) | Last upstream GitHub “Latest” at time of research | Historical |

Internal revision notes (r20 / r30 / r35 mapping): [`Repository/Documents/ShareazaCommits.txt`](../../Repository/Documents/ShareazaCommits.txt).

## Inactivity and fork modernization

| Era | Period | Notes | Label |
| --- | --- | --- | --- |
| Reduced upstream activity | ~2020–2025 | GetEnvy/Envy default branch largely quiet; site getenvy.com unreliable | Historical observation |
| Mika3578/Envy modernization | 2025–2026 | Active `develop`, CI, protocol hardening, preview release track | **Current** |
| `v4.2.0-preview.1` (draft) | 2026-09 | [Releases](https://github.com/Mika3578/Envy/releases) — preview, not stable GA | **Current** (preview) |

## Protocol claims — how to cite

Example (historical): “SourceForge project pages in the late 2010s described Envy as supporting BitTorrent, G2, Gnutella, ED2K, and DC++.”

Example (current): “On `develop`, ED2K and Kad2 are documented as partial with live interop unverified — see the status matrix.”

Never merge the two without explicit labeling.

## Windows support (summary)

| Era | Windows positioning |
| --- | --- |
| Historical Envy 1.x–4.x | Windows client (historical installers on SourceForge / GitHub) |
| Current fork | Windows 10 1809+; x64 primary; Win32 legacy Stage A ([`AGENTS.md`](../../AGENTS.md), [`status.md`](../10_dev/status.md)) |

## Sources

[`SOURCES.md`](SOURCES.md); archived site <https://web.archive.org/web/*/http://getenvy.com/>.
