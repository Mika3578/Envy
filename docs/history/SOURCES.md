# Envy historical research — evidence ledger

Status: community research artifact (not canonical for current implementation).

Use this ledger before repeating historical claims on the website, Wiki, or in outreach.
Current protocol and product status live in [`docs/10_dev/status.md`](../10_dev/status.md).

## How to read this table

| Column | Meaning |
| --- | --- |
| **Type** | primary project source; archived primary source; source-code evidence; maintainer statement; secondary source |
| **Confidence** | verified; strongly supported; uncertain |

Do not publish **uncertain** rows as facts in user-facing copy.

## Claims

| Claim | Date/period | Source | Type | Confidence | Notes |
| --- | --- | --- | --- | --- | --- |
| Shareaza is an open-source multi-network P2P client; Envy’s G1/G2/DC stacks are Shareaza-lineage | 2000s–present | [Shareaza on SourceForge](https://sourceforge.net/projects/shareaza/); Envy `Envy/G1*`, `Envy/G2*` | source-code evidence | verified | Lineage is code-path specific, not a single rename event |
| PeerProject was presented as a Shareaza-lineage fork with continued development | ~2008–2019 | [PeerProject on SourceForge](https://sourceforge.net/projects/peerproject/); [Open Hub PeerProject](https://www.openhub.net/p/peerproject) | secondary source | strongly supported | Open Hub metadata is archival, not a spec |
| PeerProject first commit ~September 2008 (Open Hub COCOMO estimate) | 2008 | [Open Hub PeerProject](https://www.openhub.net/p/peerproject) | secondary source | uncertain | Use as approximate metadata only |
| Upstream Envy ReadMe states: previously PeerProject; originally derived from Shareaza | 2016+ | [GetEnvy/Envy ReadMe.txt](https://github.com/GetEnvy/Envy/blob/master/ReadMe.txt) | primary project source | verified | Paraphrase only in public docs |
| GetEnvy/Envy GitHub repository created 2016-04-03 | 2016-04 | [GetEnvy/Envy](https://github.com/GetEnvy/Envy) repository metadata | primary project source | verified | API `created_at` |
| First tagged pre-release `1.0.0.0.Pre` on GetEnvy/Envy | 2016-04-08 | [GitHub release 1.0.0.0.Pre](https://github.com/GetEnvy/Envy/releases/tag/1.0.0.0.Pre) | primary project source | verified | |
| Tagged release `1.0.0.0` | 2016-09-02 | [GitHub release 1.0.0.0](https://github.com/GetEnvy/Envy/releases/tag/1.0.0.0) | primary project source | verified | |
| Tagged releases `1.0 RC`, `1.0` | 2017-01 | [GitHub releases](https://github.com/GetEnvy/Envy/releases) | primary project source | verified | |
| Envy 2.0 release tag dated 2019-08-01 | 2019-08 | [GitHub release 2.0](https://github.com/GetEnvy/Envy/releases/tag/2.0) | primary project source | verified | |
| Maintainer announced Envy 2.0 after ~2 years of development; forked from PeerProject mirror of Shareaza; described PeerProject as “retired” in maintainer’s wording | 2019 (forum post) | [Shareaza forum topic 2626](https://shareaza.sourceforge.net/phpbb/viewtopic.php?f=9&t=2626) | maintainer statement | strongly supported | Community succession language; not a legal transfer |
| Envy 2.0 described as largely up to date with Shareaza r9700 (~2 years prior in post) | 2019 | Same forum topic | maintainer statement | strongly supported | Historical comparison only |
| Tagged releases `3.0`, `4.0` on GetEnvy/Envy | 2020-01 | [GitHub releases 3.0, 4.0](https://github.com/GetEnvy/Envy/releases) | primary project source | verified | |
| Internal revision map: v1→r20 (2017.1), v2→r30 (2019.8), v3→r35 (2020.1); Shareaza baseline r9700 | 2016–2020 | [`Repository/Documents/ShareazaCommits.txt`](../../Repository/Documents/ShareazaCommits.txt) | source-code evidence | strongly supported | Maintainer-maintained mapping in tree |
| Historical project site `http://getenvy.com` | 2010s–2020s | [Wayback Machine snapshots](https://web.archive.org/web/*/http://getenvy.com/) | archived primary source | strongly supported | Prefer dated archive URLs in links |
| SourceForge project `getenvy` hosts historical downloads and descriptions | 2016+ | [SourceForge getenvy](https://sourceforge.net/projects/getenvy/) | archived primary source | strongly supported | User reviews are opinion, not specs |
| Mika3578/Envy is a fork of GetEnvy/Envy with active modernization on `develop` | 2025–2026 | [Mika3578/Envy](https://github.com/Mika3578/Envy); [`docs/10_dev/devsecops-envy.md`](../10_dev/devsecops-envy.md) | primary project source | verified | |
| Planned preview release `v4.2.0-preview.1` on maintained fork | 2026-09 | [Mika3578/Envy releases](https://github.com/Mika3578/Envy/releases) | primary project source | planned | Target pending publication; not a verified release |
| Current Windows x64 is primary product; ED2K/Kad interop partial/unverified live | 2026 | [`docs/10_dev/status.md`](../10_dev/status.md) | primary project source | verified | Canonical **current** truth |
| CHANGELOG narrative dates for “Envy 1.0.0.0” in 2022 conflict with GetEnvy tags in 2016–2017 | — | [`CHANGELOG.md`](../../CHANGELOG.md) vs GetEnvy releases | source-code evidence | verified | Site/Wiki follow tags + ledger, not unchecked CHANGELOG prose |

## Archive pointers (non-exhaustive)

- getenvy.com: <https://web.archive.org/web/*/http://getenvy.com/>
- peerproject.org / SourceForge: <https://sourceforge.net/projects/peerproject/>
- Shareaza source browser (historical baseline): <http://sourceforge.net/p/shareaza/code/>

## Research gaps (intentionally omitted from public “fact” lists)

- Exact calendar month of first public Envy **source** commit before `1.0.0.0.Pre` without reading full GetEnvy git history.
- Whether specific historical website pages claimed support for protocols beyond what release notes stated — verify per dated snapshot before quoting.
