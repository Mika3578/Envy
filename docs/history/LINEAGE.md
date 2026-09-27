# Shareaza, PeerProject, and Envy — lineage

Status: community history (see [`SOURCES.md`](SOURCES.md)). **Current** implementation status: [`docs/10_dev/status.md`](../10_dev/status.md).

## What this document is not

Envy is **not** accurately described as “Shareaza renamed.” The relationship is layered:

| Layer | Summary |
| --- | --- |
| **Source-code lineage** | Large parts of the multi-network UI and several protocol stacks (notably Gnutella, Gnutella2, and Direct Connect paths) inherit from the Shareaza line via PeerProject-era code. ED2K/Kad work on the maintained fork follows eMule-family interoperability goals documented separately. |
| **Project succession** | PeerProject continued Shareaza-lineage development under its own branding; upstream Envy then continued from that codebase under the Envy name (see upstream ReadMe and 2019 maintainer forum post in the ledger). |
| **Maintained fork today** | [Mika3578/Envy](https://github.com/Mika3578/Envy) is an active modernization fork of [GetEnvy/Envy](https://github.com/GetEnvy/Envy). It is not the same as historical getenvy.com operations. |

## Shareaza (context only)

Shareaza is an open-source Windows multi-network client. Envy documentation references Shareaza for **G1/G2 behaviour and heritage**, not as the live governing project of today’s fork.

Further Shareaza history belongs on Shareaza’s own archives; this file only covers what Envy contributors need for accurate lineage.

## PeerProject

PeerProject was marketed as a versatile multi-network client (BitTorrent, Gnutella/G2, eDonkey, DC++, and others in historical materials). Open Hub and SourceForge record long-running development with last activity years before the maintained fork’s modernization phase.

Upstream Envy credits PeerProject as the immediate predecessor name. That is a **rebrand and continuation**, not proof that every PeerProject release feature maps 1:1 to current Envy behaviour.

## Envy (GetEnvy / historical)

The GetEnvy GitHub organization published tagged releases from 2016 through 2020 (`1.0.0.0.Pre` through `4.0`). A 2019 maintainer post on the Shareaza forum announced Envy 2.0 and described the effort as pushing beyond a PeerProject mirror that had tracked Shareaza’s slowdown.

Historical marketing on SourceForge and archived getenvy.com pages described broad protocol support. Treat those as **historical claims** unless corroborated for the **current** tree.

## Mika3578/Envy (current)

The maintained fork targets Windows 10+ with Visual Studio 2026 / v145, manifest vcpkg dependencies, expanded CI, and evidence-based status reporting. Preview builds may be published as drafts; there is no promise of feature parity with every historical Envy major version announcement.

## Suggested vocabulary

| Phrase | When to use |
| --- | --- |
| **derived from** | Code ancestry (Shareaza-lineage modules) |
| **forked from** | GitHub fork relationship (Mika3578 ← GetEnvy) |
| **succeeded / continued development** | Community narrative with maintainer source cited |
| **rebranded from** | PeerProject → Envy name change per upstream ReadMe |

## Sources

See [`SOURCES.md`](SOURCES.md) and the website [history page](https://github.com/Mika3578/Envy/blob/develop/site/history.html) (after merge).
