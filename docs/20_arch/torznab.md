# Torznab client (Prowlarr / Jackett)

Status: **planned**. Envy is not a Torznab server and not a Prowlarr/Jackett download client.

Torznab is **search**. It is not the download-client API used by Radarr.

Architecture: [`remote-api.md`](remote-api.md). Audit: [`AUDIT_REMOTE_API_2026-09.md`](AUDIT_REMOTE_API_2026-09.md).

## MVP

```text
IIndexer { GetCapabilities(); Search(...); }
TorznabIndexer : IIndexer
  base URL, API key, name, caps cache, timeout, enable, tags
```

First useful slice: `t=caps` + generic `t=search`. `tvsearch` / `movie` follow caps.

## Untrusted XML

Indexer XML is hostile input. Do **not** feed it to unbounded `CXMLElement::FromString`. Use a bounded walker (see `CHostBrowser::LoadDC`). Caps:

- HTTP body size
- XML size / depth / element count
- string / URL length
- attribute count
- category count
- redirects

No DTD, no XXE, no `file:` URLs. Build query URLs with a parser, never string concat onto the base.

Do not fetch magnet or `.torrent` hrefs without the same validation as manual add. Auto-download is out of MVP.

## Tests

Fixtures for valid/minimal caps, search hits/empty, missing fields, malformed/truncated/huge XML, unknown attrs/categories, wrong content-type, 401/403/429/500, timeout, redirect, invalid URL. No live Jackett required.
