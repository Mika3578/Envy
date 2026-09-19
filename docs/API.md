# API Documentation

## Scope

There are **three** automation surfaces. They are not interchangeable.

| Surface | Status | Canonical docs |
| --- | --- | --- |
| Native ENVY control API (`/api/v1`) | **planned** | [`docs/20_arch/remote-api.md`](20_arch/remote-api.md), [`docs/api/openapi.yaml`](api/openapi.yaml) |
| qBittorrent Web API **subset** for *arr | **planned** | [`docs/20_arch/arr-integration.md`](20_arch/arr-integration.md) |
| Torznab **client** (Prowlarr/Jackett) | **planned** | [`docs/20_arch/torznab.md`](20_arch/torznab.md) |
| HTML Remote UI (`/remote/`) | **partial** | `Envy/Remote.cpp` — browser control, not a JSON engine API |
| `Remote/api-specification.md` | **obsolete design** | JS `/api/*` calls have **no** C++ handlers |

Audit (2026-09): [`docs/20_arch/AUDIT_REMOTE_API_2026-09.md`](20_arch/AUDIT_REMOTE_API_2026-09.md).

Do not call Envy “Radarr-compatible” or “qBittorrent-compatible” until interoperability tests exist.

## Native authentication (planned)

`Authorization: Bearer <token>`. Cookie/CSRF remains for the HTML Remote UI only.

## Verification

This tree does not ship a served JSON API. Headless/daemon is **planned** (#161). Validate each future route against live handlers before relying on it from external tools.
