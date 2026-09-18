# DEVELOPMENT PLAN (LIVING)

> **LIVING DOCUMENT** — Must be updated after every meaningful change (feature, architectural decision, scope change, blocker resolution).

- **Last Updated:** 2026-09-17
- **Changelog Entry:** 2026-09-17 — #92 slice: Remote Base64 empty-input safety (`RemoteBase64.h`), CHM `LocalAlloc`/`LocalFree` pairing, TorrentEnvy clipboard wide-NUL size. EDClients lock order and `TerminateThread` remain open.
- **Last Updated:** 2026-09-18
- **Changelog Entry:** 2026-09-17 — Portable ZIP staging now mirrors the Inno runtime tree (`stage-portable.ps1`: `Data`/`Skins`/`Schemas`/`Plugins`/…); flattened EXE/DLL-only ZIPs are rejected by `verify-artifacts.ps1`.
- **Changelog Entry:** 2026-09-17 — Hardened `release.yml`: replaced parallel `softprops/action-gh-release` asset uploads with idempotent sequential `gh api` uploads by `release_id` (`scripts/release/*`); draft stays unpublished; `workflow_dispatch` remains dry-run unless explicit `repair_release_id`.
- **Changelog Entry:** 2026-09-17 — #120: ED2K preview frames capped at 4 MiB and written with a bounded bulk copy (`Ed2kPreviewFrameAcceptable`).
