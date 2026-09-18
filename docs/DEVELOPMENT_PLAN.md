# DEVELOPMENT PLAN (LIVING)

> **LIVING DOCUMENT** — Must be updated after every meaningful change (feature, architectural decision, scope change, blocker resolution).

- **Last Updated:** 2026-09-18
- **Changelog Entry:** 2026-09-18 — #81/#82: file-backed ED2K tag key / TAG_STRING lengths checked against remaining `.met` bytes (`Ed2kTagStringLengthOk`) before allocate/Read.
- **Changelog Entry:** 2026-09-18 — #166 / D-009 P1: Windows Firewall exceptions via WFAS `INetFwPolicy2` (all Domain/Private/Public profiles); drop legacy `INetFwMgr`.
- **Changelog Entry:** 2026-09-18 — #76: Remote UI HTML-escapes `CRemote::Add()` substitutions (`Escape`); `AddRaw` for trusted markup; `RemoteHtmlEscape.h` + EnvyTests smoke coverage.
- **Changelog Entry:** 2026-09-18 — #82 partial: BEP-9 ut_metadata advertised size capped at 32 MiB (`BtUtMetadataSizeOk`) before accepting metadata pieces.
- **Changelog Entry:** 2026-09-18 — #79: Remote passwords stored with PBKDF2-HMAC-SHA256 (`BCryptDeriveKeyPBKDF2`); legacy SHA1 / sha256-salted verify + migrate on login.
- **Changelog Entry:** 2026-09-18 — #92 cooperative close: abandon timed-out threads without `TerminateThread` (`EnvyThreadPolicy.h`); completes remaining #92 slice after lock-order.
- **Changelog Entry:** 2026-09-18 — #92 lock-order: EDClients before Transfers (`Ed2kLockOrder.h`); remaining #92 item is cooperative thread close without `TerminateThread`.
- **Changelog Entry:** 2026-09-18 — #121: CryptLayer Hello bits stay 0 (TCP obfuscation unimplemented); peer Hello crypt bits no longer start PUBLICKEY packet crypto (`Ed2kCryptLayerHelloBitsMayStartPacketCrypto`).
