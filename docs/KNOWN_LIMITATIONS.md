# Known Limitations

This document tracks important current constraints that affect development and validation.

- **Toolchain runner dependency:** Authoritative `v145` parity is not guaranteed in every hosted CI context.
- **Incomplete CMake:** Top-level CMake does not yet model the full authoritative application build.
- **Limited protocol parser tests:** Automated coverage for malformed/edge packet paths remains partial; ED2K SourceEx and inbound length-underflow guards are covered by `tests/test_protocol_parser_smoke.cpp`, but full MFC-linked ReadBuffer integration tests are still absent.
- **ED2K SecureIdent:** eMule-compatible RSA SecureIdent is **not implemented**. As of #75 Envy does not advertise SecureIdent and never marks peers verified; inbound SecureIdent packets are ignored without blocking ED2K transfer. See `docs/DEVELOPMENT_PLAN.md` SecureIdent roadmap and `docs/10_dev/status.md`.
- **ED2K/Kad live interop:** Opcode-level documentation is not a substitute for Envy ↔ eMule Community / aMule transfer tests. Live interoperability remains **unverified**.
- **No headless daemon:** Envy is an MFC GUI process. Remote/Web is a limited control surface, not a stable JSON-RPC/REST engine API.
- **Legacy UI/core coupling:** MFC and core protocol logic remain tightly coupled in key paths.
- **Partial IPv6 support:** Helpers and settings exist; core sockets, host cache, and Source Exchange remain IPv4-centric (`docs/ipv6/PLAN.md`).
- **CI limitations:** CI signals are useful but not a complete substitute for full local/VS validation.
- **Protocol gaps:** Some advanced ED2K/Kad/BitTorrent features remain partial or planned.
