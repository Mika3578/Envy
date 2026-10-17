# Envy review guide

Envy is a legacy MFC/ATL peer-to-peer client for Windows (C++17 today, C++20
policy for new first-party code), built with MSBuild and `Visual Studio/Envy.sln`.

Report only findings a maintainer would act on, most severe first:

- Correctness: memory lifetime, bounds checks, integer overflow, null handling,
  error paths, resource leaks.
- Threading and locking: `CCriticalSection` / `CSingleLock` use, races,
  lock ordering.
- Protocol and network code (ED2K/Kad, Gnutella/G2, BitTorrent, NMDC/ADC,
  NAT, packet parsing): wire-format changes, untrusted input validation,
  missing regression tests.
- Security: Remote web UI (CSRF, XSS, auth, sessions), crypto, secrets,
  workflow permissions and unpinned actions.

Do not comment on:

- Formatting. `clang-format-diff` already gates changed hunks; the codebase uses
  tabs and Allman braces on purpose.
- MFC style. `CString`, `CAtlList`, `CMap` and Hungarian member prefixes
  (`m_s`, `m_n`, `m_b`, `m_p`) are the house style; do not suggest `std::`
  replacements in MFC code.
- Vendored third-party trees (`Services/`, `HashLib/HashLib/`) or translations.
- Copyright years or licence headers, unless one was removed.

Write comments in English, one finding per comment, with the concrete failure
scenario and a minimal fix.
