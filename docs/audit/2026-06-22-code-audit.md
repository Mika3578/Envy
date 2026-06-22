# Envy Code Audit — 2026-06-22

- **Date:** 2026-06-22
- **Scope:** First-party C++ (`Envy/`, `HashLib/` first-party wrappers, `TorrentEnvy/`),
  the remote-control web surface, and the dependency/build wiring. Vendored trees
  (`Services/`, `HashLib/HashLib/*`, third-party plugins) inspected only for *how
  they are used*.
- **Method:** Targeted source reading by subsystem (network parsers, remote/web/URL
  surface, memory-safety + C++20 debt, crypto/concurrency) with every Critical/High
  finding verified against the exact code and its call chain. File:line references
  are exact against `develop` at the time of writing.
- **Companion artifacts:** parser fixes in PR #69 (`fix/parser-length-validation`);
  individual findings tracked as issues #70–#79.

## Executive summary

Envy is a multi-protocol P2P client that parses **untrusted data from the internet**
across BitTorrent, ED2K/eMule, Kad, Gnutella and G2. The highest-impact findings are
remotely triggerable memory-safety bugs in the packet parsers: several let a single
crafted packet from an ordinary peer drive `len - N` arithmetic that underflows
before being bounded against the bytes actually available, producing ~4 GB
allocations / heap over-reads or NULL dereferences (remote crash / DoS, no auth).
The remote-control web interface adds a stored-XSS → takeover path and missing CSRF
checks. Cryptographic posture is mostly protocol-compat-legacy (acceptable) with a
few genuine security-relevant gaps (a non-functional ED2K SecureIdent check, a weak
`rand()` fallback for security tokens, and password storage without a KDF).

| Severity | Count |
|---|---|
| Critical | 2 |
| High | 8 |
| Medium | ~12 |
| Low / latent | ~8 |

A class of five parser bugs (the Critical pair + three High) is **fixed in PR #69**;
the rest are tracked for follow-up.

## Critical — remotely exploitable, single crafted packet, no authentication

| # | Issue | File:line | Bug | Status |
|---|---|---|---|---|
| C1 | #70 | `Envy/EDPacket.cpp:458` + `EDPacket.h:152` | ED2K `ReadBuffer`: `nLength == 0` passes the unsigned guard → `New()` does `Write(ptr, 0xFFFFFFFF)` → ~4 GB allocation + heap over-read. | Fixed in #69 |
| C2 | #71 | `Envy/BTPacket.cpp:550` | BitTorrent extension packet with declared length 1 → `nLength - 2 = 0xFFFFFFFF` into `CBENode::Decode` → heap over-read. | Fixed in #69 |

Common root cause: `len - N` computed on a declared length **before** clamping it
against the bytes actually available.

## High

| # | Issue | File:line | Bug | Status |
|---|---|---|---|---|
| H1 | #72 | `Envy/QueryHit.cpp:909` (+ `G1Packet.cpp:444`) | Query-hit XML `{deflate}`: `nSize - 10 = -1` → `CZLib::Decompress` over-read. | Fixed in #69 |
| H2 | #73 | `Envy/QueryHit.cpp:1111`, `QuerySearch.cpp:902` & `:962` | Zero-length GGEP `H`/`M` item leaves `m_pBuffer == NULL`; `switch (m_pBuffer[0])` → NULL deref / remote crash. | Fixed in #69 |
| H3 | #74 | `Envy/EDClient.cpp:2974` | ED2K preview answer: `static_cast<int>(nFrameSize)` makes a high-bit size negative → bounds check bypassed → multi-GB byte-by-byte disk write. | Fixed in #69 |
| H4 | #75 | `Envy/EDClient.cpp:199-224` | ED2K SecureIdent verification accepts **any non-zero response** (`return TRUE` if a byte ≠ 0); uses the wrong ID and never receives the peer's random bytes. Broken auth primitive. | Open |
| H5 | #76 | `Envy/Remote.cpp:689-695` (sinks `:1064/1108/1434/1597/1737`) | Stored XSS: peer-supplied filenames / User-Agent / nicks rendered into the remote web UI unescaped (`SafeString` only strips control chars). Viewing a tab runs script in the authenticated session → remote-control takeover. | Open |
| H6 | #77 | `Envy/Remote.cpp:1711`, `:1256`, `:1533` | Missing CSRF checks on network connect/disconnect and download/upload filter+group+queue state; the CSRF gate only matches certain path substrings. | Open |
| H7 | #78 | `RemoteSecurity.cpp:386-396`, `Envy.h:377`, `Envy.cpp:1835` | `rand()` fallback for session IDs / CSRF tokens / salts and anti-spoof tokens when the crypto provider is unavailable (and `CryptAcquireContext`'s return is ignored). Predictable → session hijack. | Open |
| H8 | #79 | `RemoteSecurity.cpp:417-456` | Remote password storage uses single-iteration salted SHA256 (no KDF) and still accepts unsalted legacy `SHA1(password)`. | Open |

## Medium

- **Unbounded bencode recursion** → stack-exhaustion crash, reachable from
  torrent/tracker/peer/DHT — `Envy/BENode.cpp:489` / `:509`.
- **`ut_metadata` size trusted without cap** → memory-exhaustion — `BTClient.cpp:1361` /
  `:1479`, reassembly in `BTInfo.cpp` (the `.torrent` path caps at 20 MB; this one
  does not).
- **`atoin` has no overflow check** feeding bencode `i…e` integers used as
  sizes/offsets — `Strings.cpp:680` → `BENode.cpp:472`.
- **ED2K `.met`/collection blob allocation** from an unchecked 32-bit length
  (`CFile*` overload) — `EDPacket.cpp:1560` (the in-packet reader is correctly
  bounded).
- **ED2K hashset answer**: block count validated but not payload length before
  `SetHashset` — `DownloadTransferED2K.cpp:386`.
- **CSRF token placed in URLs and logged** (history/Referer/log leak) —
  `Remote.cpp:803` / `:193`.
- **`LocalAlloc` leak** with no `LocalFree` on any path in `ReadCHM` —
  `LibraryBuilderInternals.cpp:4514`.
- **Clipboard buffer under-allocated by one byte** (wide NUL not written) —
  `TorrentEnvy/PageFinished.cpp:332`.
- **Lock-ordering inversion** on (EDClients `m_pSection`, `Transfers.m_pSection`) —
  `EDClients.cpp:354` vs `:383` (mitigated by timed `Lock(250)`).
- **`TerminateThread` on shutdown** can orphan held `CCriticalSection`s →
  potential deadlock — `EnvyThread.cpp:239-278`.

## Low / latent

- Base64 padding OOB write on empty input — `RemoteSecurity.cpp:540`.
- Attacker-controlled magnet/`envy:` source URLs validated only by `SafeString`
  (SSRF-style) — `EnvyURL.cpp:1028`, `:769-825`.
- BitTorrent v2 (BEP-52) Merkle verification is **stubbed** (uses dummy hashes) and
  has no first-party caller — dangerous if ever wired in — `MerkleTree.cpp:132-168`.
- AICH chunk verification is a stub that always returns true (dead code) —
  `HashLib/AICH.cpp:228-244`.
- `_PORTABLE` build: five hash pointers uninitialized + leak on early return —
  `TorrentEnvy/TorrentBuilder.h:99`.
- `__int64 → int` narrowing in bencode string-length decode (not exploitable in
  practice) — `BENode.cpp:554`.
- `CGGEPItem::Read` / `CG2Packet::New(BYTE*)` rely on the single caller for bounds
  (defense-in-depth only) — `GGEP.cpp:273`, `G2Packet.cpp:114`.

## C++20 / v145 modernization debt (first-party)

| Construct (removed/deprecated) | Count | Representative sites |
|---|---|---|
| `throw()` exception-spec → `noexcept` | ~109 | `HGlobal.h`, `ThreadImpl.h`, `HostCache.h`, `Augment/*.hpp`, `StreamArchive.h` |
| `register` storage class | 22 | `Strings.cpp`, `QueryHashTable.cpp`, `XML.cpp` |
| `std::bind2nd` | 11 | `HostCache.*`, `FragmentedFile.cpp` |
| `augment::auto_ptr` (project's own replacement) | ~40 use sites | `LibraryBuilderInternals.cpp`, `CollectionFile.cpp` → migrate to `std::unique_ptr` |
| `virtual ~T() throw()` | 2 | `HGlobal.h:55`, `StreamArchive.h:38` |

Confirmed **absent** in first-party code: `std::unary_function`/`binary_function`
bases, `std::bind1st`, `std::ptr_fun`, `std::random_shuffle`, `std::auto_ptr` (the
std one), deprecated allocator members.

## Dependencies

- **The vcpkg manifest is misleading.** `vcpkg.json` declares `zlib`, `bzip2`,
  `sqlite3`, `miniupnpc`, but the solution actually compiles and links the **vendored**
  copies in `Services/` via `<ProjectReference>` (e.g. `Envy/Envy.vcxproj:1676` →
  `Services/MiniUPnP/MiniUPnPc.vcxproj`). Only `openssl` (and `gtest` for tests) truly
  comes from vcpkg. vcpkg/Dependabot updates therefore do **not** reach these libraries.
- **UnRAR 5.30 (2015)** — `Services/UnRAR/UnRARDLL.vcxproj`, loaded by
  `Plugins/RARBuilder`. Parses untrusted archives; old UnRAR has serious CVEs
  (e.g. CVE-2022-30333 path traversal). High priority to update or sandbox.
- **MiniUPnPc 2.0 (2016)** — vendored and linked; parses SSDP/SOAP network responses;
  ~8 years of upstream fixes missing (latest 2.2.x).
- **zlib 1.3** — current-ish; 1.3.1 exists. **SQLite 3.51.1** — current.
- **Version inconsistency:** `vcpkg.json` `version-string` is `5.0.0` while
  `version.json` is `4.1.0` (build 53). (Note: `MODERNIZATION.md`'s bundled-deps table
  lists older versions than the tree actually contains, e.g. zlib 1.2.10 / sqlite 3.30
  — that table is stale.)

## Prior findings re-checked

- **`KadProtocol.cpp` `strcpy` (prior SECURITY_AUDIT)** — **refuted.** No `strcpy`
  exists; keyword handling is length-bounded and the file is dead code
  (`#ifdef ENVY_LEGACY_KADEMLIA`, never defined). The active implementation is
  `Kademlia.cpp`.
- **"Broad ShellExecute surface" (prior SECURITY_AUDIT)** — **largely refuted.** Of
  60+ call sites, only `FileExecutor.cpp:332` touches an attacker-influenced filename,
  and it is specifically sanitized (quote-strip + `PathCanonicalize`). The `command:`
  URI does **not** shell out (dispatches to internal command IDs).
- Path traversal in remote file serving, HTTP Range parsing, IRC format-strings, and
  several agent-suggested `memcpy` sites were checked and found **safe**.

## Recommended remediation order

1. **P0 (remote memory-safety):** C1, C2, H1, H2, H3 — *done in PR #69*. Follow up
   with a sweep for sibling `nLength -` / `nSize -` patterns and a parser smoke/fuzz
   harness for these packet paths.
2. **P1:** H4 (SecureIdent), H5 (remote XSS output-escaping), H6 (CSRF), H7 (RNG
   fail-closed), H8 (password KDF); bencode recursion + `ut_metadata` caps; UnRAR /
   MiniUPnPc currency.
3. **P2:** C++20 debt (scriptable per category), Merkle/AICH stubs, memory leaks,
   the vcpkg-vs-vendored wiring, and the `5.0.0`/`4.1.0` version reconciliation.
