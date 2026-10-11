# Peer XML validation

Scope: bounded G1/G2 XML parsing and HTTP metadata/THEX receive handling.
Issue #391 and PR #393 own this change. This guide describes validation;
it does not establish that a particular build has passed the live checks.

## Automated checks

Build the full Windows application with `Visual Studio/Envy.sln` using the
normal Release x64/Win32 commands in [build.md](build.md). Run EnvyTests on
each platform. Its peer XML cases exercise budget admission, shared accounting,
HTTP control-response classification and the production receive-loop helper.

After the solution build has generated `Envy/EnvyOM.h`, run the native suite
from a Visual Studio 2026 Developer shell at the repository root:

```powershell
msbuild tests/PeerXmlTests.vcxproj /m /p:Configuration=Release /p:Platform=x64
& 'tests/Release x64/PeerXmlTests.exe'
msbuild tests/PeerXmlTests.vcxproj /m /p:Configuration=Release /p:Platform=Win32
& 'tests/Release Win32/PeerXmlTests.exe'
```

This standalone MFC test target compiles the real `XML.cpp` and `Strings.cpp`.
It is separate from the full application solution and must be run explicitly.
It tests valid XML against the local parser, depth 32/33 and a 4096-level
attack, 4096-node admission, attribute accounting, exact character limits,
shared-budget/depth restoration, malformed input, UTF-8/UTF-16 BOM handling,
and the production HTTP receive-loop helper on a real loopback socket after
remote shutdown. It does not instantiate the complete download transfer or
exercise the session/profile ownership path.

## Controlled application checks

Record the PR HEAD, base, built commit, artifact/run, platform and results.
Use a disposable download directory. Start the loopback-only fixture:

```powershell
python tests/peer_http_fixture.py
```

Enable download metadata and Tiger verification in Envy for their respective
cases. Add each URL as a new HTTP download in Envy. Remove the previous test download
before repeating a case, so existing ranges or cached hash trees do not mask
the request being tested. The fixture prints expected SHA256 hashes; verify
completed downloads with `Get-FileHash -Algorithm SHA256 <file>`.

| URL suffix under `http://127.0.0.1:18793` | Expected observation |
| --- | --- |
| `/file-known.bin` | 65,536-byte download completes with the printed normal-file SHA256. |
| `/file-close.bin` | Same bytes/hash without Content-Length; no completion at a 16 KiB prefix. |
| `/file-empty.bin` | Explicit zero Content-Length is rejected before changing an unknown download size; no empty file is reported complete. |
| `/file-metadata-valid.bin` | Log shows `/metadata-valid` requested; valid bounded XML does not crash or stall the transfer. |
| `/file-metadata-close.bin` | Close-delimited metadata completes after shutdown. |
| `/file-metadata-deep.bin` | Depth-33 metadata is discarded; the application remains responsive. |
| `/file-metadata-large.bin` | Oversized metadata is rejected without unbounded buffering. |
| `/file-thex-single.bin` | Log shows `/thex-single`; the descriptor and matching nonempty-ID tree arrive together. |
| `/file-thex-split.bin` | Same tree/download result when the descriptor and a partial tree record arrive separately. |
| `/file-thex-short.bin` | Truncated known-length THEX fails closed; no successful tree installation is reported. |

THEX fixtures use the specification's 1024-byte `A` test vector and a padded
XML descriptor larger than the header receive cap. Confirm the THEX request
in the server log: a file download alone does not demonstrate tree handling.
The fixture is an HTTP test source and does not emulate a Gnutella client.
Stop it with Ctrl+C. No Internet-facing listener is created.

## Peer interoperability checks

With a second Envy or Shareaza-lineage client, verify G1/G2 search results with
metadata, Browse Host folders/results, a valid profile, and private chat.
Repeat search/browse after a rejected malformed profile or metadata payload;
the session must remain usable and the application must remain responsive.
Use a controlled peer fixture for malicious cases; ordinary successful
connections do not establish that the rejection paths ran. Record client
versions and which G1/G2 paths were actually observed. Do not claim universal
client compatibility from one reference-client pass.

## Protocol evidence

- [THEX draft, §3.3.1](https://adc.sourceforge.io/draft-jchapweske-thex-02.html):
  `http://open-content.net/spec/thex/breadthfirst` is the serialization **type
  identifier**, compared as data. It is not fetched. Replacing its scheme with
  HTTPS changes the identifier and breaks existing peers. The same applies to
  the Tiger digest identifier. Qualify cpp:S5332 on that comparison as a false
  positive with this evidence; do not suppress the rule or rewrite the value.
- [XML 1.0](https://www.w3.org/TR/REC-xml/): limits are Envy resource policy,
  not new XML syntax. Local `FromString`/`FromFile` behavior stays separate.
- [HTTP/1.1 framing, RFC 9112 §6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3):
  close-delimited responses end at connection close; known-length responses
  must contain their declared body. The bounded receive path must drain queued
  socket bytes before treating FD_CLOSE as completion.
