# Third-Party Licenses (Vendored Components)

This document tracks bundled third-party attribution for vendored components. Entries marked `TODO` require maintainer follow-up to confirm or add explicit in-tree license text.

| Component | Declared License | In-Tree License Evidence |
|---|---|---|
| SQLite | Public Domain | `Services/SQLite/sqlite3.h` header notice (public domain statement). |
| zlib | zlib License | TODO: explicit standalone license file not found under `Services/zlib/`; verify and add canonical license text file/link. |
| MiniUPnPc | BSD-3-Clause | `Services/MiniUPnP/License.txt`. |
| UnRAR | UnRAR License | `Services/UnRAR/License.txt`. |
| HashLib | AGPLv3 (per file headers) with mixed upstream notices | TODO: no dedicated `HashLib` license file found; current evidence is per-source header blocks (for example `HashLib/HashLib.h`, `HashLib/MD5.cpp`, `HashLib/SHA.cpp`). |
