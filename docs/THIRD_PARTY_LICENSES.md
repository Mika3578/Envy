# Third-Party Licenses (Vendored Components)

This document tracks bundled third-party attribution for vendored components. Entries marked `TODO` require maintainer follow-up to confirm or add explicit in-tree license text.

| Component | Declared License | In-Tree License Evidence |
|---|---|---|
| SQLite | Public Domain | `Services/SQLite/sqlite3.h` header notice (public domain statement). |
| zlib | zlib License | `Services/zlib/zlibwapi.txt` (full license notice) and `Services/zlib/zlib.h` header notice. |
| MiniUPnPc | BSD-3-Clause | `Services/MiniUPnP/License.txt`. |
| UnRAR | UnRAR License | `Services/UnRAR/License.txt`. |
| HashLib | GPLv3-or-later (per file headers) with mixed upstream notices | No dedicated `HashLib` license file; evidence is per-source header blocks (for example `HashLib/HashLib.h`, `HashLib/MD5.cpp`, `HashLib/SHA.cpp`). TODO: add a standalone `HashLib/LICENSE` file. |
