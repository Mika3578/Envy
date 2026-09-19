#!/usr/bin/env python3
"""One documented command for the ENVY ↔ eMule/aMule interop harness (#160).

Examples:

    python3 tools/interop/run.py --dry-run
    python3 tools/interop/run.py --self-test
    python3 tools/interop/run.py --live --envy-exe "C:\\Path With Spaces\\Envy.exe" --amule-exe /usr/bin/amuled
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from envy_interop.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
