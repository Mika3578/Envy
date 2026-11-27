"""Make envy_interop importable when unittest discovers tests/ directly."""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_TESTS = Path(__file__).resolve().parent
for entry in (_ROOT, _TESTS):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))
