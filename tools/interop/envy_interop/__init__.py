"""ENVY live interoperability harness (GitHub issue #160).

This package is opt-in integration infrastructure. It does not change ED2K or
Kad production protocol behavior. Live eMule/aMule binaries are never required
for unit tests or required PR CI.
"""

from __future__ import annotations

HARNESS_VERSION = "1.0.0"
REPORT_SCHEMA_VERSION = 1

__all__ = ["HARNESS_VERSION", "REPORT_SCHEMA_VERSION"]
