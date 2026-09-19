"""Deliberately generated, harmless, bounded test files with reproducible hashes."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .md4 import md4_hex

FIXTURE_MARKER = b"ENVY-ED2K-INTEROP-FIXTURE\n"
FIXTURE_SIZE = 64 * 1024  # 64 KiB — well under the 9.5 MiB ED2K chunk size
ED2K_CHUNK = 9728000


@dataclass(frozen=True)
class TestFileSpec:
    name: str
    size: int
    ed2k_hex: str
    sha256_hex: str
    note: str


def build_payload(size: int = FIXTURE_SIZE) -> bytes:
    if size <= 0 or size > 1024 * 1024:
        raise ValueError("fixture size must be in 1..1048576 bytes")
    body = FIXTURE_MARKER + bytes(i & 0xFF for i in range(size - len(FIXTURE_MARKER)))
    return body[:size]


def ed2k_hex(data: bytes) -> str:
    """ED2K hash: MD4 of the file when size <= one chunk."""
    if len(data) > ED2K_CHUNK:
        raise ValueError("phase-1 fixtures stay in a single ED2K chunk")
    return md4_hex(data)


def spec_for(data: bytes, name: str = "envy-interop-fixture.bin") -> TestFileSpec:
    import hashlib

    return TestFileSpec(
        name=name,
        size=len(data),
        ed2k_hex=ed2k_hex(data),
        sha256_hex=hashlib.sha256(data).hexdigest(),
        note="Harmless generated fixture; not copyrighted P2P content.",
    )


def write_fixture(directory: Path, *, size: int = FIXTURE_SIZE) -> TestFileSpec:
    directory.mkdir(parents=True, exist_ok=True)
    data = build_payload(size)
    meta = spec_for(data)
    (directory / meta.name).write_bytes(data)
    (directory / (meta.name + ".meta.json")).write_text(
        json.dumps(
            {
                "name": meta.name,
                "size": meta.size,
                "ed2k": meta.ed2k_hex,
                "sha256": meta.sha256_hex,
                "note": meta.note,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return meta
