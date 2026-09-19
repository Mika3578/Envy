"""Golden Hello capture metadata and ingest (no auto-commit of raw dumps)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from .hello import HelloParseError, normalize_hello_for_commit, parse_hello_tcp


class GoldenError(ValueError):
    pass


def parse_hex_dump(text: str) -> bytes:
    cleaned = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue
        if stripped.startswith("0000") and "  " in stripped:
            # Possible xxd offset line: take the hex columns only.
            parts = stripped.split()
            hex_parts = [p for p in parts[1:] if all(c in "0123456789abcdefABCDEF" for c in p)]
            cleaned.extend(hex_parts)
            continue
        cleaned.append(stripped.replace(" ", "").replace("\t", ""))
    hex_str = "".join(cleaned)
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]
    if len(hex_str) % 2:
        raise GoldenError("odd number of hex digits")
    try:
        return bytes.fromhex(hex_str)
    except ValueError as exc:
        raise GoldenError("invalid hex") from exc


def load_bytes(path: Path) -> bytes:
    data = path.read_bytes()
    if not data:
        raise GoldenError(f"empty capture: {path}")
    try:
        text_try = data.decode("utf-8")
    except UnicodeDecodeError:
        return data
    stripped = text_try.lstrip()
    if stripped.startswith("{"):
        try:
            obj = json.loads(text_try)
        except json.JSONDecodeError as exc:
            raise GoldenError(f"capture looks like JSON but is malformed: {path}") from exc
        if isinstance(obj, dict) and obj.get("tcp_frame_hex"):
            return bytes.fromhex(str(obj["tcp_frame_hex"]))
        raise GoldenError("JSON capture missing tcp_frame_hex")
    if all(c in "0123456789abcdefABCDEF \r\n\t#/" for c in stripped.replace("x", "")):
        return parse_hex_dump(text_try)
    if stripped.lower().startswith("0x") or all(
        c in "0123456789abcdefABCDEF \r\n\t" for c in stripped
    ):
        return parse_hex_dump(text_try)
    return data


def golden_metadata(
    *,
    reference_client: str,
    reference_version: str,
    direction: str,
    protocol: int,
    opcode: int,
    capture_date: str,
    normalization: str,
    hex_bytes: str,
    notes: str = "",
) -> Dict[str, Any]:
    if not reference_client:
        raise GoldenError("reference_client is required")
    if not reference_version and reference_client not in {"envy-self"}:
        raise GoldenError("reference_version is required for non-self goldens")
    if direction not in {"send", "recv"}:
        raise GoldenError("direction must be send or recv")
    return {
        "schema_version": 1,
        "reference_client": reference_client,
        "reference_version": reference_version,
        "packet_direction": direction,
        "protocol": protocol,
        "opcode": opcode,
        "capture_date": capture_date,
        "normalization": normalization,
        "privacy": "userhash and server IP/port zeroed for committed candidates",
        "notes": notes,
        "tcp_frame_hex": hex_bytes,
    }


def ingest_hello(
    source: Path,
    dest_dir: Path,
    *,
    reference_client: str,
    reference_version: str,
    direction: str,
    normalize: bool = True,
) -> Dict[str, Any]:
    raw = load_bytes(source)
    parsed = parse_hello_tcp(raw)
    store = parsed
    normalization = "none"
    if normalize:
        store = normalize_hello_for_commit(parsed)
        normalization = "userhash zeroed; trailing server IPv4/port zeroed"
    meta = golden_metadata(
        reference_client=reference_client,
        reference_version=reference_version,
        direction=direction,
        protocol=store.protocol,
        opcode=store.opcode,
        capture_date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        normalization=normalization,
        hex_bytes=store.raw.hex(),
        notes="Candidate only. Do not commit until origin/version/privacy review.",
    )
    dest_dir.mkdir(parents=True, exist_ok=True)
    out = dest_dir / "hello-candidate.json"
    out.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    return meta


def load_golden_json(path: Path) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GoldenError(f"malformed golden metadata: {path}") from exc
    for key in (
        "reference_client",
        "reference_version",
        "packet_direction",
        "protocol",
        "opcode",
        "capture_date",
        "normalization",
        "tcp_frame_hex",
    ):
        if key not in data:
            raise GoldenError(f"golden missing {key}")
    parse_hello_tcp(bytes.fromhex(data["tcp_frame_hex"]))
    return data
