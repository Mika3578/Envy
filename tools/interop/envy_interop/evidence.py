"""Bounded packet-evidence extractors for interop scenarios.

Not a Wireshark replacement. Fail closed on malformed frames. Optional tshark
is used only when present; absence is SKIP, never an install attempt.
"""

from __future__ import annotations

import json
import shutil
import struct
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .constants import (
    ED2K_C2C_ANSWERSOURCES,
    ED2K_C2C_ANSWERSOURCES2,
    ED2K_C2C_CALLBACK,
    ED2K_C2C_COMPRESSEDPART,
    ED2K_C2C_COMPRESSEDPART_I64,
    ED2K_C2C_HELLO,
    ED2K_C2C_HELLOANSWER,
    ED2K_C2C_PUBLICIP_ANSWER,
    ED2K_C2C_PUBLICIP_REQ,
    ED2K_C2C_REQUESTSOURCES,
    ED2K_C2C_REQUESTSOURCES2,
    ED2K_PROTOCOL_EDONKEY,
    ED2K_PROTOCOL_EMULE,
    KAD_OP_FIREWALLED_ACK_RES,
    KAD_OP_FIREWALLED_REQ,
    KAD_OP_FIREWALLED_RES,
    KAD_OP_SEARCH_RES,
    KAD_OP_SEARCH_SOURCE_REQ,
)
from .golden import GoldenError, load_bytes
from .hello import HelloParseError, parse_emule_info_tcp, parse_hello_tcp


class EvidenceError(ValueError):
    pass


@dataclass
class FrameHit:
    protocol: int
    opcode: int
    offset: int
    length: int
    label: str
    details: Dict[str, Any] = field(default_factory=dict)


OPCODE_LABELS = {
    (ED2K_PROTOCOL_EDONKEY, ED2K_C2C_HELLO): "hello",
    (ED2K_PROTOCOL_EDONKEY, ED2K_C2C_HELLOANSWER): "hello_answer",
    (ED2K_PROTOCOL_EMULE, 0x01): "muleinfo",
    (ED2K_PROTOCOL_EMULE, 0x02): "muleinfo_answer",
    (ED2K_PROTOCOL_EMULE, ED2K_C2C_COMPRESSEDPART): "compressedpart",
    (ED2K_PROTOCOL_EMULE, ED2K_C2C_COMPRESSEDPART_I64): "compressedpart_i64",
    (ED2K_PROTOCOL_EMULE, ED2K_C2C_PUBLICIP_REQ): "publicip_req",
    (ED2K_PROTOCOL_EMULE, ED2K_C2C_PUBLICIP_ANSWER): "publicip_answer",
    (ED2K_PROTOCOL_EMULE, ED2K_C2C_CALLBACK): "callback",
    (ED2K_PROTOCOL_EMULE, ED2K_C2C_REQUESTSOURCES): "sourceex_req",
    (ED2K_PROTOCOL_EMULE, ED2K_C2C_ANSWERSOURCES): "sourceex_ans",
    (ED2K_PROTOCOL_EMULE, ED2K_C2C_REQUESTSOURCES2): "sourceex2_req",
    (ED2K_PROTOCOL_EMULE, ED2K_C2C_ANSWERSOURCES2): "sourceex2_ans",
    (ED2K_PROTOCOL_EMULE, KAD_OP_SEARCH_SOURCE_REQ): "kad_search_source_req",
    (ED2K_PROTOCOL_EMULE, KAD_OP_SEARCH_RES): "kad_search_res",
    (ED2K_PROTOCOL_EMULE, KAD_OP_FIREWALLED_REQ): "kad_firewalled_req",
    (ED2K_PROTOCOL_EMULE, KAD_OP_FIREWALLED_RES): "kad_firewalled_res",
    (ED2K_PROTOCOL_EMULE, KAD_OP_FIREWALLED_ACK_RES): "kad_firewalled_ack",
}


def find_tshark() -> Optional[str]:
    return shutil.which("tshark")


def extract_ed2k_frames(blob: bytes, *, max_frames: int = 64) -> List[FrameHit]:
    """Scan a blob for ED2K TCP frames: <proto:1><size:4 LE><opcode:1><body>.

    Fail closed: truncated size fields are skipped; no speculative repair.
    """
    hits: List[FrameHit] = []
    i = 0
    n = len(blob)
    while i + 6 <= n and len(hits) < max_frames:
        proto = blob[i]
        if proto not in (ED2K_PROTOCOL_EDONKEY, ED2K_PROTOCOL_EMULE):
            i += 1
            continue
        size = struct.unpack_from("<I", blob, i + 1)[0]
        if size < 1 or size > 2 * 1024 * 1024:
            i += 1
            continue
        frame_end = i + 5 + size
        if frame_end > n:
            # Plausible proto+size can appear in unrelated bytes; keep scanning.
            i += 1
            continue
        opcode = blob[i + 5]
        body = blob[i + 6 : frame_end]
        label = OPCODE_LABELS.get((proto, opcode), f"op_{proto:02x}_{opcode:02x}")
        details: Dict[str, Any] = {"body_len": len(body)}
        if proto == ED2K_PROTOCOL_EDONKEY and opcode in (ED2K_C2C_HELLO, ED2K_C2C_HELLOANSWER):
            try:
                parsed = parse_hello_tcp(blob[i:frame_end])
                details["client_id"] = parsed.client_id
                details["tcp_port"] = parsed.tcp_port
                details["compression"] = parsed.features1["compression"]
                details["kad_nibble"] = parsed.features2["kad"]
            except HelloParseError as exc:
                details["parse_error"] = str(exc)
        elif proto == ED2K_PROTOCOL_EMULE and opcode in (0x01, 0x02):
            try:
                info = parse_emule_info_tcp(blob[i:frame_end])
                details.update({k: info[k] for k in ("emule_protocol_version",) if k in info})
            except HelloParseError as exc:
                details["parse_error"] = str(exc)
        elif proto == ED2K_PROTOCOL_EMULE and opcode == ED2K_C2C_PUBLICIP_ANSWER:
            if len(body) != 4:
                details["parse_error"] = f"PUBLICIP_ANSWER body must be 4 bytes, got {len(body)}"
            else:
                details["ipv4_le"] = struct.unpack("<I", body)[0]
        elif proto == ED2K_PROTOCOL_EMULE and opcode == ED2K_C2C_CALLBACK:
            if len(body) < 38:
                details["parse_error"] = f"CALLBACK body too short ({len(body)} < 38)"
            else:
                details["layout"] = "kadcheck16+filehash16+ip4+tcp2"
        elif proto == ED2K_PROTOCOL_EMULE and opcode in (
            ED2K_C2C_COMPRESSEDPART,
            ED2K_C2C_COMPRESSEDPART_I64,
        ):
            need = 16 + (8 if opcode == ED2K_C2C_COMPRESSEDPART_I64 else 4) + 4
            if len(body) < need:
                details["parse_error"] = f"compressed part header truncated ({len(body)} < {need})"
            else:
                details["i64"] = opcode == ED2K_C2C_COMPRESSEDPART_I64
        hits.append(
            FrameHit(
                protocol=proto,
                opcode=opcode,
                offset=i,
                length=frame_end - i,
                label=label,
                details=details,
            )
        )
        i = frame_end
    return hits


def load_evidence_bytes(path: Path) -> bytes:
    try:
        return load_bytes(path)
    except GoldenError as exc:
        raise EvidenceError(str(exc)) from exc


def summarize_hits(hits: Sequence[FrameHit]) -> Dict[str, Any]:
    labels = [h.label for h in hits]
    return {
        "frame_count": len(hits),
        "labels": labels,
        "unique_labels": sorted(set(labels)),
        "frames": [
            {
                "protocol": h.protocol,
                "opcode": h.opcode,
                "offset": h.offset,
                "length": h.length,
                "label": h.label,
                "details": h.details,
            }
            for h in hits
        ],
    }


def require_labels(hits: Sequence[FrameHit], required: Sequence[str]) -> Tuple[bool, str]:
    have = {h.label for h in hits}
    missing = [name for name in required if name not in have]
    if missing:
        return False, f"missing evidence labels: {', '.join(missing)}"
    # Fail closed if any matching frame carried a parse_error.
    for h in hits:
        if h.label in required and h.details.get("parse_error"):
            return False, f"{h.label}: {h.details['parse_error']}"
    return True, "required evidence labels present"


def extract_from_pcap_via_tshark(
    pcap_path: Path,
    *,
    ports: Sequence[int],
    timeout_sec: float = 30.0,
) -> bytes:
    """Extract TCP payloads for configured ports using tshark when available."""
    tool = find_tshark()
    if not tool:
        raise EvidenceError("tshark not found (optional; do not install from the harness)")
    if not pcap_path.is_file():
        raise EvidenceError(f"pcap not found: {pcap_path}")
    port_or = " or ".join(f"tcp.port == {int(p)}" for p in ports)
    display = f"({port_or})"
    argv = [
        tool,
        "-r",
        str(pcap_path),
        "-Y",
        display,
        "-T",
        "fields",
        "-e",
        "tcp.payload",
    ]
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EvidenceError(f"tshark failed: {exc}") from exc
    if proc.returncode != 0:
        raise EvidenceError(f"tshark exit {proc.returncode}: {proc.stderr.strip()[:200]}")
    chunks: List[bytes] = []
    for line in proc.stdout.splitlines():
        hex_str = line.strip().replace(":", "")
        if not hex_str:
            continue
        try:
            chunks.append(bytes.fromhex(hex_str))
        except ValueError as exc:
            raise EvidenceError("tshark produced malformed hex payload") from exc
    return b"".join(chunks)


def write_evidence_summary(path: Path, summary: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")


def ingest_packet_dump(
    source: Path,
    dest_dir: Path,
    *,
    required_labels: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    raw = load_evidence_bytes(source)
    hits = extract_ed2k_frames(raw)
    summary = summarize_hits(hits)
    summary["source_name"] = source.name
    if required_labels:
        ok, reason = require_labels(hits, required_labels)
        summary["required_ok"] = ok
        summary["required_reason"] = reason
        if not ok:
            raise EvidenceError(reason)
    dest_dir.mkdir(parents=True, exist_ok=True)
    write_evidence_summary(dest_dir / "packet-evidence.json", summary)
    return summary
