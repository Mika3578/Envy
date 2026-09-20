"""Bounded packet-evidence extractors for interop scenarios.

Not a Wireshark replacement. Fail closed on malformed frames. Optional tshark
is used only when present; absence is SKIP, never an install attempt.

ED2K TCP frames use ``<proto:1><size:4 LE><opcode:1><body>`` (0xE3/0xC5).
Kad2 UDP datagrams use ``<proto:1><opcode:1><body>`` (0xE4); packed 0xE5 is
recognized but not inflated here.
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
    ED2K_PROTOCOL_KAD,
    ED2K_PROTOCOL_KAD_PACKED,
    KAD_OP_FIND_NODE,
    KAD_OP_FIND_NODE_RES,
    KAD_OP_FIREWALLED_ACK_RES,
    KAD_OP_FIREWALLED_REQ,
    KAD_OP_FIREWALLED_RES,
    KAD_OP_HELLO_REQ,
    KAD_OP_HELLO_RES,
    KAD_OP_PING,
    KAD_OP_PONG,
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


# eMule / eDonkey TCP (sized frames). Kad must not be registered here.
TCP_OPCODE_LABELS = {
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
}

# Kad2 UDP opcodes on protocol 0xE4 (Envy/EDPacket.h).
# HELLO is 0x11/0x19 (Bootstrap 0x01/0x09 is not registered here).
KAD_OPCODE_LABELS = {
    KAD_OP_HELLO_REQ: "kad_hello",
    KAD_OP_HELLO_RES: "kad_hello",
    KAD_OP_PING: "kad_ping_pong",
    KAD_OP_PONG: "kad_ping_pong",
    KAD_OP_FIND_NODE: "kad_find_node",
    KAD_OP_FIND_NODE_RES: "kad_find_node",
    KAD_OP_SEARCH_SOURCE_REQ: "kad_search_source_req",
    KAD_OP_SEARCH_RES: "kad_search_res",
    KAD_OP_FIREWALLED_REQ: "kad_firewalled_req",
    KAD_OP_FIREWALLED_RES: "kad_firewalled_res",
    KAD_OP_FIREWALLED_ACK_RES: "kad_firewalled_ack",
}

# Back-compat alias for callers/tests that imported OPCODE_LABELS.
OPCODE_LABELS = {**TCP_OPCODE_LABELS}


def find_tshark() -> Optional[str]:
    return shutil.which("tshark")


def extract_ed2k_frames(blob: bytes, *, max_frames: int = 64) -> List[FrameHit]:
    """Scan a blob for ED2K TCP frames: <proto:1><size:4 LE><opcode:1><body>.

    Fail closed: truncated size fields are skipped; no speculative repair.
    Does not recognize Kad UDP (0xE4); use ``extract_kad_udp_frames``.
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
        label = TCP_OPCODE_LABELS.get((proto, opcode), f"op_{proto:02x}_{opcode:02x}")
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
                # Do not store the observed IPv4 — evidence JSON is not sanitized.
                details["ipv4_present"] = True
        elif proto == ED2K_PROTOCOL_EMULE and opcode == ED2K_C2C_CALLBACK:
            if len(body) != 38:
                details["parse_error"] = f"CALLBACK body must be exactly 38 bytes, got {len(body)}"
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
                compressed_len = struct.unpack_from("<I", body, need - 4)[0]
                remaining = len(body) - need
                if remaining != compressed_len:
                    details["parse_error"] = (
                        f"compressed payload length mismatch "
                        f"(declared {compressed_len}, remaining {remaining})"
                    )
                else:
                    details["i64"] = opcode == ED2K_C2C_COMPRESSEDPART_I64
                    details["compressed_len"] = compressed_len
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


def _next_kad_opcode_offset(blob: bytes, start: int) -> int:
    """Return offset of the next 0xE4 + known Kad opcode, or len(blob)."""
    n = len(blob)
    i = start
    while i + 2 <= n:
        if blob[i] == ED2K_PROTOCOL_KAD and blob[i + 1] in KAD_OPCODE_LABELS:
            return i
        i += 1
    return n


def extract_kad_udp_frames(blob: bytes, *, max_frames: int = 64) -> List[FrameHit]:
    """Scan for Kad2 UDP datagrams: <0xE4><opcode:1><body> (no size field).

    Packed protocol 0xE5 is skipped (fail closed — no inflate). Body runs until
    the next known Kad opcode header or end of blob. Single-datagram operator
    dumps are the common case.
    """
    hits: List[FrameHit] = []
    n = len(blob)
    i = 0
    while i + 2 <= n and len(hits) < max_frames:
        proto = blob[i]
        if proto == ED2K_PROTOCOL_KAD_PACKED:
            i += 1
            continue
        if proto != ED2K_PROTOCOL_KAD:
            i += 1
            continue
        opcode = blob[i + 1]
        label = KAD_OPCODE_LABELS.get(opcode)
        if label is None:
            i += 1
            continue
        frame_end = _next_kad_opcode_offset(blob, i + 2)
        body = blob[i + 2 : frame_end]
        details: Dict[str, Any] = {"body_len": len(body), "transport": "udp"}
        if opcode in (KAD_OP_HELLO_REQ, KAD_OP_HELLO_RES):
            # <NodeID 16><TagList…> — NodeID is mandatory.
            if len(body) < 16:
                details["parse_error"] = f"HELLO body too short ({len(body)} < 16)"
            else:
                details["has_node_id"] = True
        elif opcode in (KAD_OP_PING, KAD_OP_PONG):
            # <TagList> — at least the tag-count byte.
            if len(body) < 1:
                details["parse_error"] = f"PING/PONG body too short ({len(body)} < 1)"
        elif opcode in (KAD_OP_FIND_NODE, KAD_OP_FIND_NODE_RES):
            # <NodeID 16><Type 1><TagList…>
            if len(body) < 17:
                details["parse_error"] = f"FIND_NODE body too short ({len(body)} < 17)"
            else:
                details["has_node_id"] = True
                details["find_type"] = body[16]
        elif opcode == KAD_OP_FIREWALLED_REQ:
            if len(body) != 2:
                details["parse_error"] = f"FIREWALLED_REQ body must be 2 bytes, got {len(body)}"
            else:
                details["tcp_port"] = struct.unpack("<H", body)[0]
        elif opcode == KAD_OP_FIREWALLED_RES:
            if len(body) != 4:
                details["parse_error"] = f"FIREWALLED_RES body must be 4 bytes, got {len(body)}"
            else:
                # Observed public IP — never persist the raw address.
                details["ipv4_present"] = True
        elif opcode == KAD_OP_FIREWALLED_ACK_RES:
            if len(body) != 0:
                details["parse_error"] = f"FIREWALLED_ACK body must be empty, got {len(body)}"
        elif opcode == KAD_OP_SEARCH_SOURCE_REQ:
            if len(body) < 16:
                details["parse_error"] = f"SEARCH_SOURCE_REQ body too short ({len(body)} < 16)"
            else:
                details["has_filehash"] = True
                details["has_filesize"] = len(body) >= 24
        elif opcode == KAD_OP_SEARCH_RES:
            # Two wire layouts exist in this repo:
            # - Production inbound / eMule (KadSearchResDelivery.h):
            #   <SenderID 16><TargetID 16><Count 2 LE>  (min 34)
            # - Envy outbound OnSearch*Request responses (Kademlia.cpp):
            #   <Hash 16><Count 1>  (min 17) — legacy; accept for evidence
            min_emule = 16 + 16 + 2
            min_legacy = 16 + 1
            if len(body) >= min_emule:
                details["layout"] = "sender_target_count2"
                details["has_sender_id"] = True
                details["has_target_id"] = True
                details["result_count"] = struct.unpack_from("<H", body, 32)[0]
            elif len(body) >= min_legacy:
                details["layout"] = "envy_outbound_hash_count1"
                details["has_filehash"] = True
                details["result_count"] = body[16]
            else:
                details["parse_error"] = (
                    f"SEARCH_RES body too short ({len(body)} < {min_legacy})"
                )
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


def _overlaps_span(offset: int, length: int, spans: Sequence[Tuple[int, int]]) -> bool:
    end = offset + length
    for start, stop in spans:
        if offset < stop and end > start:
            return True
    return False


def extract_frames(blob: bytes, *, max_frames: int = 64) -> List[FrameHit]:
    """Extract ED2K TCP and Kad UDP evidence frames from a blob.

    Kad hits that fall inside a recognized ED2K TCP frame span are dropped so
    compressed/TCP payload bytes cannot false-PASS Kad observe scenarios.
    """
    tcp = extract_ed2k_frames(blob, max_frames=max_frames)
    tcp_spans = [(h.offset, h.offset + h.length) for h in tcp]
    kad_raw = extract_kad_udp_frames(blob, max_frames=max_frames)
    kad = [
        h
        for h in kad_raw
        if not _overlaps_span(h.offset, h.length, tcp_spans)
    ]
    combined = tcp + kad
    combined.sort(key=lambda h: h.offset)
    return combined[:max_frames]


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
) -> List[bytes]:
    """Extract per-packet TCP/UDP payloads (one list entry per tshark field line).

    Units are not concatenated: callers must parse each chunk separately so UDP
    datagram and TCP segment boundaries are preserved.
    """
    tool = find_tshark()
    if not tool:
        raise EvidenceError("tshark not found (optional; do not install from the harness)")
    if not pcap_path.is_file():
        raise EvidenceError(f"pcap not found: {pcap_path}")
    port_or = " or ".join(
        f"(tcp.port == {int(p)} or udp.port == {int(p)})" for p in ports
    )
    display = f"({port_or})"
    chunks: List[bytes] = []
    for field in ("tcp.payload", "udp.payload"):
        argv = [
            tool,
            "-r",
            str(pcap_path),
            "-Y",
            display,
            "-T",
            "fields",
            "-e",
            field,
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
        for line in proc.stdout.splitlines():
            hex_str = line.strip().replace(":", "")
            if not hex_str:
                continue
            try:
                chunks.append(bytes.fromhex(hex_str))
            except ValueError as exc:
                raise EvidenceError("tshark produced malformed hex payload") from exc
    return chunks


def write_evidence_summary(path: Path, summary: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")


def safe_evidence_source_name(name: str) -> str:
    """Fixed attachable identifier — never store operator basenames (PII/path leak)."""
    del name  # intentionally unused; basename content must not reach evidence JSON
    return "packet-evidence.bin"


def ingest_packet_dump(
    source: Path,
    dest_dir: Path,
    *,
    required_labels: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    raw = load_evidence_bytes(source)
    hits = extract_frames(raw)
    summary = summarize_hits(hits)
    summary["source_name"] = safe_evidence_source_name(source.name)
    if required_labels:
        ok, reason = require_labels(hits, required_labels)
        summary["required_ok"] = ok
        summary["required_reason"] = reason
        if not ok:
            raise EvidenceError(reason)
    dest_dir.mkdir(parents=True, exist_ok=True)
    write_evidence_summary(dest_dir / "packet-evidence.json", summary)
    return summary
