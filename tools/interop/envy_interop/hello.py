"""Parse ED2K C2C Hello / HelloAnswer TCP frames and compare capability bits."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .constants import (
    ED2K_C2C_HELLO,
    ED2K_C2C_HELLOANSWER,
    ED2K_CT_FEATUREVERSIONS,
    ED2K_CT_MOREFEATUREVERSIONS,
    ED2K_CT_NAME,
    ED2K_CT_SOFTWAREVERSION,
    ED2K_CT_UDPPORTS,
    ED2K_CT_VERSION,
    ED2K_PROTOCOL_EDONKEY,
    ED2K_TAG_INT,
    ED2K_TAG_STRING,
    ENVY_ADVERTISED,
    ENVY_IMPLEMENTED,
    ENVY_KNOWN_ADVERTISE_DEBT,
)


class HelloParseError(ValueError):
    pass


def _u16(buf: bytes, offset: int) -> int:
    return buf[offset] | (buf[offset + 1] << 8)


def _u32(buf: bytes, offset: int) -> int:
    return (
        buf[offset]
        | (buf[offset + 1] << 8)
        | (buf[offset + 2] << 16)
        | (buf[offset + 3] << 24)
    )


def unpack_misc_options1(n_opt1: int) -> Dict[str, int]:
    return {
        "aich": (n_opt1 >> 29) & 0x07,
        "unicode": (n_opt1 >> 28) & 0x01,
        "udp": (n_opt1 >> 24) & 0x0F,
        "compression": (n_opt1 >> 20) & 0x0F,
        "secureident": (n_opt1 >> 16) & 0x0F,
        "source_exchange": (n_opt1 >> 12) & 0x0F,
        "extended_request": (n_opt1 >> 8) & 0x0F,
        "comments": (n_opt1 >> 4) & 0x0F,
        "preview": n_opt1 & 0x01,
    }


def unpack_misc_options2(n_opt2: int) -> Dict[str, int]:
    return {
        "captcha": (n_opt2 >> 11) & 0x01,
        "source_exchange2": (n_opt2 >> 10) & 0x01,
        "cryptlayer_requires": (n_opt2 >> 9) & 0x01,
        "cryptlayer_requests": (n_opt2 >> 8) & 0x01,
        "cryptlayer_supports": (n_opt2 >> 7) & 0x01,
        "ext_multipacket": (n_opt2 >> 5) & 0x01,
        "large_files": (n_opt2 >> 4) & 0x01,
        "kad": n_opt2 & 0x0F,
    }


@dataclass
class HelloPacket:
    protocol: int
    opcode: int
    is_hello: bool
    userhash: bytes
    client_id: int
    tcp_port: int
    tags: Dict[int, object] = field(default_factory=dict)
    nick_utf8: bytes = b""
    misc_options1: Optional[int] = None
    misc_options2: Optional[int] = None
    software_version: Optional[int] = None
    udp_port: Optional[int] = None
    ed2k_version: Optional[int] = None
    server_ip: int = 0
    server_port: int = 0
    raw: bytes = b""

    @property
    def features1(self) -> Dict[str, int]:
        return unpack_misc_options1(self.misc_options1 or 0)

    @property
    def features2(self) -> Dict[str, int]:
        return unpack_misc_options2(self.misc_options2 or 0)


def strip_tcp_header(packet: bytes) -> Tuple[int, bytes]:
    if len(packet) < 6:
        raise HelloParseError("packet shorter than ED2K TCP header")
    if packet[0] != ED2K_PROTOCOL_EDONKEY:
        raise HelloParseError("protocol byte is not 0xE3")
    length = _u32(packet, 1)
    if length < 1 or len(packet) < 5 + length:
        raise HelloParseError("length prefix does not fit remaining bytes")
    opcode = packet[5]
    body = packet[6 : 5 + length]
    return opcode, body


def parse_hello_tcp(packet: bytes) -> HelloPacket:
    opcode, body = strip_tcp_header(packet)
    if opcode == ED2K_C2C_HELLO:
        is_hello = True
        if not body or body[0] != 0x10:
            raise HelloParseError("Hello body missing legacy 0x10 hash-size prefix")
        payload = body[1:]
    elif opcode == ED2K_C2C_HELLOANSWER:
        is_hello = False
        payload = body
    else:
        raise HelloParseError("opcode is neither Hello (0x01) nor HelloAnswer (0x4C)")

    if len(payload) < 16 + 4 + 2 + 4:
        raise HelloParseError("Hello body truncated before tag count")

    userhash = payload[0:16]
    client_id = _u32(payload, 16)
    tcp_port = _u16(payload, 20)
    n_tags = _u32(payload, 22)
    offset = 26
    tags: Dict[int, object] = {}
    nick = b""

    for _ in range(n_tags):
        if offset + 4 > len(payload):
            raise HelloParseError("truncated tag header")
        tag_type = payload[offset]
        key_len = _u16(payload, offset + 1)
        offset += 3
        if key_len != 1 or offset + 1 > len(payload):
            raise HelloParseError("only classic 1-byte tag keys are supported")
        key = payload[offset]
        offset += 1
        if tag_type == ED2K_TAG_INT:
            if offset + 4 > len(payload):
                raise HelloParseError("truncated integer tag")
            value = _u32(payload, offset)
            offset += 4
            tags[key] = value
        elif tag_type == ED2K_TAG_STRING:
            if offset + 2 > len(payload):
                raise HelloParseError("truncated string tag length")
            str_len = _u16(payload, offset)
            offset += 2
            if offset + str_len > len(payload):
                raise HelloParseError("truncated string tag payload")
            value_b = payload[offset : offset + str_len]
            offset += str_len
            tags[key] = value_b
            if key == ED2K_CT_NAME:
                nick = value_b
        else:
            raise HelloParseError("unexpected classic-tag type in Hello")

    server_ip = 0
    server_port = 0
    if offset + 6 <= len(payload):
        server_ip = _u32(payload, offset)
        server_port = _u16(payload, offset + 4)

    parsed = HelloPacket(
        protocol=ED2K_PROTOCOL_EDONKEY,
        opcode=opcode,
        is_hello=is_hello,
        userhash=userhash,
        client_id=client_id,
        tcp_port=tcp_port,
        tags=tags,
        nick_utf8=nick,
        misc_options1=tags.get(ED2K_CT_FEATUREVERSIONS) if isinstance(tags.get(ED2K_CT_FEATUREVERSIONS), int) else None,
        misc_options2=tags.get(ED2K_CT_MOREFEATUREVERSIONS)
        if isinstance(tags.get(ED2K_CT_MOREFEATUREVERSIONS), int)
        else None,
        software_version=tags.get(ED2K_CT_SOFTWAREVERSION)
        if isinstance(tags.get(ED2K_CT_SOFTWAREVERSION), int)
        else None,
        udp_port=tags.get(ED2K_CT_UDPPORTS) if isinstance(tags.get(ED2K_CT_UDPPORTS), int) else None,
        ed2k_version=tags.get(ED2K_CT_VERSION) if isinstance(tags.get(ED2K_CT_VERSION), int) else None,
        server_ip=server_ip,
        server_port=server_port,
        raw=bytes(packet),
    )
    return parsed


def compare_envy_advertisement(packet: HelloPacket) -> Dict[str, object]:
    """Compare parsed Hello bits to the frozen Envy advertise/implement tables.

    Returns observations. Does not mutate production protocol values.
    """
    f1 = packet.features1
    f2 = packet.features2
    mismatches: List[Dict[str, object]] = []

    checks = {
        "aich": f1["aich"],
        "unicode": f1["unicode"],
        "udp": f1["udp"],
        "compression": f1["compression"],
        "secureident": f1["secureident"],
        "source_exchange": f1["source_exchange"],
        "extended_request": f1["extended_request"],
        "source_exchange2": f2["source_exchange2"],
        "cryptlayer_supports": f2["cryptlayer_supports"],
        "cryptlayer_requests": f2["cryptlayer_requests"],
        "cryptlayer_requires": f2["cryptlayer_requires"],
        "ext_multipacket": f2["ext_multipacket"],
        "large_files": f2["large_files"],
        "kad": f2["kad"],
    }
    for name, actual in checks.items():
        expected = ENVY_ADVERTISED[name]
        if actual != expected:
            mismatches.append(
                {
                    "field": name,
                    "parsed": actual,
                    "expected_advertised": expected,
                    "kind": "advertise_table_mismatch",
                }
            )

    honesty_notes = [dict(item) for item in ENVY_KNOWN_ADVERTISE_DEBT]
    if f1["compression"] == 1 and not ENVY_IMPLEMENTED["compression_send"]:
        honesty_notes.append(
            {
                "field": "compression",
                "parsed": f1["compression"],
                "implemented_send": False,
                "kind": "advertise_vs_implement",
                "issue": 87,
            }
        )
    return {
        "mismatches": mismatches,
        "known_debt": honesty_notes,
        "implemented": dict(ENVY_IMPLEMENTED),
        "advertised_expected": dict(ENVY_ADVERTISED),
        "parsed_features1": f1,
        "parsed_features2": f2,
    }


def normalize_hello_for_commit(packet: HelloPacket) -> HelloPacket:
    """Zero privacy-sensitive / volatile fields before a committed golden."""
    raw = bytearray(packet.raw)
    opcode, body = strip_tcp_header(packet.raw)
    # Body starts at offset 6. Hello has extra 0x10.
    hash_off = 6 + (1 if opcode == ED2K_C2C_HELLO else 0)
    if hash_off + 16 <= len(raw):
        raw[hash_off : hash_off + 16] = b"\x00" * 16
    # Trailing server IP/port: last 6 bytes of the TCP payload after opcode.
    if len(raw) >= 12:
        raw[-6:] = b"\x00" * 6
    return parse_hello_tcp(bytes(raw))
