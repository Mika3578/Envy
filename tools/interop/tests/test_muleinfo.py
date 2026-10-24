"""MuleInfo evidence framing, independently of production protocol code."""

from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from envy_interop.config import HarnessConfig
from envy_interop.evidence import extract_ed2k_frames, require_labels
from envy_interop.hello import HelloParseError, parse_emule_info_tcp
from envy_interop.runner import run_harness


def frame(body: bytes, opcode: int = 1) -> bytes:
    return b"\xc5" + struct.pack("<I", len(body) + 1) + bytes([opcode]) + body


class MuleInfoEvidenceTests(unittest.TestCase):
    # Classic INT tag, one-byte name ET_COMPRESSION, uint32 value 1.
    int_tag = bytes.fromhex("0301002001000000")
    string_tag = bytes.fromhex("02010055") + struct.pack("<H", 7) + b"private"

    def test_reference_layout_with_integer_and_unknown_string_tag(self) -> None:
        body = b"\x50\x01" + struct.pack("<I", 2) + self.int_tag + self.string_tag
        for opcode in (1, 2):
            with self.subTest(opcode=opcode):
                info = parse_emule_info_tcp(frame(body, opcode))
                self.assertEqual(info["emule_client_version"], 0x50)
                self.assertEqual(info["emule_protocol_version"], 1)
                self.assertEqual(info["tag_keys"], [0x20, 0x55])
                self.assertEqual(info["tags"], {0x20: 1})
                self.assertNotIn("private", repr(info))

    def test_each_truncation_fails_even_with_consistent_tcp_length(self) -> None:
        body = b"\x50\x01" + struct.pack("<I", 2) + self.int_tag + self.string_tag
        valid = frame(body)
        for cut in range(len(valid)):
            with self.subTest(tcp_cut=cut):
                with self.assertRaises(HelloParseError):
                    parse_emule_info_tcp(valid[:cut])
        for cut in range(len(body)):
            with self.subTest(body_cut=cut):
                with self.assertRaises(HelloParseError):
                    parse_emule_info_tcp(frame(body[:cut]))

    def test_count_limits_and_trailing_bytes(self) -> None:
        for count in (1, 65, 0xFFFFFFFF):
            with self.subTest(count=count):
                with self.assertRaises(HelloParseError):
                    parse_emule_info_tcp(frame(b"\x50\x01" + struct.pack("<I", count)))
        for count in (0, 64):
            info = parse_emule_info_tcp(frame(
                b"\x50\x01" + struct.pack("<I", count) + self.int_tag * count
            ))
            self.assertEqual(info["emule_protocol_version"], 1)
        with self.assertRaises(HelloParseError):
            parse_emule_info_tcp(frame(b"\x50\x01\0\0\0\0\xff"))
        with self.assertRaises(HelloParseError):
            parse_emule_info_tcp(frame(b"\x50\x01\0\0\0\0") + b"\0")

    def test_unsupported_encodings_never_become_parse_clean(self) -> None:
        for body in (
            b"\x50\xff\0\0\0\0",  # aMule OSInfo is outside this parser's scope.
            b"\x50\x01\x01\0\0\0\x83\x20\x01\0\0\0",  # compact tag
            b"\x50\x01\x01\0\0\0\x03\x02\0xx\x01\0\0\0",  # named tag
            b"\x50\x01\x01\0\0\0\x99\x01\0\x20",  # unknown type
        ):
            with self.subTest(body=body.hex()):
                hits = extract_ed2k_frames(frame(body))
                self.assertEqual(len(hits), 1)
                self.assertIn("parse_error", hits[0].details)
                self.assertFalse(require_labels(hits, ["muleinfo"])[0])

    def test_runner_rejects_truncated_tags_instead_of_passing(self) -> None:
        repo = Path(__file__).resolve().parents[3]
        for body in (
            b"\x01\0\0\0\0",  # Old self-test omitted the client-version byte.
            b"\x50\x01\x01\0\0\0",  # Declared tag absent.
            b"\x50\x01\x01\0\0\0" + self.int_tag[:-1],
        ):
            with self.subTest(body=body.hex()), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                evidence = root / "muleinfo.bin"
                evidence.write_bytes(frame(body))
                cfg = HarnessConfig(
                    repo_root=repo, artifact_dir=root / "artifacts", work_dir=root / "work",
                    dry_run=True, live=False, packet_evidence=evidence, scenarios=["muleinfo"],
                )
                report = run_harness(cfg)
                self.assertEqual(report["scenarios"][0]["result"], "FAIL")
