# SPDX-License-Identifier: AGPL-3.0-or-later
"""Capture finalization and sequence-aware evidence regression coverage."""

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

_INTEROP_ROOT = Path(__file__).resolve().parents[1]
if str(_INTEROP_ROOT) not in sys.path:
    sys.path.insert(0, str(_INTEROP_ROOT))

from envy_interop.config import HarnessConfig
from envy_interop.evidence import (
    EvidenceError, PcapPayloadExtract, extract_frames_for_path,
    extract_from_pcap_via_tshark, reassemble_tcp_segments, require_labels,
)
from envy_interop.golden import load_bytes
from envy_interop.runner import _convert_owned_pcap, _finalize_pcap_lifecycle, run_harness
from envy_interop.scenarios import SCENARIOS, handle_optional_pcap
from tests.harness_mocks import mock_tshark_extraction


class TcpSequenceTests(unittest.TestCase):
    def test_reordering_retransmission_and_partial_overlap(self):
        self.assertEqual(reassemble_tcp_segments([
            (104, b"efgh"), (100, b"abcd"), (102, b"cdef"), (100, b"abcd")
        ]), b"abcdefgh")

    def test_wraparound_and_reordered_wraparound(self):
        for segments in ([(0xFFFFFFFE, b"ab"), (0, b"cd")],
                         [(0, b"cd"), (0xFFFFFFFE, b"ab")]):
            self.assertEqual(reassemble_tcp_segments(segments), b"abcd")

    def test_gaps_conflicts_and_bounds_fail_closed(self):
        for segments in (
            [(0, b"ab"), (3, b"cd")],
            [(0, b"ab"), (1, b"X")],
            [(0, b"ab"), (0, b"ac")],
            [(0, b"a"), (2**31, b"b")],
            [(-1, b"a")], [(2**32, b"a")], [(0, b"")],
            [(0, b"a")] * 65537,
            [(0, b"a" * (8 * 1024 * 1024 + 1))],
        ):
            with self.assertRaises(EvidenceError):
                reassemble_tcp_segments(segments)
        self.assertEqual(reassemble_tcp_segments([]), b"")

    @staticmethod
    def row(seq, payload, source="192.0.2.1", syn=0, stream=0):
        # Equal source/destination ports must still keep directions separate.
        return (
            f"{stream}\t4662\t4662\t{seq}\t{len(payload)}\t{syn}\t"
            f"{source}\t\t{payload.hex()}"
        )

    def extract(self, rows, udp=""):
        with tempfile.TemporaryDirectory() as tmp:
            pcap = Path(tmp) / "synthetic.pcap"
            pcap.write_bytes(b"mock reader input")
            with mock_tshark_extraction(rows, udp) as run:
                result = extract_from_pcap_via_tshark(pcap, ports=[4662])
                self.assertIn("tcp.seq_raw", run.call_args_list[0].args[0])
                self.assertFalse(run.call_args_list[0].kwargs["shell"])
                return result

    def test_extraction_preserves_streams_directions_syn_and_udp(self):
        rows = "\n".join([
            self.row(104, b"ef"), self.row(99, b"abcd", syn=1),
            self.row(100, b"abcd"), self.row(40, b"reverse", source="192.0.2.2"),
            self.row(10, b"other", stream=1),
        ])
        result = self.extract(rows, "10\te4:60\n\t\n10\te4:60\n")
        self.assertEqual(sorted(x[0] for x in result.tcp_by_stream.values()),
                         [b"abcdef", b"other", b"reverse"])
        self.assertEqual(result.udp, [b"\xe4\x60", b"\xe4\x60"])
        self.assertNotIn("192.0.2", repr(result))

    def test_extraction_rejects_truncated_udp_datagrams(self):
        for udp in ("11\te4:60\n", "9\te4:60\n", "x\te4:60\n", "10\tzz\n"):
            with self.subTest(udp=udp), self.assertRaises(EvidenceError):
                self.extract(self.row(1, b"ab"), udp)

    def test_extraction_rejects_declared_tcp_payload_without_hex(self):
        rows = "0\t4662\t4663\t1\t4\t0\t192.0.2.1\t\t"
        with self.assertRaises(EvidenceError):
            self.extract(rows)

    def test_extraction_rejects_declared_udp_payload_without_hex(self):
        with self.assertRaises(EvidenceError):
            self.extract(self.row(1, b"ab"), "12\t\n")

    def test_tcp_export_skips_empty_udp_rows(self):
        udp_row = "\t" * 8
        result = self.extract(self.row(1, b"ab") + "\n" + udp_row, "10\te4:60\n")
        self.assertEqual(list(result.tcp_by_stream.values())[0][0], b"ab")
        self.assertEqual(result.udp, [b"\xe4\x60"])

    def test_extraction_rejects_subheader_udp_length(self):
        with self.assertRaises(EvidenceError):
            self.extract(self.row(1, b"ab"), "7\t\n")

    def test_extraction_rejects_missing_metadata_truncation_and_conflict(self):
        for rows in (
            "0\t4662\t4663\tab",  # Old extractor output had no sequence fields.
            self.row(1, b"ab").replace("\t2\t0\t", "\t3\t0\t"),
            self.row(1, b"ab") + "\n" + self.row(2, b"X"),
            self.row(1, b"ab") + "\n" + self.row(4, b"cd"),
        ):
            with self.assertRaises(EvidenceError):
                self.extract(rows)


class AnchoredFramingTests(unittest.TestCase):
    """Payload bytes of one frame or datagram must never become evidence."""

    TCP = Path("from-pcap-tcp-0000-0000.bin")
    UDP = Path("from-pcap-udp-0000.bin")
    HELLO = load_bytes(_INTEROP_ROOT / "fixtures" / "golden" / "envy-self-hello.json")
    # <NodeID 16><TCP port 2><version 1><tag count 1> (eMule HELLO layout).
    KAD_HELLO = b"\xe4\x11" + bytes(range(16)) + b"\x36\x12\x09\x00"

    @staticmethod
    def frame(protocol, opcode, body):
        return bytes([protocol]) + (len(body) + 1).to_bytes(4, "little") + bytes([opcode]) + body

    def labels(self, path, blob, required):
        hits = extract_frames_for_path(path, blob)
        return [hit.label for hit in hits], require_labels(hits, required)[0]

    def test_valid_stream_and_datagram_still_pass(self):
        stream = self.HELLO + self.frame(0xC5, 0x60, b"")
        self.assertEqual(self.labels(self.TCP, stream, ["hello"]),
                         (["hello", "op_c5_60"], True))
        self.assertEqual(self.labels(self.UDP, self.KAD_HELLO, ["kad_hello_req"]),
                         (["kad_hello_req"], True))

    def test_tcp_payload_is_never_searched_for_frames(self):
        cases = {
            "packed": self.frame(0xD4, 0x40, b"\x00" + self.HELLO),
            "leading": b"\x00" + self.HELLO,
            "truncated": (self.HELLO[:1] + (len(self.HELLO) + 100).to_bytes(4, "little")
                          + self.HELLO[5:6] + self.HELLO),
            "short-tail": self.HELLO[:-1],
        }
        for name, stream in cases.items():
            with self.subTest(name=name):
                labels, ok = self.labels(self.TCP, stream, ["hello"])
                self.assertFalse(ok)
                self.assertNotIn("hello", labels)

    def test_packed_frame_is_skipped_by_size_but_never_clean(self):
        stream = self.frame(0xD4, 0x40, b"\x00" + self.HELLO) + self.HELLO
        hits = extract_frames_for_path(self.TCP, stream)
        self.assertEqual([hit.label for hit in hits], ["op_d4_40", "hello"])
        self.assertTrue(hits[0].details["parse_error"])
        self.assertFalse(require_labels(hits, ["op_d4_40"])[0])

    def test_udp_datagram_header_must_start_the_datagram(self):
        for prefix in (b"\xe5\x11", b"\x9a\x33\x71", b"\xe3", b"\xe4\x77"):
            with self.subTest(prefix=prefix.hex()):
                labels, ok = self.labels(self.UDP, prefix + b"\x00" * 5 + self.KAD_HELLO,
                                         ["kad_hello_req"])
                self.assertEqual((labels, ok), ([], False))


class CaptureLifecycleTests(unittest.TestCase):
    def context(self, root, *, code=0, pre=None, content=b"unvalidated capture"):
        root = Path(root)
        (root / "logs").mkdir()
        pcap = root / "owned.pcap"
        pcap.write_bytes(content)
        owned = MagicMock()
        owned.poll.return_value = pre
        processes = MagicMock()
        processes.terminate_owned.return_value = code
        cfg = HarnessConfig(
            repo_root=Path(__file__).resolve().parents[3],
            live=True,
            dry_run=False,
            enable_pcap=True,
        )
        return SimpleNamespace(cfg=cfg, run_dir=root, logs_dir=root / "logs",
                               pcap_path=pcap, pcap_owned=owned, processes=processes,
                               pcap_stopped=False, pcap_usable=None, pcap_start_error=None)

    def test_unknown_usability_never_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx = self.context(tmp)
            ctx.pcap_stopped = True
            result = handle_optional_pcap(ctx, SCENARIOS["optional_pcap"])
            self.assertEqual(result.result, "SKIP")

    def test_empty_timeout_and_early_failure_cannot_be_converted(self):
        for args in (dict(content=b""), dict(code=None), dict(code=1, pre=1)):
            with self.subTest(args=args), tempfile.TemporaryDirectory() as tmp:
                ctx = self.context(tmp, **args)
                _finalize_pcap_lifecycle(ctx, ctx.cfg)
                self.assertFalse(ctx.pcap_usable)
                with patch("envy_interop.runner.extract_from_pcap_via_tshark") as extract:
                    self.assertIsNone(_convert_owned_pcap(ctx, ctx.cfg))
                    extract.assert_not_called()

    def test_only_successful_nonempty_extraction_establishes_usability(self):
        for outcome, expected in (
            (PcapPayloadExtract({"0-0": [b"validated"]}, []), True),
            (PcapPayloadExtract({}, []), False),
            (EvidenceError("corrupt pcap"), False),
        ):
            with tempfile.TemporaryDirectory() as tmp:
                ctx = self.context(tmp, code=-15)
                _finalize_pcap_lifecycle(ctx, ctx.cfg)
                self.assertTrue(ctx.pcap_stopped)
                self.assertIsNone(ctx.pcap_usable)
                with patch("envy_interop.evidence.find_tshark", return_value="tshark"), \
                        patch("envy_interop.runner.extract_from_pcap_via_tshark") as extract:
                    if isinstance(outcome, Exception):
                        extract.side_effect = outcome
                    else:
                        extract.return_value = outcome
                    _convert_owned_pcap(ctx, ctx.cfg)
                self.assertIs(ctx.pcap_usable, expected)
                self.assertEqual(handle_optional_pcap(ctx, SCENARIOS["optional_pcap"]).result,
                                 "PASS" if expected else "FAIL")

    def test_missing_reader_leaves_usability_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx = self.context(tmp)
            _finalize_pcap_lifecycle(ctx, ctx.cfg)
            with patch("envy_interop.evidence.find_tshark", return_value=None):
                self.assertIsNone(_convert_owned_pcap(ctx, ctx.cfg))
            self.assertIsNone(ctx.pcap_usable)

    def test_runner_finalizes_before_global_cleanup_and_cleans_on_error(self):
        for broken in (False, True):
            with self.subTest(broken=broken), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                cfg = HarnessConfig(repo_root=Path(__file__).resolve().parents[3],
                                    work_dir=root / "work", artifact_dir=root / "artifacts",
                                    live=True, dry_run=False, enable_pcap=True,
                                    scenarios=["optional_pcap"])
                events = []
                manager = MagicMock()
                manager.exit_snapshot.return_value = []
                manager.owned_pids.return_value = []
                manager.terminate_all.side_effect = lambda _: events.append("cleanup")

                def finalize(ctx, config):
                    events.append("finalize")
                    if broken:
                        raise RuntimeError("synthetic finalization failure")

                def convert(ctx, config):
                    events.append("convert")

                with patch("envy_interop.runner.ProcessManager", return_value=manager), \
                        patch("envy_interop.runner.find_capture_tool", return_value="tshark"), \
                        patch("envy_interop.runner.start_capture", return_value=MagicMock()), \
                        patch("envy_interop.runner._finalize_pcap_lifecycle", side_effect=finalize), \
                        patch("envy_interop.runner._convert_owned_pcap", side_effect=convert):
                    if broken:
                        with self.assertRaises(RuntimeError):
                            run_harness(cfg)
                    else:
                        run_harness(cfg)
                self.assertEqual(events, ["finalize", "cleanup"] if broken else
                                 ["finalize", "convert", "cleanup"])
