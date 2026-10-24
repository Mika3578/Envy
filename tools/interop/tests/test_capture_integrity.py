# SPDX-License-Identifier: AGPL-3.0-or-later
"""Capture finalization and sequence-aware evidence regression coverage."""

import subprocess
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
    EvidenceError, PcapPayloadExtract, extract_from_pcap_via_tshark,
    reassemble_tcp_segments,
)
from envy_interop.runner import _convert_owned_pcap, _finalize_pcap_lifecycle, run_harness
from envy_interop.scenarios import SCENARIOS, handle_optional_pcap


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
            outputs = [subprocess.CompletedProcess([], 0, stdout=rows, stderr=""),
                       subprocess.CompletedProcess([], 0, stdout=udp, stderr="")]
            with patch("envy_interop.evidence.find_tshark", return_value="tshark"), \
                    patch("envy_interop.evidence.subprocess.run", side_effect=outputs) as run:
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
        result = self.extract(rows, "e4:60\ne4:60\n")
        self.assertEqual(sorted(x[0] for x in result.tcp_by_stream.values()),
                         [b"abcdef", b"other", b"reverse"])
        self.assertEqual(result.udp, [b"\xe4\x60", b"\xe4\x60"])
        self.assertNotIn("192.0.2", repr(result))

    def test_extraction_rejects_missing_metadata_truncation_and_conflict(self):
        for rows in (
            "0\t4662\t4663\tab",  # Old extractor output had no sequence fields.
            self.row(1, b"ab").replace("\t2\t0\t", "\t3\t0\t"),
            self.row(1, b"ab") + "\n" + self.row(2, b"X"),
            self.row(1, b"ab") + "\n" + self.row(4, b"cd"),
        ):
            with self.assertRaises(EvidenceError):
                self.extract(rows)


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
