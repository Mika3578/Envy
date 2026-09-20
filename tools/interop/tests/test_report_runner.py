"""Report, golden Hello, fixtures, dry-run runner, state classification."""

from __future__ import annotations

import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

_INTEROP_ROOT = Path(__file__).resolve().parents[1]
if str(_INTEROP_ROOT) not in sys.path:
    sys.path.insert(0, str(_INTEROP_ROOT))


from envy_interop.config import ConfigError, HarnessConfig
from envy_interop.constants import (
    ENVY_CAPABILITY_MATRIX,
    ENVY_IMPLEMENTED,
    ENVY_KNOWN_ADVERTISE_DEBT,
    EvidenceState,
    HarnessState,
    ProductionState,
    Result,
)
from envy_interop.evidence import EvidenceError, extract_ed2k_frames, require_labels
from envy_interop.fixtures import build_payload, spec_for
from envy_interop.golden import GoldenError, ingest_hello, load_golden_json, parse_hex_dump
from envy_interop.hello import HelloParseError, hello_evidence, parse_emule_info_tcp, parse_hello_tcp
from envy_interop.md4 import md4_hex
from envy_interop.pass_criteria import criteria_for
from envy_interop.report import ReportError, empty_payload, utc_now, validate_report, write_json_report
from envy_interop.runner import run_harness
from envy_interop.scenarios import CURRENT_IDS, DEFERRED_IDS, FUTURE_IDS, expand_selection


REPO = Path(__file__).resolve().parents[3]


class Md4AndFixtureTests(unittest.TestCase):
    def test_rfc1320_vectors(self) -> None:
        self.assertEqual(md4_hex(b""), "31d6cfe0d16ae931b73c59d7e0c089c0")
        self.assertEqual(md4_hex(b"a"), "bde52cb31de33e46245e05fbdbd6fb24")
        self.assertEqual(md4_hex(b"abc"), "a448017aaf21d8525fc10ae87aa6729d")

    def test_fixture_reproducible(self) -> None:
        a = spec_for(build_payload())
        b = spec_for(build_payload())
        self.assertEqual(a.size, 65536)
        self.assertEqual(a.ed2k_hex, b.ed2k_hex)
        self.assertEqual(a.sha256_hex, b.sha256_hex)


class CapabilityTruthTests(unittest.TestCase):
    def test_compression_send_implemented(self) -> None:
        self.assertTrue(ENVY_IMPLEMENTED["compression_send"])
        self.assertEqual(ENVY_KNOWN_ADVERTISE_DEBT, ())
        row = ENVY_CAPABILITY_MATRIX["compression_send"]
        self.assertEqual(row["production"], ProductionState.IMPLEMENTED.value)
        self.assertEqual(row["harness"], HarnessState.EVIDENCE_HOOKS.value)
        self.assertEqual(row["evidence"], EvidenceState.UNVERIFIED.value)

    def test_buddy_not_marked_implemented(self) -> None:
        self.assertFalse(ENVY_IMPLEMENTED["buddy"])
        self.assertEqual(
            ENVY_CAPABILITY_MATRIX["buddy"]["production"],
            ProductionState.NOT_IMPLEMENTED.value,
        )

    def test_stale_compression_debt_absent(self) -> None:
        for item in ENVY_KNOWN_ADVERTISE_DEBT:
            self.assertNotEqual(item.get("implemented_send"), False)


class HelloGoldenTests(unittest.TestCase):
    def test_envy_self_hello(self) -> None:
        path = REPO / "tools/interop/fixtures/golden/envy-self-hello.json"
        meta = load_golden_json(path)
        parsed = parse_hello_tcp(bytes.fromhex(meta["tcp_frame_hex"]))
        self.assertEqual(parsed.opcode, 0x01)
        self.assertEqual(parsed.client_id, 0x11223344)
        self.assertEqual(parsed.tcp_port, 4662)
        self.assertEqual(parsed.features1["aich"], 0)
        self.assertEqual(parsed.features1["secureident"], 0)
        self.assertEqual(parsed.features1["compression"], 1)
        self.assertEqual(parsed.features1["source_exchange"], 2)
        self.assertEqual(parsed.features1["unicode"], 1)
        self.assertEqual(parsed.features2["large_files"], 1)
        self.assertEqual(parsed.features2["source_exchange2"], 1)
        self.assertEqual(parsed.features2["ext_multipacket"], 0)
        self.assertEqual(parsed.features2["cryptlayer_supports"], 0)
        self.assertEqual(parsed.features2["kad"], 0)
        evidence = hello_evidence(parsed)
        self.assertEqual(evidence["protocol"], 0xE3)
        self.assertEqual(evidence["opcode"], 0x01)
        self.assertEqual(evidence["userhash_len"], 16)
        self.assertEqual(evidence["compression_version"], 1)
        self.assertEqual(evidence["source_exchange_version"], 2)
        self.assertEqual(evidence["extended_request_version"], 2)
        self.assertEqual(evidence["unicode"], 1)
        self.assertEqual(evidence["large_files"], 1)
        self.assertEqual(evidence["aich"], 0)
        self.assertEqual(evidence["secureident"], 0)
        self.assertEqual(evidence["cryptlayer_supports"], 0)
        self.assertEqual(evidence["ext_multipacket"], 0)
        self.assertEqual(evidence["kad_version_nibble"], 0)
        self.assertNotIn("nick", evidence)

    def test_envy_self_helloanswer(self) -> None:
        path = REPO / "tools/interop/fixtures/golden/envy-self-helloanswer.json"
        meta = load_golden_json(path)
        parsed = parse_hello_tcp(bytes.fromhex(meta["tcp_frame_hex"]))
        self.assertEqual(parsed.opcode, 0x4C)
        self.assertFalse(parsed.is_hello)
        self.assertEqual(parsed.features1["extended_request"], 2)

    def test_malformed_hello_too_short(self) -> None:
        with self.assertRaises(HelloParseError):
            parse_hello_tcp(b"\x00\x01")

    def test_malformed_hello_truncated_frame(self) -> None:
        with self.assertRaises(HelloParseError):
            parse_hello_tcp(bytes.fromhex("e301000000014c"))

    def test_muleinfo_minimal_frame(self) -> None:
        frame = bytes.fromhex("c506000000010100000000")
        info = parse_emule_info_tcp(frame)
        self.assertEqual(info["protocol"], 0xC5)
        self.assertEqual(info["opcode"], 0x01)
        self.assertEqual(info["emule_protocol_version"], 1)

    def test_muleinfo_rejects_hello_protocol(self) -> None:
        hello = REPO / "tools/interop/fixtures/golden/envy-self-hello.json"
        raw = bytes.fromhex(json.loads(hello.read_text(encoding="utf-8"))["tcp_frame_hex"])
        with self.assertRaises(HelloParseError):
            parse_emule_info_tcp(raw)

    def test_hex_dump_parser(self) -> None:
        raw = parse_hex_dump("# comment\ne3 54\n")
        self.assertEqual(raw, bytes.fromhex("e354"))

    def test_emule_slot_not_invented(self) -> None:
        slot = REPO / "tools/interop/fixtures/golden/emule-community"
        jsons = list(slot.glob("*.json"))
        self.assertEqual(jsons, [])

    def test_ingest_writes_candidate(self) -> None:
        src = REPO / "tools/interop/fixtures/golden/envy-self-hello.json"
        with tempfile.TemporaryDirectory() as tmp:
            meta = ingest_hello(
                src,
                Path(tmp),
                reference_client="envy-self",
                reference_version="test",
                direction="send",
            )
            self.assertTrue((Path(tmp) / "hello-candidate.json").is_file())
            parsed = parse_hello_tcp(bytes.fromhex(meta["tcp_frame_hex"]))
            self.assertEqual(parsed.userhash, b"\x00" * 16)


class EvidenceExtractorTests(unittest.TestCase):
    def test_extract_compressedpart_header(self) -> None:
        # proto C5, size=25, opcode 0x40, body = hash16 + start4 + compressed_total4
        body = b"\x11" * 16 + struct.pack("<I", 0) + struct.pack("<I", 8) + b"\x00" * 8
        frame = bytes([0xC5]) + struct.pack("<I", 1 + len(body)) + bytes([0x40]) + body
        hits = extract_ed2k_frames(frame)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].label, "compressedpart")
        ok, reason = require_labels(hits, ["compressedpart"])
        self.assertTrue(ok, reason)

    def test_publicip_answer_wrong_size_fails_closed(self) -> None:
        body = b"\x01\x02\x03"
        frame = bytes([0xC5]) + struct.pack("<I", 1 + len(body)) + bytes([0x98]) + body
        hits = extract_ed2k_frames(frame)
        ok, reason = require_labels(hits, ["publicip_answer"])
        self.assertFalse(ok)
        self.assertIn("4 bytes", reason)

    def test_truncated_blob_no_crash(self) -> None:
        hits = extract_ed2k_frames(b"\xc5\xff\xff")
        self.assertEqual(hits, [])

    def test_truncated_size_does_not_abort_later_frames(self) -> None:
        import struct

        # Fake truncated C5 frame (size claims more bytes than remain), then a real muleinfo.
        truncated = bytes([0xC5]) + struct.pack("<I", 1000) + bytes([0x01])
        mule_body = b"\x01\x00\x00\x00\x00"
        mule = bytes([0xC5]) + struct.pack("<I", 1 + len(mule_body)) + bytes([0x01]) + mule_body
        hits = extract_ed2k_frames(truncated + mule)
        self.assertTrue(any(h.label == "muleinfo" for h in hits))


class ReportTests(unittest.TestCase):
    def test_malformed_schema_version_rejected(self) -> None:
        with self.assertRaises(ReportError):
            validate_report({"schema_version": "nope"})

    def test_malformed_scenario_result_rejected(self) -> None:
        with self.assertRaises(ReportError):
            validate_report(
                {
                    "schema_version": 2,
                    "timestamp": "t",
                    "harness_version": "1",
                    "envy_revision": "x",
                    "mode": "dry-run",
                    "scenarios": [{"id": "x", "result": "WHATEVER"}],
                }
            )

    def test_write_json(self) -> None:
        payload = empty_payload(
            timestamp=utc_now(),
            envy_revision="deadbeef",
            mode="dry-run",
            reference_client="none",
            reference_version="",
            artifact_dir="artifacts/run",
            network_class="none",
        )
        payload["scenarios"] = [
            {
                "id": "demo",
                "result": Result.SKIP.value,
                "duration_ms": 1,
                "reason": "n/a",
                "production_state": "implemented",
                "harness_state": "evidence_hooks",
                "evidence_state": "unverified",
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "run-summary.json"
            write_json_report(path, payload)
            loaded = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["schema_version"], 2)


class RunnerDryRunTests(unittest.TestCase):
    def test_dry_run_skip_and_not_implemented(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = HarnessConfig(
                repo_root=REPO,
                artifact_dir=Path(tmp) / "artifacts",
                work_dir=Path(tmp) / "work",
                dry_run=True,
                live=False,
                scenarios=["all"],
            )
            payload = run_harness(cfg)
            by_id = {item["id"]: item for item in payload["scenarios"]}
            self.assertEqual(by_id["harness_self_check"]["result"], "PASS")
            self.assertEqual(by_id["envy_capability_honesty"]["result"], "PASS")
            self.assertEqual(by_id["golden_envy_hello_parse"]["result"], "PASS")
            self.assertEqual(by_id["fixture_generation"]["result"], "PASS")
            self.assertEqual(by_id["hello_capture_import"]["result"], "SKIP")
            self.assertEqual(by_id["envy_startup"]["result"], "SKIP")
            self.assertEqual(by_id["reference_startup"]["result"], "SKIP")
            self.assertEqual(by_id["hello"]["result"], "SKIP")
            # Implemented-but-unverified must not look like production NOT_IMPLEMENTED
            self.assertEqual(by_id["compressed_transfer_envy_to_ref"]["result"], "SKIP")
            self.assertEqual(
                by_id["compressed_transfer_envy_to_ref"]["production_state"], "implemented"
            )
            self.assertEqual(
                by_id["compressed_transfer_envy_to_ref"]["harness_state"], "evidence_hooks"
            )
            self.assertEqual(by_id["kad_bootstrap"]["result"], "SKIP")
            self.assertEqual(by_id["kad_nodes_dat_local"]["result"], "PASS")
            self.assertEqual(by_id["lowid_buddy"]["result"], "NOT_IMPLEMENTED")
            self.assertEqual(by_id["lowid_buddy"]["production_state"], "not_implemented")
            self.assertEqual(by_id["kad_udp_firewall"]["result"], "NOT_IMPLEMENTED")
            self.assertIn("pass_criteria", by_id["hello"])
            self.assertTrue(criteria_for("hello"))
            runs = list((Path(tmp) / "artifacts").glob("run-*"))
            self.assertEqual(len(runs), 1)
            self.assertTrue((runs[0] / "run-summary.json").is_file())
            self.assertTrue((runs[0] / "run-summary.md").is_file())
            md = (runs[0] / "run-summary.md").read_text(encoding="utf-8")
            self.assertIn("pending", md.lower())
            self.assertIn("#160", md)
            summary = json.loads((runs[0] / "run-summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["schema_version"], 2)

    def test_dry_run_phase1_no_binaries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = HarnessConfig(
                repo_root=REPO,
                artifact_dir=Path(tmp) / "artifacts",
                work_dir=Path(tmp) / "work",
                dry_run=True,
                live=False,
                scenarios=["phase1"],
            )
            payload = run_harness(cfg)
            self.assertTrue(payload["scenarios"])
            self.assertFalse(any(item["result"] == "FAIL" for item in payload["scenarios"]))

    def test_packet_evidence_can_pass_without_live(self) -> None:
        hello = REPO / "tools/interop/fixtures/golden/envy-self-hello.json"
        with tempfile.TemporaryDirectory() as tmp:
            cfg = HarnessConfig(
                repo_root=REPO,
                artifact_dir=Path(tmp) / "artifacts",
                work_dir=Path(tmp) / "work",
                dry_run=True,
                live=False,
                hello_capture=hello,
                scenarios=["hello", "hello_capture_import"],
            )
            payload = run_harness(cfg)
            by_id = {item["id"]: item for item in payload["scenarios"]}
            self.assertEqual(by_id["hello"]["result"], "PASS")
            self.assertEqual(by_id["hello_capture_import"]["result"], "PASS")

    def test_multi_frame_blob_selects_matching_frame(self) -> None:
        """Regression: evidence PASS must not assume a single frame at offset 0."""
        import struct

        hello_path = REPO / "tools/interop/fixtures/golden/envy-self-hello.json"
        hello_frame = bytes.fromhex(json.loads(hello_path.read_text(encoding="utf-8"))["tcp_frame_hex"])
        answer_path = REPO / "tools/interop/fixtures/golden/envy-self-helloanswer.json"
        answer_frame = bytes.fromhex(json.loads(answer_path.read_text(encoding="utf-8"))["tcp_frame_hex"])
        mule_body = b"\x01\x00\x00\x00\x00"
        mule_frame = bytes([0xC5]) + struct.pack("<I", 1 + len(mule_body)) + bytes([0x01]) + mule_body
        # Leading noise + concatenated frames (HelloAnswer first, then Hello, then MuleInfo).
        blob = b"\x00NOISE\xff" + answer_frame + hello_frame + mule_frame
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "multi.bin"
            evidence.write_bytes(blob)
            cfg = HarnessConfig(
                repo_root=REPO,
                artifact_dir=Path(tmp) / "artifacts",
                work_dir=Path(tmp) / "work",
                dry_run=True,
                live=False,
                packet_evidence=evidence,
                scenarios=["hello", "hello_answer", "muleinfo"],
            )
            payload = run_harness(cfg)
            by_id = {item["id"]: item for item in payload["scenarios"]}
            self.assertEqual(by_id["hello"]["result"], "PASS", by_id["hello"].get("reason"))
            self.assertEqual(by_id["hello_answer"]["result"], "PASS", by_id["hello_answer"].get("reason"))
            self.assertEqual(by_id["muleinfo"]["result"], "PASS", by_id["muleinfo"].get("reason"))

    def test_expand_aliases(self) -> None:
        self.assertIn("compressed_transfer_envy_to_ref", expand_selection(["current"]))
        self.assertIn("lowid_buddy", expand_selection(["deferred"]))
        self.assertTrue(set(DEFERRED_IDS).issubset(set(expand_selection(["all"]))))
        self.assertTrue(CURRENT_IDS)
        self.assertTrue(FUTURE_IDS)


if __name__ == "__main__":
    unittest.main()
