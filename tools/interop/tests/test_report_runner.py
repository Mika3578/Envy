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
from envy_interop.evidence import (
    EvidenceError,
    collect_hits_from_paths,
    extract_ed2k_frames,
    extract_frames,
    extract_kad_udp_frames,
    require_any_label_group,
    require_labels,
)
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

    def test_callback_body_must_be_exactly_38_bytes(self) -> None:
        short = bytes([0xC5]) + struct.pack("<I", 1 + 37) + bytes([0x99]) + (b"\x00" * 37)
        long = bytes([0xC5]) + struct.pack("<I", 1 + 39) + bytes([0x99]) + (b"\x00" * 39)
        exact = bytes([0xC5]) + struct.pack("<I", 1 + 38) + bytes([0x99]) + (b"\x00" * 38)
        self.assertFalse(require_labels(extract_ed2k_frames(short), ["callback"])[0])
        self.assertFalse(require_labels(extract_ed2k_frames(long), ["callback"])[0])
        ok, reason = require_labels(extract_ed2k_frames(exact), ["callback"])
        self.assertTrue(ok, reason)

    def test_compressedpart_payload_length_must_match(self) -> None:
        # Declared compressed_total=100 but only 8 payload bytes → fail closed.
        short = b"\x11" * 16 + struct.pack("<I", 0) + struct.pack("<I", 100) + b"\x00" * 8
        frame = bytes([0xC5]) + struct.pack("<I", 1 + len(short)) + bytes([0x40]) + short
        self.assertFalse(require_labels(extract_ed2k_frames(frame), ["compressedpart"])[0])
        # Trailing junk beyond declared length → fail closed.
        long = b"\x11" * 16 + struct.pack("<I", 0) + struct.pack("<I", 4) + b"\x00" * 8
        frame = bytes([0xC5]) + struct.pack("<I", 1 + len(long)) + bytes([0x40]) + long
        self.assertFalse(require_labels(extract_ed2k_frames(frame), ["compressedpart"])[0])

    def test_publicip_answer_omits_raw_ipv4(self) -> None:
        body = b"\x0a\x00\x00\x01"
        frame = bytes([0xC5]) + struct.pack("<I", 1 + len(body)) + bytes([0x98]) + body
        hits = extract_ed2k_frames(frame)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].label, "publicip_answer")
        self.assertTrue(hits[0].details.get("ipv4_present"))
        self.assertNotIn("ipv4_le", hits[0].details)
        dumped = str(hits[0].details)
        self.assertNotIn("167772170", dumped)  # would be LE int of 10.0.0.1

    def test_kad_udp_search_res_opcode_3b(self) -> None:
        # Production inbound / eMule: <SenderID 16><TargetID 16><Count 2 LE>
        body = (b"\x11" * 16) + (b"\x22" * 16) + struct.pack("<H", 0)
        datagram = bytes([0xE4, 0x3B]) + body
        hits = extract_kad_udp_frames(datagram)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].label, "kad_search_res")
        self.assertEqual(hits[0].opcode, 0x3B)
        self.assertEqual(hits[0].details.get("layout"), "sender_target_count2")
        self.assertEqual(hits[0].details.get("result_count"), 0)
        self.assertNotIn("parse_error", hits[0].details)
        # Envy outbound legacy: <Hash 16><Count 1>
        legacy = bytes([0xE4, 0x3B]) + (b"\x11" * 16) + bytes([0])
        legacy_hits = extract_kad_udp_frames(legacy)
        self.assertEqual(legacy_hits[0].details.get("layout"), "envy_outbound_hash_count1")
        self.assertTrue(require_labels(legacy_hits, ["kad_search_res"])[0])
        # Too short for either layout.
        short = bytes([0xE4, 0x3B]) + (b"\x11" * 15)
        short_hits = extract_kad_udp_frames(short)
        self.assertTrue(short_hits[0].details.get("parse_error"))
        self.assertFalse(require_labels(short_hits, ["kad_search_res"])[0])

    def test_kad_udp_not_confused_with_c5_tcp(self) -> None:
        # Old bug: SEARCH_RES 0x35 on C5 would mislabel SEARCH_NOTES as kad_search_res.
        body = b"\x00" * 4
        fake = bytes([0xC5]) + struct.pack("<I", 1 + len(body)) + bytes([0x35]) + body
        hits = extract_frames(fake)
        self.assertFalse(any(h.label == "kad_search_res" for h in hits))

    def test_kad_firewalled_res_omits_raw_ipv4(self) -> None:
        body = b"\xc0\xa8\x00\x01"
        datagram = bytes([0xE4, 0x58]) + body
        hits = extract_kad_udp_frames(datagram)
        self.assertEqual(hits[0].label, "kad_firewalled_res")
        self.assertTrue(hits[0].details.get("ipv4_present"))
        self.assertNotIn("ipv4_le", hits[0].details)

    def test_kad_search_source_and_firewall_labels(self) -> None:
        req = bytes([0xE4, 0x34]) + (b"\xaa" * 16) + struct.pack("<Q", 100)
        fw_req = bytes([0xE4, 0x50]) + struct.pack("<H", 4662)
        fw_ack = bytes([0xE4, 0x59])
        blob = req + fw_req + fw_ack
        hits = extract_kad_udp_frames(blob)
        labels = {h.label for h in hits}
        self.assertEqual(
            labels, {"kad_search_source_req", "kad_firewalled_req", "kad_firewalled_ack"}
        )

    def test_kad_hello_ping_find_node_opcodes(self) -> None:
        # Production HELLO is 0x11/0x19 — Bootstrap 0x01/0x09 must not match.
        # Request and response keep distinct labels.
        hello_req = bytes([0xE4, 0x11]) + (b"\x01" * 16) + bytes([0])  # NodeID + empty TagList
        hello_res = bytes([0xE4, 0x19]) + (b"\x02" * 16) + bytes([0])
        ping = bytes([0xE4, 0x60, 0x00])  # tag count
        pong = bytes([0xE4, 0x61, 0x00])
        find = bytes([0xE4, 0x21]) + (b"\x03" * 16) + bytes([0x02, 0x00])
        find_res = bytes([0xE4, 0x29]) + (b"\x03" * 16) + bytes([0x02, 0x00])
        bootstrap = bytes([0xE4, 0x01]) + (b"\x04" * 16)
        hits = extract_kad_udp_frames(
            hello_req + hello_res + ping + pong + find + find_res + bootstrap
        )
        labels = {h.label for h in hits}
        self.assertEqual(
            labels,
            {
                "kad_hello_req",
                "kad_hello_res",
                "kad_ping",
                "kad_pong",
                "kad_find_node_req",
                "kad_find_node_res",
            },
        )
        self.assertTrue(all(h.opcode != 0x01 for h in hits))
        self.assertTrue(any(h.opcode == 0x11 for h in hits))
        self.assertTrue(any(h.opcode == 0x19 for h in hits))
        self.assertTrue(all(not h.details.get("parse_error") for h in hits))
        self.assertTrue(require_labels(hits, ["kad_hello_req", "kad_hello_res"])[0])
        self.assertFalse(require_labels(hits[:1], ["kad_hello_req", "kad_hello_res"])[0])

    def test_kad_hello_empty_body_fails_closed(self) -> None:
        bare = bytes([0xE4, 0x11])  # no NodeID
        hits = extract_kad_udp_frames(bare)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].label, "kad_hello_req")
        self.assertIn("parse_error", hits[0].details)
        ok, _ = require_labels(hits, ["kad_hello_req"])
        self.assertFalse(ok)

    def test_kad_hit_inside_tcp_frame_excluded(self) -> None:
        # Craft an ED2K TCP frame whose body contains E4 11 … bytes.
        kad_like = bytes([0xE4, 0x11]) + (b"\xaa" * 16) + bytes([0])
        body = b"noise" + kad_like + b"tail"
        tcp = bytes([0xE3]) + struct.pack("<I", 1 + len(body)) + bytes([0x01]) + body
        hits = extract_frames(tcp)
        self.assertFalse(any(h.label == "kad_hello_req" for h in hits))

    def test_ingest_sanitizes_source_name(self) -> None:
        from envy_interop.evidence import ingest_packet_dump, safe_evidence_source_name

        self.assertEqual(
            safe_evidence_source_name(r"C:\Users\alice\share name dump.bin"),
            "packet-evidence.bin",
        )
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "alice-home-secret.bin"
            # Minimal valid Kad HELLO so ingest succeeds.
            src.write_bytes(bytes([0xE4, 0x11]) + (b"\x01" * 16) + bytes([0]))
            dest = Path(tmp) / "out"
            summary = ingest_packet_dump(src, dest, required_labels=["kad_hello_req"])
            self.assertEqual(summary["source_name"], "packet-evidence.bin")
            dumped = (dest / "packet-evidence.json").read_text(encoding="utf-8")
            self.assertNotIn("alice", dumped)
            self.assertNotIn("secret", dumped)

    def test_cross_file_label_aggregation(self) -> None:
        """Hello req and res in separate files must satisfy kad_hello together."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.bin").write_bytes(
                bytes([0xE4, 0x11]) + (b"\x01" * 16) + bytes([0])
            )
            (root / "b.bin").write_bytes(
                bytes([0xE4, 0x19]) + (b"\x02" * 16) + bytes([0])
            )
            hits = collect_hits_from_paths([root / "a.bin", root / "b.bin"])
            ok, reason, matched = require_any_label_group(
                hits, [("kad_hello_req", "kad_hello_res")]
            )
            self.assertTrue(ok, reason)
            self.assertEqual(matched, ("kad_hello_req", "kad_hello_res"))

    def test_sourceex2_alternative_group(self) -> None:
        # Minimal SourceEx2 request/answer frames (eMule proto 0xC5).
        def frame(opcode: int, body: bytes) -> bytes:
            return bytes([0xC5]) + struct.pack("<I", 1 + len(body)) + bytes([opcode]) + body

        blob = frame(0x83, b"\x00" * 16) + frame(0x84, b"\x00" * 16)
        hits = extract_ed2k_frames(blob)
        ok, _, matched = require_any_label_group(
            hits,
            (
                ("sourceex_req", "sourceex_ans"),
                ("sourceex2_req", "sourceex2_ans"),
            ),
        )
        self.assertTrue(ok)
        self.assertEqual(matched, ("sourceex2_req", "sourceex2_ans"))

    def test_tcp_segment_reassembly_across_files(self) -> None:
        """ED2K frame split across two TCP payload files still matches."""
        hello_path = REPO / "tools/interop/fixtures/golden/envy-self-hello.json"
        frame = bytes.fromhex(
            json.loads(hello_path.read_text(encoding="utf-8"))["tcp_frame_hex"]
        )
        mid = len(frame) // 2
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "from-pcap-0000.bin").write_bytes(frame[:mid])
            (root / "from-pcap-0001.bin").write_bytes(frame[mid:])
            # Per-file extract misses; concat TCP path must recover.
            per = extract_frames((root / "from-pcap-0000.bin").read_bytes())
            self.assertFalse(any(h.label == "hello" for h in per))
            hits = collect_hits_from_paths(
                [root / "from-pcap-0000.bin", root / "from-pcap-0001.bin"]
            )
            self.assertTrue(any(h.label == "hello" for h in hits))


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
            # Documentation-only note must not PASS (Copilot honesty finding).
            self.assertEqual(by_id["kad_nodes_dat_local"]["result"], "SKIP")
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
