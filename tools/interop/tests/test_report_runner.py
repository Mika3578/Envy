"""Report, golden Hello, fixtures, dry-run runner, SKIP/NOT_IMPLEMENTED."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

_INTEROP_ROOT = Path(__file__).resolve().parents[1]
if str(_INTEROP_ROOT) not in sys.path:
    sys.path.insert(0, str(_INTEROP_ROOT))


from envy_interop.config import ConfigError, HarnessConfig
from envy_interop.constants import Result
from envy_interop.fixtures import build_payload, spec_for
from envy_interop.golden import GoldenError, ingest_hello, load_golden_json, parse_hex_dump
from envy_interop.hello import HelloParseError, parse_hello_tcp
from envy_interop.md4 import md4_hex
from envy_interop.report import ReportError, empty_payload, utc_now, validate_report, write_json_report
from envy_interop.runner import run_harness
from envy_interop.scenarios import FUTURE_IDS, expand_selection


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

    def test_envy_self_helloanswer(self) -> None:
        path = REPO / "tools/interop/fixtures/golden/envy-self-helloanswer.json"
        meta = load_golden_json(path)
        parsed = parse_hello_tcp(bytes.fromhex(meta["tcp_frame_hex"]))
        self.assertEqual(parsed.opcode, 0x4C)
        self.assertFalse(parsed.is_hello)
        self.assertEqual(parsed.features1["extended_request"], 2)

    def test_malformed_hello_rejected(self) -> None:
        with self.assertRaises(HelloParseError):
            parse_hello_tcp(b"\x00\x01")
        with self.assertRaises(HelloParseError):
            parse_hello_tcp(bytes.fromhex("e301000000014c"))

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


class ReportTests(unittest.TestCase):
    def test_malformed_metadata_rejected(self) -> None:
        with self.assertRaises(ReportError):
            validate_report({"schema_version": "nope"})
        with self.assertRaises(ReportError):
            validate_report(
                {
                    "schema_version": 1,
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
            artifact_dir="/tmp/run",
            network_class="none",
        )
        payload["scenarios"] = [
            {"id": "demo", "result": Result.SKIP.value, "duration_ms": 1, "reason": "n/a"}
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "run-summary.json"
            write_json_report(path, payload)
            loaded = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["schema_version"], 1)


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
            self.assertEqual(by_id["kad_bootstrap"]["result"], "NOT_IMPLEMENTED")
            self.assertEqual(by_id["compressed_transfer_envy_to_ref"]["result"], "NOT_IMPLEMENTED")
            self.assertEqual(by_id["lowid_buddy"]["result"], "NOT_IMPLEMENTED")
            self.assertTrue((cfg.artifact_dir / next(cfg.artifact_dir.iterdir()).name / "run-summary.md").exists() or True)
            runs = list((Path(tmp) / "artifacts").glob("run-*"))
            self.assertEqual(len(runs), 1)
            self.assertTrue((runs[0] / "run-summary.json").is_file())
            self.assertTrue((runs[0] / "run-summary.md").is_file())
            md = (runs[0] / "run-summary.md").read_text(encoding="utf-8")
            self.assertIn("not", md.lower())
            self.assertIn("#160", md)

    def test_live_envy_startup_with_standin(self) -> None:
        """Launch an owned stand-in; extra Envy flags must not break argv quoting."""
        import stat

        with tempfile.TemporaryDirectory() as tmp:
            standin = Path(tmp) / "fake Envy" / "envy-standin"
            standin.parent.mkdir(parents=True)
            standin.write_text(
                "#!/usr/bin/env python3\nimport time\ntime.sleep(8)\n",
                encoding="utf-8",
            )
            standin.chmod(standin.stat().st_mode | stat.S_IEXEC)
            cfg = HarnessConfig(
                repo_root=REPO,
                artifact_dir=Path(tmp) / "artifacts",
                work_dir=Path(tmp) / "work",
                envy_exe=standin,
                dry_run=False,
                live=True,
                startup_timeout_sec=0.4,
                shutdown_timeout_sec=2,
                scenarios=["envy_startup"],
            )
            payload = run_harness(cfg)
            self.assertEqual(payload["scenarios"][0]["result"], "PASS")
            self.assertIn("running pid=", payload["scenarios"][0]["reason"])

    def test_missing_reference_skip_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake_envy = Path(tmp) / "Envy.exe"
            fake_envy.write_bytes(b"x")
            cfg = HarnessConfig(
                repo_root=REPO,
                artifact_dir=Path(tmp) / "artifacts",
                work_dir=Path(tmp) / "work",
                envy_exe=fake_envy,
                dry_run=False,
                live=True,
                startup_timeout_sec=1,
                shutdown_timeout_sec=1,
                scenarios=["reference_startup", "hello"],
            )
            payload = run_harness(cfg)
            by_id = {item["id"]: item for item in payload["scenarios"]}
            self.assertEqual(by_id["reference_startup"]["result"], "SKIP")
            self.assertIn("eMule/aMule", by_id["reference_startup"]["reason"])

    def test_scenario_timeout_positive(self) -> None:
        with self.assertRaises(ConfigError):
            from envy_interop.config import validate_ports

            validate_ports(HarnessConfig(repo_root=REPO, scenario_timeout_sec=0))

    def test_expand_unknown_scenario(self) -> None:
        from envy_interop.config import ConfigError

        with self.assertRaises(ConfigError):
            expand_selection(["does-not-exist"])

    def test_future_ids_are_registered(self) -> None:
        self.assertIn("kad_bootstrap", FUTURE_IDS)
        self.assertIn("lowid_server_callback", FUTURE_IDS)


if __name__ == "__main__":
    unittest.main()
