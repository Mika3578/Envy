"""Harness tests that must not require network or reference-client binaries."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_INTEROP_ROOT = Path(__file__).resolve().parents[1]
if str(_INTEROP_ROOT) not in sys.path:
    sys.path.insert(0, str(_INTEROP_ROOT))


from envy_interop.config import ConfigError, HarnessConfig, merge_config, validate_live_executables
from envy_interop.isolation import (
    IsolationError,
    IsolationRoot,
    is_relative_to,
    parts_are_well_known_temp_root,
    safe_rmtree,
)
from envy_interop.process import ProcessError, ProcessManager, python_exit_argv, python_sleeper_argv
from envy_interop.sanitizer import sanitize_text


class ConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Path(__file__).resolve().parents[3]

    def test_cli_overrides_env_and_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "cfg.json"
            cfg_path.write_text(json.dumps({"envy_tcp_port": 1111, "live": False}), encoding="utf-8")
            os.environ["ENVY_INTEROP_ENVY_TCP_PORT"] = "2222"
            self.addCleanup(lambda: os.environ.pop("ENVY_INTEROP_ENVY_TCP_PORT", None))
            from argparse import Namespace

            ns = Namespace(
                envy_exe=None,
                emule_exe=None,
                amule_exe=None,
                work_dir=None,
                artifact_dir=None,
                envy_tcp_port=4664,
                reference_tcp_port=None,
                startup_timeout_sec=None,
                scenario_timeout_sec=None,
                shutdown_timeout_sec=None,
                allow_external_network=None,
                enable_pcap=None,
                pcap_duration_sec=None,
                dry_run=True,
                live=False,
                cleanup=True,
                scenarios=None,
                hello_capture=None,
                packet_evidence=None,
                reference_client=None,
                reference_version=None,
            )
            cfg = merge_config(
                repo_root=self.repo,
                json_data=json.loads(cfg_path.read_text(encoding="utf-8")),
                cli=ns,
            )
            self.assertEqual(cfg.envy_tcp_port, 4664)
            self.assertTrue(cfg.dry_run)

    def test_invalid_executable_path_live(self) -> None:
        cfg = HarnessConfig(repo_root=self.repo, envy_exe=Path("/no/such/Envy.exe"), live=True, dry_run=False)
        with self.assertRaises(ConfigError):
            validate_live_executables(cfg)

    def test_missing_reference_is_not_config_error(self) -> None:
        cfg = HarnessConfig(repo_root=self.repo, live=True, dry_run=False)
        reasons = validate_live_executables(cfg, require_envy=True)
        self.assertTrue(any("ENVY" in item for item in reasons))

    def test_port_zero_rejected(self) -> None:
        from envy_interop.config import validate_ports

        cfg = HarnessConfig(repo_root=self.repo, envy_tcp_port=0)
        with self.assertRaises(ConfigError):
            validate_ports(cfg)

    def test_path_with_spaces_and_unicode_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            spaced = Path(tmp) / "path with spaces" / "café测试"
            spaced.mkdir(parents=True)
            fake = spaced / "Envy.exe"
            fake.write_bytes(b"not-really-an-exe")
            cfg = HarnessConfig(repo_root=self.repo, envy_exe=fake, live=True, dry_run=False)
            validate_live_executables(cfg)
            self.assertTrue(cfg.envy_exe.exists())


class ProcessIsolationTests(unittest.TestCase):
    def test_launch_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mgr = ProcessManager()
            owned = mgr.launch(
                "sleeper",
                python_sleeper_argv(30),
                cwd=root,
                stdout_path=root / "out.bin",
                stderr_path=root / "err.bin",
            )
            self.assertIn(owned.pid, mgr.owned_pids())
            with self.assertRaises(ProcessError):
                mgr.wait_exit(owned, 0.2)
            code = mgr.terminate_owned(owned, 2)
            self.assertIsNotNone(code)
            self.assertNotIn("pkill", " ".join(owned.argv))

    def test_process_exits_early(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mgr = ProcessManager()
            owned = mgr.launch(
                "die",
                python_exit_argv(7),
                cwd=root,
                stdout_path=root / "out.bin",
                stderr_path=root / "err.bin",
            )
            with self.assertRaises(ProcessError) as ctx:
                mgr.wait_running(owned, 0.4)
            self.assertIn("exited early", str(ctx.exception))
            mgr.terminate_owned(owned, 1)

    def test_refuses_to_signal_unowned_pid(self) -> None:
        from envy_interop.process import OwnedProcess
        import subprocess
        import time

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mgr = ProcessManager()
            foreign = subprocess.Popen(
                python_sleeper_argv(10),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                fake = OwnedProcess(
                    name="foreign",
                    argv=["nope"],
                    cwd=root,
                    proc=foreign,
                    stdout_path=root / "x",
                    stderr_path=root / "y",
                    started_monotonic=time.monotonic(),
                )
                with self.assertRaises(ProcessError):
                    mgr.terminate_owned(fake, 1)
            finally:
                foreign.terminate()
                foreign.wait(timeout=5)

    def test_signal_skips_when_pid_missing(self) -> None:
        from envy_interop.process import OwnedProcess

        class Dummy:
            pid = None

            def terminate(self):
                raise AssertionError("should not terminate")

            def kill(self):
                raise AssertionError("should not kill")

            def poll(self):
                return 0

        mgr = ProcessManager()
        owned = OwnedProcess(
            name="gone",
            argv=["x"],
            cwd=Path("."),
            proc=Dummy(),
            stdout_path=Path("x"),
            stderr_path=Path("y"),
            started_monotonic=0.0,
            launch_pid=0,
        )
        mgr._signal(owned, graceful=True)
        mgr._signal(owned, graceful=False)

    def test_unicode_and_spaces_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cwd = Path(tmp) / "my files" / "用户"
            cwd.mkdir(parents=True)
            mgr = ProcessManager()
            owned = mgr.launch(
                "ok",
                python_exit_argv(0),
                cwd=cwd,
                stdout_path=cwd / "out.bin",
                stderr_path=cwd / "err.bin",
            )
            code = mgr.wait_exit(owned, 5)
            self.assertEqual(code, 0)

    def test_safe_cleanup_refuses_home(self) -> None:
        with self.assertRaises(IsolationError):
            safe_rmtree(Path.home(), owned_root=Path.home() / "not-the-same")

    def test_safe_cleanup_refuses_process_temp_root(self) -> None:
        tmp_root = Path(tempfile.gettempdir()).resolve()
        with self.assertRaises(IsolationError):
            safe_rmtree(tmp_root, owned_root=tmp_root)

    def test_well_known_temp_roots_match_components_only(self) -> None:
        self.assertTrue(parts_are_well_known_temp_root(("/", "tmp")))
        self.assertTrue(parts_are_well_known_temp_root(("/", "var", "tmp")))
        self.assertTrue(parts_are_well_known_temp_root(("C:\\", "Windows", "Temp")))
        self.assertTrue(parts_are_well_known_temp_root(("C:\\", "Temp")))
        self.assertFalse(parts_are_well_known_temp_root(("/", "tmp", "child")))
        self.assertFalse(parts_are_well_known_temp_root(("/", "home")))
        self.assertFalse(parts_are_well_known_temp_root(()))

    def test_safe_cleanup_owned_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            owned = IsolationRoot(Path(tmp) / "owned")
            victim = Path(tmp) / "not-owned"
            victim.mkdir()
            marker = victim / "keep.txt"
            marker.write_text("stay", encoding="utf-8")
            with self.assertRaises(IsolationError):
                safe_rmtree(victim, owned_root=owned.root)
            self.assertTrue(marker.exists())
            child = owned.child("a")
            (child / "f.txt").write_text("x", encoding="utf-8")
            owned.cleanup()
            self.assertFalse(owned.root.exists())

    def test_path_escape_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            owned = IsolationRoot(Path(tmp) / "owned")
            with self.assertRaises(IsolationError):
                owned.child("..", "..", "etc")


class CaptureToolTests(unittest.TestCase):
    def test_optional_pcap_absent_is_skip_not_fail(self) -> None:
        from envy_interop.capture import find_capture_tool
        from envy_interop.scenarios import SCENARIOS, RunContext, handle_optional_pcap
        from envy_interop.isolation import create_run_isolation
        from envy_interop.process import ProcessManager

        repo = Path(__file__).resolve().parents[3]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = HarnessConfig(repo_root=repo, dry_run=True, live=False)
            isolation = create_run_isolation(root, "pcap-test")
            ctx = RunContext(
                cfg=cfg,
                run_dir=root / "run",
                isolation=isolation,
                processes=ProcessManager(),
                logs_dir=root / "logs",
                git_sha="test",
            )
            ctx.run_dir.mkdir(parents=True, exist_ok=True)
            result = handle_optional_pcap(ctx, SCENARIOS["optional_pcap"])
            # Availability alone must SKIP (not PASS) — owned capture required.
            self.assertEqual(result.result, "SKIP")
            if find_capture_tool():
                self.assertIn("available", result.reason.lower())
            else:
                self.assertIn("optional", result.reason.lower())

    def test_tcp_port_filter_and_darwin_loopback(self) -> None:
        from envy_interop import capture as capture_mod

        self.assertEqual(capture_mod._tcp_port_filter([4662, 4663]), "tcp port 4662 or tcp port 4663")
        old = os.environ.pop("ENVY_INTEROP_PCAP_IFACE", None)
        self.addCleanup(lambda: (os.environ.__setitem__("ENVY_INTEROP_PCAP_IFACE", old) if old is not None else os.environ.pop("ENVY_INTEROP_PCAP_IFACE", None)))
        os.environ.pop("ENVY_INTEROP_PCAP_IFACE", None)
        # Force Darwin branch without requiring macOS.
        import sys
        old_plat = sys.platform
        sys.platform = "darwin"
        try:
            self.assertEqual(capture_mod._loopback_iface(), "lo0")
        finally:
            sys.platform = old_plat

    def test_tcpdump_duration_options_before_bpf(self) -> None:
        from envy_interop import capture as capture_mod
        from envy_interop.process import ProcessManager
        from unittest.mock import MagicMock, patch

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "cap.pcap"
            mgr = ProcessManager()
            with patch.object(mgr, "launch", return_value=MagicMock()) as launch:
                capture_mod.start_capture(
                    mgr,
                    out_path=out,
                    log_dir=Path(tmp),
                    ports=[4662],
                    tool="/usr/sbin/tcpdump",
                    duration_sec=5,
                )
                argv = launch.call_args[0][1]
                self.assertEqual(argv[-1], "tcp port 4662")
                self.assertIn("-G", argv)
                self.assertLess(argv.index("-G"), len(argv) - 1)
                self.assertEqual(argv[argv.index("-G") + 1], "5")


class SanitizerTests(unittest.TestCase):
    def test_redacts_username_home_and_public_ip(self) -> None:
        sample = (
            f"user={os.environ.get('USER', 'tester')} home={Path.home()} "
            "ip=8.8.8.8 loop=127.0.0.1 password=supersecret "
            "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"
            r"C:\Users\alice\AppData\Roaming\eMule"
        )
        out = sanitize_text(sample)
        self.assertNotIn("8.8.8.8", out)
        self.assertIn("127.0.0.1", out)
        self.assertIn("<redacted>", out.lower() + out)
        self.assertNotIn("supersecret", out)
        self.assertNotIn("BEGIN PRIVATE KEY", out)
        if os.environ.get("USER"):
            self.assertNotIn(os.environ["USER"] + " ", out + " ")


class VersionAndExitTests(unittest.TestCase):
    def test_describe_missing_executable(self) -> None:
        from envy_interop.versions import describe_executable

        info = describe_executable(Path("/no/such/Envy.exe"), allow_version_flag=False)
        self.assertTrue(info["configured"])
        self.assertFalse(info["exists"])
        self.assertEqual(info["name"], "Envy.exe")
        self.assertNotIn("no/such", json.dumps(info))

    def test_describe_unicode_path_without_storing_it(self) -> None:
        from envy_interop.versions import describe_executable

        with tempfile.TemporaryDirectory() as tmp:
            exe = Path(tmp) / "path with spaces" / "café测试" / "amuled"
            exe.parent.mkdir(parents=True)
            exe.write_bytes(b"not-a-real-binary")
            info = describe_executable(exe, allow_version_flag=False)
            self.assertEqual(info["name"], "amuled")
            self.assertEqual(info["size"], len(b"not-a-real-binary"))
            self.assertTrue(info["sha256"])
            dumped = json.dumps(info)
            self.assertNotIn(str(tmp), dumped)
            self.assertNotIn("path with spaces", dumped)

    def test_amule_version_flag_standin(self) -> None:
        import stat

        from envy_interop.versions import describe_executable

        with tempfile.TemporaryDirectory() as tmp:
            exe = Path(tmp) / "amuled"
            exe.write_text("#!/usr/bin/env python3\nprint('aMule 2.3.3')\n", encoding="utf-8")
            exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
            info = describe_executable(exe, allow_version_flag=True)
            self.assertEqual(info["probe"], "--version")
            self.assertIn("aMule 2.3.3", info["version_text"])

    def test_exit_snapshot_after_owned_process(self) -> None:
        mgr = ProcessManager()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            owned = mgr.launch(
                "die",
                python_exit_argv(3),
                cwd=root,
                stdout_path=root / "out.bin",
                stderr_path=root / "err.bin",
            )
            mgr.wait_exit(owned, 5)
            snap = mgr.exit_snapshot()
            self.assertEqual(len(snap), 1)
            self.assertEqual(snap[0]["exit_code"], 3)
            self.assertEqual(snap[0]["name"], "die")
            self.assertNotIn(str(root), json.dumps(snap))


if __name__ == "__main__":
    unittest.main()
