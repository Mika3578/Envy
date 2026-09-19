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
from envy_interop.isolation import IsolationError, IsolationRoot, is_relative_to, safe_rmtree
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
                dry_run=True,
                live=False,
                cleanup=True,
                scenarios=None,
                hello_capture=None,
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


if __name__ == "__main__":
    unittest.main()
