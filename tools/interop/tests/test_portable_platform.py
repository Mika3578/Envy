"""Regression coverage for Windows-portable harness mocks (#375 / #410)."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_INTEROP_ROOT = Path(__file__).resolve().parents[1]
if str(_INTEROP_ROOT) not in sys.path:
    sys.path.insert(0, str(_INTEROP_ROOT))

from envy_interop.capture import _loopback_iface
from envy_interop.isolation import forbidden_cleanup_roots
from envy_interop.process import ProcessManager
from tests.harness_mocks import (
    capture_platform,
    expected_windows_popen_flags,
    isolation_platform,
    mock_executable_version_probe,
    mock_spawned_process,
    process_platform,
    version_completed_process,
)


class CaptureLoopbackPlatformTests(unittest.TestCase):
    def test_windows_default_loopback(self) -> None:
        with capture_platform("nt"):
            self.assertEqual(_loopback_iface(), r"\Device\NPF_Loopback")

    def test_darwin_default_loopback(self) -> None:
        with capture_platform("posix", platform="darwin"):
            self.assertEqual(_loopback_iface(), "lo0")

    def test_linux_default_loopback(self) -> None:
        with capture_platform("posix", platform="linux"):
            self.assertEqual(_loopback_iface(), "lo")

    def test_env_override_wins_on_windows_mock(self) -> None:
        env = dict(os.environ, ENVY_INTEROP_PCAP_IFACE="mock-npcap-iface")
        with capture_platform("nt", environ=env):
            self.assertEqual(_loopback_iface(), "mock-npcap-iface")


class ProcessLaunchPlatformTests(unittest.TestCase):
    def test_windows_mock_uses_process_group_flag(self) -> None:
        expected = expected_windows_popen_flags()
        if not expected:
            self.skipTest("host runtime has no CREATE_NEW_PROCESS_GROUP")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with process_platform("nt"), patch(
                "envy_interop.process.subprocess.Popen",
                return_value=mock_spawned_process(),
            ) as popen:
                mgr = ProcessManager()
                owned = mgr.launch(
                    "pcap",
                    ["dumpcap.exe", "-i", "lo"],
                    cwd=root,
                    stdout_path=root / "out.bin",
                    stderr_path=root / "err.bin",
                )
                self.assertEqual(owned.launch_pid, 4242)
                kwargs = popen.call_args.kwargs
                self.assertFalse(kwargs["shell"])
                self.assertEqual(kwargs["creationflags"], expected)
                mgr.terminate_owned(owned, 1)

    def test_posix_mock_uses_new_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with process_platform("posix"), patch(
                "envy_interop.process.subprocess.Popen",
                return_value=mock_spawned_process(),
            ) as popen:
                mgr = ProcessManager()
                owned = mgr.launch(
                    "pcap",
                    [sys.executable, "-c", "pass"],
                    cwd=root,
                    stdout_path=root / "out.bin",
                    stderr_path=root / "err.bin",
                )
                kwargs = popen.call_args.kwargs
                self.assertTrue(kwargs["start_new_session"])
                self.assertNotIn("creationflags", kwargs)
                mgr.terminate_owned(owned, 1)


class VersionProbePlatformTests(unittest.TestCase):
    def test_amule_version_probe_uses_mocked_completed_process(self) -> None:
        from envy_interop.versions import describe_executable

        with tempfile.TemporaryDirectory() as tmp:
            exe = Path(tmp) / "amuled.exe"
            exe.write_bytes(b"synthetic binary identity")
            argv = [str(exe), "--version"]
            result = version_completed_process(argv, b"aMule 3.1.0\n")
            with mock_executable_version_probe(result) as launch:
                info = describe_executable(exe, allow_version_flag=True)
            self.assertEqual(launch.call_args.args[0], argv)
            self.assertFalse(launch.call_args.kwargs["shell"])
            self.assertEqual(info["probe"], "--version")
            self.assertIn("aMule 3.1.0", info["version_text"])


class IsolationPlatformTests(unittest.TestCase):
    def test_windows_mock_adds_drive_and_profile_guards(self) -> None:
        env = {
            "USERPROFILE": r"C:\Users\tester",
            "APPDATA": r"C:\Users\tester\AppData\Roaming",
            "LOCALAPPDATA": r"C:\Users\tester\AppData\Local",
            "HOMEDRIVE": "C:",
        }
        with isolation_platform("nt", environ=env):
            roots = forbidden_cleanup_roots()
        self.assertIn(Path("C:\\"), roots)
        self.assertIn(Path("D:\\"), roots)
        profile_guards = [item for item in roots if "tester" in str(item)]
        self.assertGreaterEqual(len(profile_guards), 2)


if __name__ == "__main__":
    unittest.main()