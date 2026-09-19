"""Launch and stop only processes this harness started.

Arguments are always a sequence (never a shell string) so paths with spaces or
Unicode cannot inject commands. Broad image-name kills are forbidden.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence


class ProcessError(RuntimeError):
    pass


@dataclass
class OwnedProcess:
    name: str
    argv: List[str]
    cwd: Path
    proc: subprocess.Popen
    stdout_path: Path
    stderr_path: Path
    started_monotonic: float
    launch_pid: int = 0
    stdout_handle: object = field(repr=False, default=None)
    stderr_handle: object = field(repr=False, default=None)
    exit_code: Optional[int] = None
    timed_out: bool = False

    @property
    def pid(self) -> Optional[int]:
        # Prefer the pid captured at spawn; do not re-read a possibly-cleared Popen.pid.
        if self.launch_pid:
            return self.launch_pid
        return self.proc.pid

    def poll(self) -> Optional[int]:
        code = self.proc.poll()
        if code is not None:
            self.exit_code = int(code)
        return code


class ProcessManager:
    def __init__(self) -> None:
        self._owned: Dict[int, OwnedProcess] = {}

    def owned_pids(self) -> List[int]:
        return list(self._owned.keys())

    def launch(
        self,
        name: str,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Optional[dict] = None,
        stdout_path: Path,
        stderr_path: Path,
        extra_env: Optional[dict] = None,
    ) -> OwnedProcess:
        if not argv:
            raise ProcessError("argv is empty")
        exe = Path(argv[0])
        if not exe.exists():
            raise ProcessError(f"executable does not exist: {exe}")
        cwd.mkdir(parents=True, exist_ok=True)
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path.parent.mkdir(parents=True, exist_ok=True)

        merged_env = os.environ.copy()
        if env:
            merged_env.update({str(k): str(v) for k, v in env.items()})
        if extra_env:
            merged_env.update({str(k): str(v) for k, v in extra_env.items()})

        stdout_handle = stdout_path.open("wb")
        stderr_handle = stderr_path.open("wb")
        popen_kwargs = {
            "args": [str(part) for part in argv],
            "cwd": str(cwd),
            "env": merged_env,
            "stdout": stdout_handle,
            "stderr": stderr_handle,
            "stdin": subprocess.DEVNULL,
            "shell": False,
        }
        if os.name == "posix":
            popen_kwargs["start_new_session"] = True
        elif os.name == "nt" and hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

        try:
            proc = subprocess.Popen(**popen_kwargs)
        except OSError as exc:
            stdout_handle.close()
            stderr_handle.close()
            raise ProcessError(f"failed to spawn {name}: {exc}") from exc

        owned = OwnedProcess(
            name=name,
            argv=[str(part) for part in argv],
            cwd=cwd,
            proc=proc,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            started_monotonic=time.monotonic(),
            stdout_handle=stdout_handle,
            stderr_handle=stderr_handle,
        )
        owned.launch_pid = int(proc.pid)
        if owned.launch_pid <= 0:
            self._close_handles(owned)
            raise ProcessError(f"{name} spawned without a usable pid")
        self._owned[owned.launch_pid] = owned
        return owned

    def wait_running(self, owned: OwnedProcess, timeout_sec: float) -> None:
        """Require the process to stay alive for timeout_sec (no indefinite wait)."""
        deadline = time.monotonic() + timeout_sec
        while time.monotonic() < deadline:
            code = owned.poll()
            if code is not None:
                raise ProcessError(f"{owned.name} exited early with code {code}")
            time.sleep(0.05)
        code = owned.poll()
        if code is not None:
            raise ProcessError(f"{owned.name} exited early with code {code}")

    def wait_exit(self, owned: OwnedProcess, timeout_sec: float) -> int:
        deadline = time.monotonic() + timeout_sec
        while time.monotonic() < deadline:
            code = owned.poll()
            if code is not None:
                self._close_handles(owned)
                return int(code)
            time.sleep(0.05)
        owned.timed_out = True
        raise ProcessError(f"{owned.name} did not exit within {timeout_sec}s")

    def terminate_owned(self, owned: OwnedProcess, timeout_sec: float) -> Optional[int]:
        pid = owned.launch_pid or owned.pid
        if pid is None or int(pid) not in self._owned:
            raise ProcessError("refusing to signal a process this harness did not start")
        if owned.poll() is not None:
            self._close_handles(owned)
            return owned.exit_code
        self._signal(owned, graceful=True)
        try:
            return self.wait_exit(owned, timeout_sec)
        except ProcessError:
            self._signal(owned, graceful=False)
            try:
                return self.wait_exit(owned, max(1.0, timeout_sec / 3.0))
            except ProcessError:
                return owned.poll()

    def terminate_all(self, timeout_sec: float) -> None:
        owned_snapshot = tuple(self._owned.values())
        for owned in owned_snapshot:
            try:
                self.terminate_owned(owned, timeout_sec)
            except ProcessError:
                pass

    def exit_snapshot(self) -> List[dict]:
        """Record exit state for processes this harness started (no full paths)."""
        rows = []
        for owned in tuple(self._owned.values()):
            code = owned.poll()
            argv0 = Path(owned.argv[0]).name if owned.argv else ""
            rows.append(
                {
                    "name": owned.name,
                    "pid": owned.launch_pid or owned.pid,
                    "exit_code": code if code is not None else owned.exit_code,
                    "timed_out": owned.timed_out,
                    "argv0": argv0,
                }
            )
        return rows

    def _signal(self, owned: OwnedProcess, *, graceful: bool) -> None:
        raw_pid = owned.launch_pid or owned.pid
        if raw_pid is None:
            return
        try:
            pid = int(raw_pid)
        except (TypeError, ValueError):
            return
        try:
            if os.name == "posix":
                sig = signal.SIGTERM if graceful else signal.SIGKILL
                try:
                    os.killpg(pid, sig)
                except ProcessLookupError:
                    return
                except PermissionError:
                    owned.proc.terminate() if graceful else owned.proc.kill()
            else:
                if graceful:
                    owned.proc.terminate()
                else:
                    owned.proc.kill()
        except (OSError, TypeError):
            return

    def _close_handles(self, owned: OwnedProcess) -> None:
        for handle in (owned.stdout_handle, owned.stderr_handle):
            try:
                if handle:
                    handle.close()
            except OSError:
                pass
        owned.stdout_handle = None
        owned.stderr_handle = None
        if owned.pid in self._owned:
            # Keep metadata; drop live tracking after close of stdio.
            pass

    def forget(self, owned: OwnedProcess) -> None:
        self._close_handles(owned)
        key = owned.launch_pid or owned.pid
        if key in self._owned:
            del self._owned[key]


def python_sleeper_argv(seconds: float) -> List[str]:
    """Test helper: argv that sleeps without invoking a shell."""
    return [sys.executable, "-c", f"import time; time.sleep({float(seconds)!r})"]


def python_exit_argv(code: int) -> List[str]:
    return [sys.executable, "-c", f"raise SystemExit({int(code)})"]
