"""Windows-portable mock helpers for the interop harness unit tests.

Patches module-level platform selectors (``os.name``, ``sys.platform``) and
replaces subprocess probes with ``CompletedProcess`` fixtures. Tests must not
mutate the host ``pathlib`` implementation or launch POSIX shebang scripts.
"""

from __future__ import annotations

import contextlib
import os
import subprocess
from types import SimpleNamespace
from typing import Iterator, List, Optional, Sequence, Union
from unittest.mock import MagicMock, patch

BytesOrStr = Union[bytes, str]


@contextlib.contextmanager
def capture_platform(
    os_name: str,
    *,
    platform: Optional[str] = None,
    environ: Optional[dict] = None,
) -> Iterator[None]:
    """Patch ``envy_interop.capture`` OS selectors without replacing the host ``os`` module."""
    import envy_interop.capture as capture_mod

    env = dict(os.environ if environ is None else environ)
    fake_os = SimpleNamespace(name=os_name, environ=env)
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(capture_mod, "os", fake_os))
        if platform is not None:
            stack.enter_context(patch("sys.platform", platform))
        yield


@contextlib.contextmanager
def process_platform(os_name: str, *, environ: Optional[dict] = None) -> Iterator[None]:
    """Patch ``envy_interop.process`` platform bits for launch/teardown tests."""
    import envy_interop.process as process_mod

    real_os = process_mod.os
    env = dict(os.environ if environ is None else environ)
    fake_os = SimpleNamespace(
        name=os_name,
        environ=env,
        killpg=getattr(real_os, "killpg", None),
    )
    with patch.object(process_mod, "os", fake_os):
        yield


@contextlib.contextmanager
def isolation_platform(os_name: str, *, environ: Optional[dict] = None) -> Iterator[None]:
    """Patch ``envy_interop.isolation`` so forbidden-root tests can simulate Windows."""
    import envy_interop.isolation as isolation_mod

    env = dict(os.environ if environ is None else environ)
    with patch.object(isolation_mod, "os", SimpleNamespace(name=os_name, environ=env)):
        yield


def version_completed_process(
    argv: Sequence[str],
    stdout: BytesOrStr,
    *,
    returncode: int = 0,
    stderr: BytesOrStr = b"",
) -> subprocess.CompletedProcess:
    """Build a ``CompletedProcess`` for ``describe_executable`` version probes."""
    if isinstance(stdout, str):
        stdout = stdout.encode("utf-8")
    if isinstance(stderr, str):
        stderr = stderr.encode("utf-8")
    return subprocess.CompletedProcess(list(argv), returncode, stdout=stdout, stderr=stderr)


@contextlib.contextmanager
def mock_executable_version_probe(
    result: subprocess.CompletedProcess,
) -> Iterator[MagicMock]:
    with patch("envy_interop.versions.subprocess.run", return_value=result) as launch:
        yield launch


@contextlib.contextmanager
def mock_tshark_extraction(
    tcp_stdout: str,
    udp_stdout: str = "",
) -> Iterator[MagicMock]:
    """Replace tshark subprocess calls with deterministic row fixtures."""
    outputs = [
        subprocess.CompletedProcess([], 0, stdout=tcp_stdout, stderr=""),
        subprocess.CompletedProcess([], 0, stdout=udp_stdout, stderr=""),
    ]
    with patch("envy_interop.evidence.find_tshark", return_value="tshark"), patch(
        "envy_interop.evidence.subprocess.run",
        side_effect=outputs,
    ) as run:
        yield run


def mock_spawned_process(*, pid: int = 4242, poll_result: Optional[int] = None) -> MagicMock:
    proc = MagicMock()
    proc.pid = pid
    proc.poll.return_value = poll_result
    return proc


def expected_windows_popen_flags() -> int:
    """Return CREATE_NEW_PROCESS_GROUP when the host runtime exposes it."""
    flag = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", None)
    if flag is None:
        return 0
    return int(flag)