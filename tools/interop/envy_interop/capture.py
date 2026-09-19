"""Optional packet capture. Never required for baseline harness operation."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import List, Optional

from .process import OwnedProcess, ProcessError, ProcessManager


CAPTURE_TOOLS = ("dumpcap", "tcpdump")


def find_capture_tool() -> Optional[str]:
    for name in CAPTURE_TOOLS:
        path = shutil.which(name)
        if path:
            return path
    return None


def start_capture(
    manager: ProcessManager,
    *,
    tool: str,
    out_path: Path,
    ports: List[int],
    log_dir: Path,
) -> OwnedProcess:
    """Start a loopback capture limited to the configured test ports."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    port_spec = " or ".join(f"port {int(p)}" for p in ports)
    argv: List[str]
    if Path(tool).name.startswith("dumpcap"):
        argv = [tool, "-i", "lo", "-f", port_spec, "-w", str(out_path)]
    else:
        argv = [tool, "-i", "lo", "-n", "-w", str(out_path), port_spec]
    try:
        return manager.launch(
            "pcap",
            argv,
            cwd=out_path.parent,
            stdout_path=log_dir / "pcap.stdout",
            stderr_path=log_dir / "pcap.stderr",
        )
    except ProcessError:
        raise
