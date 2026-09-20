"""Optional packet capture. Never required for baseline harness operation.

Supports dumpcap, tshark, and tcpdump when present. Never installs software.
Windows operators typically use dumpcap/tshark from a Wireshark install.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import List, Optional

from .process import OwnedProcess, ProcessManager


CAPTURE_TOOLS = ("dumpcap", "tshark", "tcpdump")


def find_capture_tool() -> Optional[str]:
    for name in CAPTURE_TOOLS:
        path = shutil.which(name)
        if path:
            return path
    return None


def _loopback_iface() -> str:
    if os.name == "nt":
        # dumpcap/tshark on Windows: "Npc" is not portable; operators may
        # override via ENVY_INTEROP_PCAP_IFACE. Default to a common Npcap name.
        return os.environ.get("ENVY_INTEROP_PCAP_IFACE", r"\Device\NPF_Loopback")
    return os.environ.get("ENVY_INTEROP_PCAP_IFACE", "lo")


def start_capture(
    manager: ProcessManager,
    *,
    tool: str,
    out_path: Path,
    ports: List[int],
    log_dir: Path,
    duration_sec: Optional[int] = None,
) -> OwnedProcess:
    """Start a bounded capture limited to the configured test ports."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    port_spec = " or ".join(f"port {int(p)}" for p in ports)
    iface = _loopback_iface()
    name = Path(tool).name.lower()
    argv: List[str]
    if name.startswith("dumpcap"):
        argv = [tool, "-i", iface, "-f", port_spec, "-w", str(out_path)]
        if duration_sec and duration_sec > 0:
            argv.extend(["-a", f"duration:{int(duration_sec)}"])
    elif name.startswith("tshark"):
        argv = [
            tool,
            "-i",
            iface,
            "-f",
            port_spec,
            "-w",
            str(out_path),
            "-q",
        ]
        if duration_sec and duration_sec > 0:
            argv.extend(["-a", f"duration:{int(duration_sec)}"])
    else:
        # tcpdump
        argv = [tool, "-i", iface, "-n", "-w", str(out_path), port_spec]
        if duration_sec and duration_sec > 0:
            argv.extend(["-G", str(int(duration_sec)), "-W", "1"])
    return manager.launch(
        "pcap",
        argv,
        cwd=out_path.parent,
        stdout_path=log_dir / "pcap.stdout",
        stderr_path=log_dir / "pcap.stderr",
    )
