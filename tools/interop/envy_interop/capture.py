"""Optional packet capture. Never required for baseline harness operation.

Supports dumpcap, tshark, and tcpdump when present. Never installs software.
Windows operators typically use dumpcap/tshark from a Wireshark install.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import List, Optional, Sequence

from .process import OwnedProcess, ProcessManager


CAPTURE_TOOLS = ("dumpcap", "tshark", "tcpdump")


def find_capture_tool() -> Optional[str]:
    for name in CAPTURE_TOOLS:
        path = shutil.which(name)
        if path:
            return path
    return None


def _loopback_iface() -> str:
    override = os.environ.get("ENVY_INTEROP_PCAP_IFACE", "").strip()
    if override:
        return override
    if os.name == "nt":
        # dumpcap/tshark on Windows: "netdev" is not portable. Default to a
        # common Npcap name; operators override via ENVY_INTEROP_PCAP_IFACE.
        return r"\Device\NPF_Loopback"
    import sys

    if sys.platform == "darwin":
        return "lo0"
    return "lo"


def _tcp_port_filter(ports: List[int]) -> str:
    """BPF filter limited to TCP on the configured test ports (compat helper)."""
    return _capture_filter(tcp_ports=ports, udp_ports=[])


def _capture_filter(
    *,
    tcp_ports: Sequence[int],
    udp_ports: Sequence[int] = (),
) -> str:
    """BPF filter for ED2K TCP ports and Kad UDP ports."""
    parts: List[str] = []
    for p in tcp_ports:
        if p:
            parts.append(f"tcp port {int(p)}")
    for p in udp_ports:
        if p:
            parts.append(f"udp port {int(p)}")
    if not parts:
        raise ValueError("capture filter requires at least one TCP or UDP port")
    return " or ".join(parts)


def start_capture(
    manager: ProcessManager,
    *,
    tool: str,
    out_path: Path,
    ports: Optional[List[int]] = None,
    tcp_ports: Optional[Sequence[int]] = None,
    udp_ports: Optional[Sequence[int]] = None,
    log_dir: Path,
    duration_sec: Optional[int] = None,
) -> OwnedProcess:
    """Start a bounded capture limited to the configured test ports.

    ``ports`` is a legacy alias for ``tcp_ports``. Prefer explicit
    ``tcp_ports`` / ``udp_ports`` so Kad UDP (default 4672) is included.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    resolved_tcp = list(tcp_ports) if tcp_ports is not None else list(ports or [])
    resolved_udp = list(udp_ports or [])
    port_spec = _capture_filter(tcp_ports=resolved_tcp, udp_ports=resolved_udp)
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
        # tcpdump: BPF expression must be last (positional). Options before it.
        argv = [tool, "-i", iface, "-n", "-w", str(out_path)]
        if duration_sec and duration_sec > 0:
            argv.extend(["-G", str(int(duration_sec)), "-W", "1"])
        argv.append(port_spec)
    return manager.launch(
        "pcap",
        argv,
        cwd=out_path.parent,
        stdout_path=log_dir / "pcap.stdout",
        stderr_path=log_dir / "pcap.stderr",
    )
