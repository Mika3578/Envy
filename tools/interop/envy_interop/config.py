"""Operator configuration: CLI, environment, JSON. No hard-coded machine paths."""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence


ENV_PREFIX = "ENVY_INTEROP_"

DEFAULT_ENVY_TCP_PORT = 4662
DEFAULT_REFERENCE_TCP_PORT = 4663
DEFAULT_KAD_UDP_PORT = 4672
DEFAULT_STARTUP_TIMEOUT = 30
DEFAULT_SCENARIO_TIMEOUT = 120
DEFAULT_SHUTDOWN_TIMEOUT = 15


class ConfigError(ValueError):
    pass


def _env(name: str, default: str = "") -> str:
    return os.environ.get(ENV_PREFIX + name, default)


def _env_int(name: str, default: int) -> int:
    raw = _env(name, "")
    if not raw:
        return default
    try:
        return int(raw, 10)
    except ValueError as exc:
        raise ConfigError(f"environment {ENV_PREFIX}{name} is not an integer") from exc


def _env_bool(name: str, default: bool = False) -> bool:
    raw = _env(name, "")
    if not raw:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class HarnessConfig:
    repo_root: Path
    envy_exe: Optional[Path] = None
    emule_exe: Optional[Path] = None
    amule_exe: Optional[Path] = None
    work_dir: Optional[Path] = None
    artifact_dir: Optional[Path] = None
    envy_tcp_port: int = DEFAULT_ENVY_TCP_PORT
    reference_tcp_port: int = DEFAULT_REFERENCE_TCP_PORT
    kad_udp_port: int = DEFAULT_KAD_UDP_PORT
    startup_timeout_sec: int = DEFAULT_STARTUP_TIMEOUT
    scenario_timeout_sec: int = DEFAULT_SCENARIO_TIMEOUT
    shutdown_timeout_sec: int = DEFAULT_SHUTDOWN_TIMEOUT
    allow_external_network: bool = False
    enable_pcap: bool = False
    dry_run: bool = True
    live: bool = False
    cleanup: bool = True
    scenarios: List[str] = field(default_factory=lambda: ["phase1"])
    hello_capture: Optional[Path] = None
    packet_evidence: Optional[Path] = None
    pcap_duration_sec: int = 0
    operator_hold_sec: int = 0
    reference_client: str = "none"
    reference_version: str = ""
    config_path: Optional[Path] = None

    def selected_reference_exe(self) -> Optional[Path]:
        if self.reference_client == "emule-community":
            return self.emule_exe
        if self.reference_client in {"amule", "amuled"}:
            return self.amule_exe
        if self.emule_exe:
            return self.emule_exe
        if self.amule_exe:
            return self.amule_exe
        return None

    def resolved_reference_client(self) -> str:
        if self.reference_client != "none":
            return self.reference_client
        if self.emule_exe:
            return "emule-community"
        if self.amule_exe:
            return "amule"
        return "none"


def _optional_path(value: Optional[str]) -> Optional[Path]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return Path(text)


def load_json_config(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read config file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"malformed config JSON: {path}") from exc
    if not isinstance(data, dict):
        raise ConfigError("config JSON must be an object")
    return data


def merge_config(
    *,
    repo_root: Path,
    json_data: Optional[dict] = None,
    cli: Optional[argparse.Namespace] = None,
) -> HarnessConfig:
    data = dict(json_data or {})
    cfg = HarnessConfig(repo_root=repo_root.resolve())

    def pick_path(cli_val, json_key: str, env_name: str) -> Optional[Path]:
        if cli_val:
            return Path(cli_val)
        env_val = _env(env_name, "")
        if env_val:
            return Path(env_val)
        return _optional_path(data.get(json_key))

    def pick_int(cli_val, json_key: str, env_name: str, default: int) -> int:
        if cli_val is not None:
            return int(cli_val)
        if env_name and _env(env_name, ""):
            return _env_int(env_name, default)
        if json_key in data and data[json_key] is not None:
            return int(data[json_key])
        return default

    def pick_bool(cli_val, json_key: str, env_name: str, default: bool) -> bool:
        if cli_val is not None:
            return bool(cli_val)
        if _env(env_name, ""):
            return _env_bool(env_name, default)
        if json_key in data:
            return bool(data[json_key])
        return default

    cfg.envy_exe = pick_path(getattr(cli, "envy_exe", None), "envy_exe", "ENVY_EXE")
    cfg.emule_exe = pick_path(getattr(cli, "emule_exe", None), "emule_exe", "EMULE_EXE")
    cfg.amule_exe = pick_path(getattr(cli, "amule_exe", None), "amule_exe", "AMULE_EXE")
    cfg.work_dir = pick_path(getattr(cli, "work_dir", None), "work_dir", "WORK_DIR")
    cfg.artifact_dir = pick_path(
        getattr(cli, "artifact_dir", None), "artifact_dir", "ARTIFACT_DIR"
    )
    cfg.envy_tcp_port = pick_int(
        getattr(cli, "envy_tcp_port", None), "envy_tcp_port", "ENVY_TCP_PORT", DEFAULT_ENVY_TCP_PORT
    )
    cfg.reference_tcp_port = pick_int(
        getattr(cli, "reference_tcp_port", None),
        "reference_tcp_port",
        "REFERENCE_TCP_PORT",
        DEFAULT_REFERENCE_TCP_PORT,
    )
    cfg.kad_udp_port = pick_int(
        getattr(cli, "kad_udp_port", None),
        "kad_udp_port",
        "KAD_UDP_PORT",
        DEFAULT_KAD_UDP_PORT,
    )
    cfg.startup_timeout_sec = pick_int(
        getattr(cli, "startup_timeout_sec", None),
        "startup_timeout_sec",
        "STARTUP_TIMEOUT_SEC",
        DEFAULT_STARTUP_TIMEOUT,
    )
    cfg.scenario_timeout_sec = pick_int(
        getattr(cli, "scenario_timeout_sec", None),
        "scenario_timeout_sec",
        "SCENARIO_TIMEOUT_SEC",
        DEFAULT_SCENARIO_TIMEOUT,
    )
    cfg.shutdown_timeout_sec = pick_int(
        getattr(cli, "shutdown_timeout_sec", None),
        "shutdown_timeout_sec",
        "SHUTDOWN_TIMEOUT_SEC",
        DEFAULT_SHUTDOWN_TIMEOUT,
    )
    cfg.allow_external_network = pick_bool(
        getattr(cli, "allow_external_network", None),
        "allow_external_network",
        "ALLOW_EXTERNAL_NETWORK",
        False,
    )
    cfg.enable_pcap = pick_bool(
        getattr(cli, "enable_pcap", None), "enable_pcap", "ENABLE_PCAP", False
    )
    live = pick_bool(getattr(cli, "live", None), "live", "LIVE", False)
    dry = pick_bool(getattr(cli, "dry_run", None), "dry_run", "DRY_RUN", True)
    cfg.live = bool(live)
    cfg.dry_run = (not cfg.live) if getattr(cli, "live", False) else bool(dry) and not cfg.live
    if cfg.live:
        cfg.dry_run = False
    cfg.cleanup = pick_bool(getattr(cli, "cleanup", None), "cleanup", "CLEANUP", True)

    scenarios = getattr(cli, "scenarios", None)
    if scenarios:
        cfg.scenarios = [part.strip() for part in str(scenarios).split(",") if part.strip()]
    elif _env("SCENARIOS", ""):
        cfg.scenarios = [part.strip() for part in _env("SCENARIOS").split(",") if part.strip()]
    elif isinstance(data.get("scenarios"), list):
        cfg.scenarios = [str(item) for item in data["scenarios"]]
    elif isinstance(data.get("scenarios"), str):
        cfg.scenarios = [part.strip() for part in data["scenarios"].split(",") if part.strip()]

    cfg.hello_capture = pick_path(
        getattr(cli, "hello_capture", None), "hello_capture", "HELLO_CAPTURE"
    )
    cfg.packet_evidence = pick_path(
        getattr(cli, "packet_evidence", None), "packet_evidence", "PACKET_EVIDENCE"
    )
    cfg.pcap_duration_sec = pick_int(
        getattr(cli, "pcap_duration_sec", None),
        "pcap_duration_sec",
        "PCAP_DURATION_SEC",
        0,
    )
    cfg.operator_hold_sec = pick_int(
        getattr(cli, "operator_hold_sec", None),
        "operator_hold_sec",
        "OPERATOR_HOLD_SEC",
        0,
    )
    cfg.reference_client = (
        getattr(cli, "reference_client", None)
        or _env("REFERENCE_CLIENT", "")
        or str(data.get("reference_client") or "none")
    )
    cfg.reference_version = (
        getattr(cli, "reference_version", None)
        or _env("REFERENCE_VERSION", "")
        or str(data.get("reference_version") or "")
    )
    return cfg


def validate_ports(cfg: HarnessConfig) -> None:
    for name, value in (
        ("envy_tcp_port", cfg.envy_tcp_port),
        ("reference_tcp_port", cfg.reference_tcp_port),
        ("kad_udp_port", cfg.kad_udp_port),
    ):
        if not (1 <= int(value) <= 65535):
            raise ConfigError(f"{name} must be in 1..65535")
    if int(cfg.pcap_duration_sec) < 0:
        raise ConfigError("pcap_duration_sec must be >= 0")
    if int(cfg.operator_hold_sec) < 0:
        raise ConfigError("operator_hold_sec must be >= 0")
    for name, value in (
        ("startup_timeout_sec", cfg.startup_timeout_sec),
        ("scenario_timeout_sec", cfg.scenario_timeout_sec),
        ("shutdown_timeout_sec", cfg.shutdown_timeout_sec),
    ):
        if float(value) <= 0:
            raise ConfigError(f"{name} must be > 0 (no indefinite waits)")


def validate_live_executables(cfg: HarnessConfig, *, require_envy: bool = True) -> List[str]:
    """Return skip reasons; raise ConfigError for unsafe/invalid live paths."""
    validate_ports(cfg)
    reasons: List[str] = []
    if require_envy:
        if cfg.envy_exe is None:
            reasons.append("ENVY executable is not configured")
        elif not cfg.envy_exe.exists():
            raise ConfigError(f"ENVY executable does not exist: {cfg.envy_exe}")
        elif not cfg.envy_exe.is_file():
            raise ConfigError(f"ENVY executable is not a file: {cfg.envy_exe}")
    if cfg.emule_exe is not None:
        if not cfg.emule_exe.exists():
            raise ConfigError(f"eMule executable does not exist: {cfg.emule_exe}")
        if not cfg.emule_exe.is_file():
            raise ConfigError(f"eMule executable is not a file: {cfg.emule_exe}")
    if cfg.amule_exe is not None:
        if not cfg.amule_exe.exists():
            raise ConfigError(f"aMule executable does not exist: {cfg.amule_exe}")
        if not cfg.amule_exe.is_file():
            raise ConfigError(f"aMule executable is not a file: {cfg.amule_exe}")
    if cfg.hello_capture is not None and not cfg.hello_capture.is_file():
        raise ConfigError(f"hello capture is not a file: {cfg.hello_capture}")
    return reasons


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 tools/interop/run.py",
        description=(
            "Opt-in ENVY ↔ eMule Community / aMule interoperability harness (#160). "
            "Default is dry-run. Live reference binaries are never required for CI."
        ),
    )
    parser.add_argument("--config", type=str, default="", help="JSON config path")
    parser.add_argument("--envy-exe", type=str, default="", help="Path to Envy.exe")
    parser.add_argument("--emule-exe", type=str, default="", help="Path to emule.exe")
    parser.add_argument(
        "--amule-exe",
        type=str,
        default="",
        help="Path to amule or amuled",
    )
    parser.add_argument("--work-dir", type=str, default="", help="Working directory for this run")
    parser.add_argument("--artifact-dir", type=str, default="", help="Artifact root directory")
    parser.add_argument("--envy-tcp-port", type=int, default=None)
    parser.add_argument("--reference-tcp-port", type=int, default=None)
    parser.add_argument(
        "--kad-udp-port",
        type=int,
        default=None,
        help="Kad UDP port included in optional pcap BPF (default 4672)",
    )
    parser.add_argument("--startup-timeout-sec", type=int, default=None)
    parser.add_argument("--scenario-timeout-sec", type=int, default=None)
    parser.add_argument("--shutdown-timeout-sec", type=int, default=None)
    parser.add_argument(
        "--scenarios",
        type=str,
        default="",
        help="Comma-separated scenario ids or aliases (phase1, all, future)",
    )
    parser.add_argument(
        "--reference-client",
        type=str,
        default="",
        choices=["", "none", "emule-community", "amule", "amuled"],
    )
    parser.add_argument("--reference-version", type=str, default="")
    parser.add_argument(
        "--hello-capture",
        type=str,
        default="",
        help="Hex/binary Hello capture to parse (does not require live clients)",
    )
    parser.add_argument(
        "--packet-evidence",
        type=str,
        default="",
        help="Hex/binary dump of ED2K frames for scenario evidence (optional)",
    )
    parser.add_argument(
        "--pcap-duration-sec",
        type=int,
        default=None,
        help="Optional bounded capture duration for dumpcap/tshark (0 = until harness stop)",
    )
    parser.add_argument(
        "--operator-hold-sec",
        type=int,
        default=None,
        help=(
            "Live-only: seconds to wait after optional pcap start and before scenario "
            "evaluation so the operator can complete manual GUI steps (0 = no hold)"
        ),
    )
    parser.add_argument("--live", action="store_true", help="Launch configured processes")
    parser.add_argument("--dry-run", action="store_true", help="Do not launch processes (default)")
    parser.add_argument(
        "--allow-external-network",
        action="store_true",
        help="Permit scenarios that need public ED2K/Kad infrastructure",
    )
    parser.add_argument(
        "--enable-pcap",
        action="store_true",
        help="Optional packet capture if dumpcap/tshark/tcpdump is installed",
    )
    parser.add_argument("--no-cleanup", action="store_true", help="Keep isolated scratch directories")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run harness unit tests (no network, no reference binaries)",
    )
    parser.add_argument(
        "--ingest-hello",
        type=str,
        default="",
        help="Ingest a Hello hex/binary dump into the run artifacts (sanitized candidate)",
    )
    parser.add_argument(
        "--ingest-direction",
        type=str,
        default="recv",
        help="Capture direction for --ingest-hello (recv/send)",
    )
    return parser


def config_from_args(argv: Optional[Sequence[str]], repo_root: Path) -> HarnessConfig:
    parser = build_arg_parser()
    ns = parser.parse_args(list(argv) if argv is not None else None)
    json_data = None
    config_path = None
    if ns.config:
        config_path = Path(ns.config)
        json_data = load_json_config(config_path)
    if not ns.envy_exe:
        ns.envy_exe = None
    if not ns.emule_exe:
        ns.emule_exe = None
    if not ns.amule_exe:
        ns.amule_exe = None
    if not ns.work_dir:
        ns.work_dir = None
    if not ns.artifact_dir:
        ns.artifact_dir = None
    if not ns.hello_capture:
        ns.hello_capture = None
    if not getattr(ns, "packet_evidence", None):
        ns.packet_evidence = None
    if not ns.scenarios:
        ns.scenarios = None
    if not ns.reference_client:
        ns.reference_client = None
    if not ns.reference_version:
        ns.reference_version = None
    if ns.live:
        ns.dry_run = False
    elif ns.dry_run:
        ns.live = False
    else:
        ns.dry_run = True
        ns.live = False
    ns.cleanup = not ns.no_cleanup
    ns.allow_external_network = bool(ns.allow_external_network) or None
    if not ns.allow_external_network:
        ns.allow_external_network = None
    if not ns.enable_pcap:
        ns.enable_pcap = None
    cfg = merge_config(repo_root=repo_root, json_data=json_data, cli=ns)
    cfg.config_path = config_path
    validate_ports(cfg)
    return cfg
