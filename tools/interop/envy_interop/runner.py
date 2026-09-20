"""Orchestrate one harness run: artifacts, scenarios, sanitize, shutdown."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Sequence

from .capture import find_capture_tool, start_capture
from .config import HarnessConfig
from .evidence import EvidenceError, extract_from_pcap_via_tshark
from .isolation import IsolationError, create_run_isolation, safe_rmtree
from .process import ProcessError, ProcessManager
from .report import ScenarioResult, empty_payload, utc_now, write_json_report, write_markdown_report
from .sanitizer import sanitize_text, sanitize_tree
from .scenarios import (
    SCENARIOS,
    RunContext,
    expand_selection,
    run_scenario,
    _read_git_sha,
    _try_packet_evidence,
    handle_optional_pcap,
)
from .versions import record_configured_binaries


def default_artifact_root(cfg: HarnessConfig) -> Path:
    if cfg.artifact_dir is not None:
        return cfg.artifact_dir
    return cfg.repo_root / "tools" / "interop" / "artifacts"


def make_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def sanitized_config_summary(cfg: HarnessConfig) -> dict:
    def show(path: Optional[Path]) -> str:
        if path is None:
            return ""
        return sanitize_text(str(path))

    return {
        "dry_run": cfg.dry_run,
        "live": cfg.live,
        "envy_exe": show(cfg.envy_exe),
        "emule_exe": show(cfg.emule_exe),
        "amule_exe": show(cfg.amule_exe),
        "envy_tcp_port": cfg.envy_tcp_port,
        "reference_tcp_port": cfg.reference_tcp_port,
        "kad_udp_port": cfg.kad_udp_port,
        "startup_timeout_sec": cfg.startup_timeout_sec,
        "scenario_timeout_sec": cfg.scenario_timeout_sec,
        "shutdown_timeout_sec": cfg.shutdown_timeout_sec,
        "allow_external_network": cfg.allow_external_network,
        "enable_pcap": cfg.enable_pcap,
        "scenarios": list(cfg.scenarios),
        "reference_client": cfg.resolved_reference_client(),
        "reference_version": cfg.reference_version,
        "hello_capture": show(cfg.hello_capture),
        "packet_evidence": show(cfg.packet_evidence),
        "pcap_duration_sec": cfg.pcap_duration_sec,
    }


def _pcap_evidence_ports(cfg: HarnessConfig) -> List[int]:
    ports = [cfg.envy_tcp_port, cfg.reference_tcp_port, cfg.kad_udp_port]
    return [int(p) for p in ports if p]


def _convert_owned_pcap(ctx: RunContext, cfg: HarnessConfig) -> Optional[Path]:
    """Extract TCP/UDP payloads from owned pcap into captures/evidence when tshark exists."""
    if ctx.pcap_path is None or not ctx.pcap_path.is_file():
        return None
    try:
        blob = extract_from_pcap_via_tshark(
            ctx.pcap_path,
            ports=_pcap_evidence_ports(cfg),
        )
    except EvidenceError as exc:
        (ctx.logs_dir / "pcap-extract-error.txt").write_text(str(exc) + "\n", encoding="utf-8")
        return None
    if not blob:
        (ctx.logs_dir / "pcap-extract-empty.txt").write_text(
            "tshark found no TCP/UDP payloads for configured ports\n",
            encoding="utf-8",
        )
        return None
    dest = ctx.run_dir / "captures" / "evidence" / "from-pcap.bin"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(blob)
    return dest


def _refresh_after_pcap(ctx: RunContext, results: List[ScenarioResult]) -> None:
    """Re-evaluate SKIP scenarios that can consume post-capture packet evidence."""
    for index, result in enumerate(results):
        if result.result != "SKIP":
            continue
        spec = SCENARIOS.get(result.id)
        if spec is None:
            continue
        if result.id == "optional_pcap":
            results[index] = handle_optional_pcap(ctx, spec)
            continue
        renewed = _try_packet_evidence(ctx, spec)
        if renewed is not None:
            results[index] = renewed


def run_harness(cfg: HarnessConfig, *, scenario_ids: Optional[Sequence[str]] = None) -> dict:
    run_started = time.monotonic()
    run_id = make_run_id()
    artifact_root = default_artifact_root(cfg)
    artifact_root.mkdir(parents=True, exist_ok=True)
    run_dir = artifact_root / f"run-{run_id}"
    run_dir.mkdir(parents=True, exist_ok=True)
    logs_dir = run_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    work_base = cfg.work_dir if cfg.work_dir is not None else run_dir
    isolation = create_run_isolation(work_base, run_id)
    processes = ProcessManager()
    git_sha = _read_git_sha(cfg.repo_root)
    ctx = RunContext(
        cfg=cfg,
        run_dir=run_dir,
        isolation=isolation,
        processes=processes,
        logs_dir=logs_dir,
        git_sha=git_sha,
    )

    (run_dir / "config.sanitized.json").write_text(
        json.dumps(sanitized_config_summary(cfg), indent=2) + "\n", encoding="utf-8"
    )
    binaries = record_configured_binaries(cfg)
    (run_dir / "versions.txt").write_text(
        sanitize_text(
            "\n".join(
                [
                    f"harness_git_sha={git_sha}",
                    f"envy_revision={git_sha}",
                    f"reference_client={cfg.resolved_reference_client()}",
                    f"reference_version={cfg.reference_version or 'unspecified'}",
                    f"mode={'live' if cfg.live else 'dry-run'}",
                    f"envy_binary={binaries['envy'].get('name') or 'none'}",
                    f"emule_binary={binaries['emule'].get('name') or 'none'}",
                    f"amule_binary={binaries['amule'].get('name') or 'none'}",
                    f"amule_version_text={binaries['amule'].get('version_text') or ''}",
                ]
            )
            + "\n"
        ),
        encoding="utf-8",
    )
    (run_dir / "binaries.json").write_text(
        json.dumps(binaries, indent=2) + "\n", encoding="utf-8"
    )

    selected = expand_selection(scenario_ids if scenario_ids is not None else cfg.scenarios)
    pcap_path = run_dir / "captures" / "loopback.pcap"
    if cfg.live and cfg.enable_pcap:
        tool = find_capture_tool()
        if tool:
            try:
                ctx.pcap_owned = start_capture(
                    processes,
                    tool=tool,
                    out_path=pcap_path,
                    tcp_ports=[cfg.envy_tcp_port, cfg.reference_tcp_port],
                    udp_ports=[cfg.kad_udp_port],
                    log_dir=logs_dir,
                    duration_sec=cfg.pcap_duration_sec or None,
                )
                ctx.pcap_path = pcap_path
            except ProcessError as exc:
                ctx.pcap_start_error = str(exc)
                (logs_dir / "pcap-start-error.txt").write_text(str(exc), encoding="utf-8")
        else:
            (logs_dir / "pcap-skipped.txt").write_text(
                "pcap requested but dumpcap/tshark/tcpdump was not found "
                "(optional; harness does not install capture tools)\n",
                encoding="utf-8",
            )

    results: List[ScenarioResult] = []
    try:
        for scenario_id in selected:
            spec = SCENARIOS[scenario_id]
            results.append(run_scenario(ctx, spec))
    finally:
        processes.terminate_all(cfg.shutdown_timeout_sec)
        if ctx.pcap_owned:
            processes.terminate_owned(ctx.pcap_owned, cfg.shutdown_timeout_sec)
            ctx.pcap_stopped = True
            extracted = _convert_owned_pcap(ctx, cfg)
            if extracted is not None:
                ctx.packet_evidence_path = extracted

    if ctx.pcap_owned or ctx.packet_evidence_path is not None:
        _refresh_after_pcap(ctx, results)

    payload = empty_payload(
        timestamp=utc_now(),
        envy_revision=git_sha,
        mode="live" if cfg.live else "dry-run",
        reference_client=cfg.resolved_reference_client(),
        reference_version=cfg.reference_version,
        artifact_dir=sanitize_text(str(run_dir)),
        network_class="local" if cfg.live else "none",
        git_sha_harness=git_sha,
    )
    payload["scenarios"] = [item.to_dict() for item in results]
    payload["duration_ms"] = int((time.monotonic() - run_started) * 1000)
    payload["binaries"] = binaries
    payload["process_exit"] = {
        "owned": processes.exit_snapshot(),
        "owned_pids_remaining": processes.owned_pids(),
    }

    write_json_report(run_dir / "run-summary.json", payload)
    write_markdown_report(run_dir / "run-summary.md", payload)
    sanitize_tree(logs_dir, run_dir / "sanitized" / "logs")
    sanitize_tree(run_dir / "captures", run_dir / "sanitized" / "captures")

    if cfg.cleanup:
        try:
            safe_rmtree(isolation.root, owned_root=isolation.root)
        except IsolationError:
            (run_dir / "cleanup-skipped.txt").write_text(
                "isolation cleanup skipped because the path was not owned\n",
                encoding="utf-8",
            )

    return payload
