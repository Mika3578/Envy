"""Orchestrate one harness run: artifacts, scenarios, sanitize, shutdown."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Sequence

from .capture import find_capture_tool, start_capture
from .config import ConfigError, HarnessConfig
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
        "startup_timeout_sec": cfg.startup_timeout_sec,
        "scenario_timeout_sec": cfg.scenario_timeout_sec,
        "shutdown_timeout_sec": cfg.shutdown_timeout_sec,
        "allow_external_network": cfg.allow_external_network,
        "enable_pcap": cfg.enable_pcap,
        "scenarios": list(cfg.scenarios),
        "reference_client": cfg.resolved_reference_client(),
        "reference_version": cfg.reference_version,
        "hello_capture": show(cfg.hello_capture),
    }


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
    pcap_owned = None
    if cfg.live and cfg.enable_pcap:
        tool = find_capture_tool()
        if tool:
            try:
                pcap_owned = start_capture(
                    processes,
                    tool=tool,
                    out_path=run_dir / "captures" / "loopback.pcap",
                    ports=[cfg.envy_tcp_port, cfg.reference_tcp_port],
                    log_dir=logs_dir,
                )
            except ProcessError as exc:
                (logs_dir / "pcap-start-error.txt").write_text(str(exc), encoding="utf-8")
        else:
            (logs_dir / "pcap-skipped.txt").write_text(
                "pcap requested but dumpcap/tcpdump was not found\n", encoding="utf-8"
            )

    results: List[ScenarioResult] = []
    try:
        for scenario_id in selected:
            spec = SCENARIOS[scenario_id]
            results.append(run_scenario(ctx, spec))
    finally:
        processes.terminate_all(cfg.shutdown_timeout_sec)
        if pcap_owned:
            processes.terminate_owned(pcap_owned, cfg.shutdown_timeout_sec)

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
