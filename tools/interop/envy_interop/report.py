"""JSON + Markdown run reports. Logs stay in files, not inlined."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import HARNESS_VERSION, REPORT_SCHEMA_VERSION
from .constants import Result


REQUIRED_REPORT_FIELDS = (
    "schema_version",
    "timestamp",
    "harness_version",
    "envy_revision",
    "mode",
    "scenarios",
)


class ReportError(ValueError):
    pass


@dataclass
class ScenarioResult:
    id: str
    result: str
    duration_ms: int = 0
    reason: str = ""
    network_class: str = "none"
    evidence_class: str = "deterministic"
    artifacts: List[str] = field(default_factory=list)
    observations: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if not data["observations"]:
            data.pop("observations")
        return data


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_report(data: Dict[str, Any]) -> None:
    if not isinstance(data, dict):
        raise ReportError("report must be a JSON object")
    for key in REQUIRED_REPORT_FIELDS:
        if key not in data:
            raise ReportError(f"missing required field: {key}")
    if not isinstance(data.get("schema_version"), int):
        raise ReportError("schema_version must be an integer")
    scenarios = data.get("scenarios")
    if not isinstance(scenarios, list):
        raise ReportError("scenarios must be a list")
    allowed = {item.value for item in Result}
    for item in scenarios:
        if not isinstance(item, dict) or "id" not in item or "result" not in item:
            raise ReportError("each scenario needs id and result")
        if item["result"] not in allowed:
            raise ReportError(f"invalid scenario result: {item['result']}")


def write_json_report(path: Path, payload: Dict[str, Any]) -> None:
    validate_report(payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def write_markdown_report(path: Path, payload: Dict[str, Any]) -> None:
    validate_report(payload)
    lines = [
        "# ENVY interop harness report",
        "",
        f"- Schema: `{payload['schema_version']}`",
        f"- Timestamp: `{payload['timestamp']}`",
        f"- Harness: `{payload.get('harness_version', HARNESS_VERSION)}`",
        f"- ENVY revision: `{payload.get('envy_revision', 'unknown')}`",
        f"- Mode: `{payload.get('mode')}`",
        f"- Reference client: `{payload.get('reference_client', 'none')}`",
        f"- Reference version: `{payload.get('reference_version') or '(not recorded)'}`",
        f"- Network class: `{payload.get('network_class', 'none')}`",
        "",
        "## Scenarios",
        "",
        "| Scenario | Result | Duration (ms) | Reason |",
        "| --- | --- | ---: | --- |",
    ]
    counts = {item.value: 0 for item in Result}
    for item in payload["scenarios"]:
        counts[item["result"]] = counts.get(item["result"], 0) + 1
        reason = (item.get("reason") or "").replace("|", "\\|")
        lines.append(
            f"| `{item['id']}` | **{item['result']}** | {item.get('duration_ms', 0)} | {reason} |"
        )
    lines.extend(
        [
            "",
            "## Totals",
            "",
            f"- PASS: {counts[Result.PASS.value]}",
            f"- FAIL: {counts[Result.FAIL.value]}",
            f"- SKIP: {counts[Result.SKIP.value]}",
            f"- NOT_IMPLEMENTED: {counts[Result.NOT_IMPLEMENTED.value]}",
            "",
            "## Artifacts",
            "",
            f"- Run directory: `{payload.get('artifact_dir', '')}`",
            "",
            "Live ED2K/Kad interoperability is **not** fully validated by the mere",
            "existence of this harness. Attach this report to GitHub issues #160, #86,",
            "or #87 instead of claiming protocol completeness.",
            "",
        ]
    )
    failures = [item for item in payload["scenarios"] if item["result"] == Result.FAIL.value]
    if failures:
        lines.append("## Failures")
        lines.append("")
        for item in failures:
            lines.append(f"- `{item['id']}`: {item.get('reason') or 'unspecified'}")
        lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def empty_payload(
    *,
    timestamp: str,
    envy_revision: str,
    mode: str,
    reference_client: str,
    reference_version: str,
    artifact_dir: str,
    network_class: str,
    git_sha_harness: str = "",
) -> Dict[str, Any]:
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "timestamp": timestamp,
        "harness_version": HARNESS_VERSION,
        "harness_git_sha": git_sha_harness or envy_revision,
        "envy_revision": envy_revision,
        "mode": mode,
        "reference_client": reference_client,
        "reference_version": reference_version,
        "network_class": network_class,
        "artifact_dir": artifact_dir,
        "scenarios": [],
        "notes": [
            "This report does not claim ENVY is fully interoperable with eMule/aMule.",
            "Public P2P network availability is never a required CI dependency.",
        ],
    }
