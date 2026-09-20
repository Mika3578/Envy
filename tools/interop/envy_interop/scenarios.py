"""Scenario registry and execution.

Production capability, harness automation, and live evidence are tracked
separately. A missing harness handler must not mark production as absent.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

from . import HARNESS_VERSION
from .config import ConfigError, HarnessConfig, validate_live_executables
from .constants import (
    ENVY_ADVERTISED,
    ENVY_CAPABILITY_MATRIX,
    ENVY_IMPLEMENTED,
    ENVY_KNOWN_ADVERTISE_DEBT,
    EvidenceClass,
    EvidenceState,
    HarnessState,
    NetworkClass,
    ProductionState,
    Result,
)
from .evidence import (
    EvidenceError,
    collect_hits_from_paths,
    extract_ed2k_frames,
    extract_frames,
    require_any_label_group,
    safe_evidence_source_name,
    summarize_hits,
    tcp_reassembly_blobs,
    write_evidence_summary,
)
from .fixtures import write_fixture
from .golden import GoldenError, ingest_hello, load_bytes, load_golden_json
from .hello import HelloParseError, compare_envy_advertisement, hello_evidence, parse_emule_info_tcp, parse_hello_tcp
from .isolation import IsolationRoot
from .pass_criteria import criteria_for
from .process import ProcessError, ProcessManager
from .report import ScenarioResult


@dataclass(frozen=True)
class ScenarioSpec:
    id: str
    title: str
    network: NetworkClass
    evidence: EvidenceClass
    phase: str  # "1" | "current" | "deferred"
    production: ProductionState
    harness: HarnessState
    evidence_state: EvidenceState
    requires_envy: bool = False
    requires_reference: bool = False
    requires_external: bool = False
    requires_hello_capture: bool = False
    requires_packet_evidence: bool = False
    evidence_labels: tuple = ()
    capability_key: str = ""


SCENARIOS: Dict[str, ScenarioSpec] = {}


def _add(spec: ScenarioSpec) -> None:
    SCENARIOS[spec.id] = spec


def _det(id_: str, title: str) -> ScenarioSpec:
    return ScenarioSpec(
        id=id_,
        title=title,
        network=NetworkClass.NONE,
        evidence=EvidenceClass.DETERMINISTIC,
        phase="1",
        production=ProductionState.IMPLEMENTED,
        harness=HarnessState.AUTOMATED,
        evidence_state=EvidenceState.NOT_APPLICABLE,
    )


def _live(
    id_: str,
    title: str,
    *,
    production: ProductionState,
    harness: HarnessState = HarnessState.EVIDENCE_HOOKS,
    evidence_state: EvidenceState = EvidenceState.UNVERIFIED,
    phase: str = "1",
    labels: tuple = (),
    capability_key: str = "",
    external: bool = False,
) -> ScenarioSpec:
    return ScenarioSpec(
        id=id_,
        title=title,
        network=NetworkClass.EXTERNAL if external else NetworkClass.LOCAL,
        evidence=EvidenceClass.PUBLIC_NETWORK if external else EvidenceClass.LOCAL_INTEGRATION,
        phase=phase,
        production=production,
        harness=harness,
        evidence_state=evidence_state,
        requires_envy=True,
        requires_reference=True,
        requires_external=external,
        requires_packet_evidence=bool(labels),
        evidence_labels=labels,
        capability_key=capability_key,
    )


def _absent(id_: str, title: str, *, phase: str = "deferred", capability_key: str = "") -> ScenarioSpec:
    return ScenarioSpec(
        id=id_,
        title=title,
        network=NetworkClass.LOCAL,
        evidence=EvidenceClass.LOCAL_INTEGRATION,
        phase=phase,
        production=ProductionState.NOT_IMPLEMENTED,
        harness=HarnessState.REGISTERED_ONLY,
        evidence_state=EvidenceState.NOT_APPLICABLE,
        capability_key=capability_key,
    )


# --- Phase 1 deterministic / baseline ---
_add(_det("harness_self_check", "Harness version and git SHA"))
_add(_det("envy_capability_honesty", "Advertised Hello bits vs implemented capabilities"))
_add(_det("golden_envy_hello_parse", "Parse committed Envy self-golden Hello"))
_add(_det("golden_envy_helloanswer_parse", "Parse committed Envy self-golden HelloAnswer"))
_add(_det("fixture_generation", "Deterministic harmless transfer fixture"))
_add(
    ScenarioSpec(
        "hello_capture_import",
        "Parse operator-supplied Hello capture",
        NetworkClass.NONE,
        EvidenceClass.CAPTURED_EVIDENCE,
        "1",
        ProductionState.IMPLEMENTED,
        HarnessState.AUTOMATED,
        EvidenceState.PENDING_OPERATOR,
        requires_hello_capture=True,
    )
)
_add(
    ScenarioSpec(
        "envy_startup",
        "Launch ENVY into an isolated profile",
        NetworkClass.LOCAL,
        EvidenceClass.LOCAL_INTEGRATION,
        "1",
        ProductionState.IMPLEMENTED,
        HarnessState.EVIDENCE_HOOKS,
        EvidenceState.PENDING_OPERATOR,
        requires_envy=True,
    )
)
_add(
    ScenarioSpec(
        "reference_startup",
        "Launch or attach eMule/aMule isolated",
        NetworkClass.LOCAL,
        EvidenceClass.LOCAL_INTEGRATION,
        "1",
        ProductionState.IMPLEMENTED,
        HarnessState.EVIDENCE_HOOKS,
        EvidenceState.PENDING_OPERATOR,
        requires_reference=True,
    )
)
_add(_live("ed2k_connection", "ED2K TCP connection establishment", production=ProductionState.IMPLEMENTED))
_add(
    _live(
        "hello",
        "Observe Hello (0x01)",
        production=ProductionState.IMPLEMENTED,
        labels=("hello",),
    )
)
_add(
    _live(
        "hello_answer",
        "Observe HelloAnswer (0x4C)",
        production=ProductionState.IMPLEMENTED,
        labels=("hello_answer",),
    )
)
_add(
    _live(
        "muleinfo",
        "Observe MuleInfo where applicable",
        production=ProductionState.IMPLEMENTED,
        labels=("muleinfo",),
    )
)
_add(
    _live(
        "capability_negotiation",
        "Capability negotiation from Hello-family evidence",
        production=ProductionState.IMPLEMENTED,
        # No evidence_labels: dedicated Hello parse + compare_envy_advertisement path.
    )
)
_add(_live("peer_transfer", "Basic peer transfer of the generated fixture", production=ProductionState.IMPLEMENTED))
_add(
    _live(
        "source_exchange",
        "Source Exchange observation",
        production=ProductionState.IMPLEMENTED,
        # SourceEx (0x81/0x82) or SourceEx2 (0x83/0x84) — see evidence groups.
        labels=("sourceex_req", "sourceex_ans"),
        capability_key="source_exchange",
    )
)
_add(
    _live(
        "large_file_capability",
        "Large-file capability where practical",
        production=ProductionState.IMPLEMENTED,
        capability_key="large_files",
        phase="current",
    )
)

# --- Current matrix (production present; live evidence pending) ---
_add(
    _live(
        "compressed_transfer_ref_to_envy",
        "reference → ENVY COMPRESSEDPART",
        production=ProductionState.IMPLEMENTED,
        labels=("compressedpart",),
        capability_key="compression_receive",
        phase="current",
    )
)
_add(
    _live(
        "compressed_transfer_envy_to_ref",
        "ENVY → reference COMPRESSEDPART",
        production=ProductionState.IMPLEMENTED,
        labels=("compressedpart",),
        capability_key="compression_send",
        phase="current",
    )
)
_add(
    _live(
        "compressed_transfer_i64",
        "COMPRESSEDPART_I64",
        production=ProductionState.IMPLEMENTED,
        labels=("compressedpart_i64",),
        capability_key="compression_send",
        phase="current",
    )
)
_add(
    _live(
        "compressed_transfer_uncompressed_fallback",
        "uncompressed fallback",
        production=ProductionState.IMPLEMENTED,
        capability_key="compression_send",
        phase="current",
    )
)
_add(
    _live(
        "lowid_highid_highid",
        "HighID ↔ HighID baseline",
        production=ProductionState.IMPLEMENTED,
        phase="current",
    )
)
_add(
    _live(
        "lowid_publicip_req",
        "PUBLICIP_REQ (0x97)",
        production=ProductionState.PARTIAL,
        labels=("publicip_req",),
        capability_key="publicip",
        phase="current",
    )
)
_add(
    _live(
        "lowid_publicip_answer",
        "PUBLICIP_ANSWER (0x98)",
        production=ProductionState.PARTIAL,
        labels=("publicip_answer",),
        capability_key="publicip",
        phase="current",
    )
)
_add(
    _live(
        "lowid_server_callback",
        "classic server callback",
        production=ProductionState.IMPLEMENTED,
        external=True,
        phase="current",
        capability_key="c2c_callback",
    )
)
_add(
    _live(
        "lowid_c2c_callback",
        "C2C CALLBACK (0x99)",
        production=ProductionState.PARTIAL,
        labels=("callback",),
        capability_key="c2c_callback",
        phase="current",
    )
)
_add(_absent("lowid_reaskcallback", "REASKCALLBACKTCP (Buddy required)", capability_key="reaskcallbacktcp"))
_add(_absent("lowid_buddy", "Buddy path", capability_key="buddy"))
_add(_absent("lowid_buddyping", "BUDDYPING", capability_key="buddy"))
_add(_absent("lowid_buddypong", "BUDDYPONG", capability_key="buddy"))

_add(
    ScenarioSpec(
        "kad_nodes_dat_local",
        "local nodes.dat v1/v2/v3 parse/bootstrap preparation",
        NetworkClass.NONE,
        EvidenceClass.LOCAL_DETERMINISTIC,
        "current",
        ProductionState.IMPLEMENTED,
        HarnessState.EVIDENCE_HOOKS,
        EvidenceState.UNVERIFIED,
        capability_key="",
    )
)
_add(
    _live(
        "kad_bootstrap",
        "Kad bootstrap",
        production=ProductionState.IMPLEMENTED,
        phase="current",
        external=True,
    )
)
_add(
    _live(
        "kad_hello",
        "Kad HELLO",
        production=ProductionState.IMPLEMENTED,
        labels=("kad_hello_req", "kad_hello_res"),
        phase="current",
    )
)
_add(
    _live(
        "kad_ping_pong",
        "Kad PING/PONG",
        production=ProductionState.IMPLEMENTED,
        labels=("kad_ping", "kad_pong"),
        phase="current",
    )
)
_add(
    _live(
        "kad_find_node",
        "Kad FIND_NODE",
        production=ProductionState.IMPLEMENTED,
        labels=("kad_find_node_req", "kad_find_node_res"),
        phase="current",
    )
)
_add(
    _live(
        "kad_search_source",
        "Kad SearchSource request",
        production=ProductionState.IMPLEMENTED,
        labels=("kad_search_source_req",),
        capability_key="kad_source_search",
        phase="current",
    )
)
_add(
    _live(
        "kad_search_res",
        "SEARCH_RES → ED2K source delivery",
        production=ProductionState.IMPLEMENTED,
        labels=("kad_search_res",),
        capability_key="kad_source_search",
        phase="current",
    )
)
_add(
    _live(
        "kad_routing",
        "routing-table behavior",
        production=ProductionState.IMPLEMENTED,
        capability_key="kad_routing",
        phase="current",
    )
)
_add(
    _live(
        "kad_tcp_firewall",
        "TCP firewall-check baseline",
        production=ProductionState.PARTIAL,
        labels=("kad_firewalled_req", "kad_firewalled_res"),
        capability_key="kad_tcp_firewall",
        phase="current",
    )
)
_add(_absent("kad_udp_firewall", "UDP firewall tester", capability_key="kad_udp_firewall"))
_add(_absent("kad_findbuddy", "FINDBUDDY", capability_key="buddy"))
_add(_absent("kad_buddy_lifecycle", "Buddy lifecycle", capability_key="buddy"))
_add(_absent("kad_callback", "Kad callback", capability_key="kad_callback"))
_add(
    ScenarioSpec(
        "optional_pcap",
        "Optional dumpcap/tshark capture availability",
        NetworkClass.NONE,
        EvidenceClass.DETERMINISTIC,
        "current",
        ProductionState.IMPLEMENTED,
        HarnessState.AUTOMATED,
        EvidenceState.NOT_APPLICABLE,
    )
)

PHASE1_IDS = [key for key, spec in SCENARIOS.items() if spec.phase == "1"]
CURRENT_IDS = [key for key, spec in SCENARIOS.items() if spec.phase in {"1", "current"}]
DEFERRED_IDS = [key for key, spec in SCENARIOS.items() if spec.phase == "deferred"]
ALL_IDS = list(SCENARIOS.keys())
# Back-compat alias used by older docs/tests
FUTURE_IDS = DEFERRED_IDS + [k for k, s in SCENARIOS.items() if s.phase == "current"]

ALIASES = {
    "phase1": PHASE1_IDS,
    "current": CURRENT_IDS,
    "deferred": DEFERRED_IDS,
    "future": FUTURE_IDS,
    "all": ALL_IDS,
}


@dataclass
class RunContext:
    cfg: HarnessConfig
    run_dir: Path
    isolation: IsolationRoot
    processes: ProcessManager
    logs_dir: Path
    git_sha: str
    packet_evidence_path: Optional[Path] = None
    # Owned capture lifecycle (set by runner when --live --enable-pcap succeeds).
    pcap_owned: Optional[object] = None
    pcap_path: Optional[Path] = None
    pcap_start_error: Optional[str] = None
    pcap_stopped: bool = False
    pcap_usable: Optional[bool] = None  # set after stop: True/False/None(pending)


Handler = Callable[[RunContext, ScenarioSpec], ScenarioResult]


def expand_selection(names: Sequence[str]) -> List[str]:
    selected: List[str] = []
    seen: Set[str] = set()
    for name in names:
        key = name.strip()
        if not key:
            continue
        group = ALIASES.get(key, [key])
        for item in group:
            if item not in SCENARIOS:
                raise ConfigError(f"unknown scenario: {item}")
            if item not in seen:
                selected.append(item)
                seen.add(item)
    if not selected:
        return list(PHASE1_IDS)
    return selected


def _state_fields(spec: ScenarioSpec) -> dict:
    return {
        "production_state": spec.production.value,
        "harness_state": spec.harness.value,
        "evidence_state": spec.evidence_state.value,
        "pass_criteria": criteria_for(spec.id),
        "capability_key": spec.capability_key or None,
    }


def _timed(spec: ScenarioSpec, fn: Callable[[], ScenarioResult]) -> ScenarioResult:
    started = time.monotonic()
    result = fn()
    result.duration_ms = int((time.monotonic() - started) * 1000)
    result.network_class = spec.network.value
    result.evidence_class = spec.evidence.value
    for key, value in _state_fields(spec).items():
        if not getattr(result, key, None):
            setattr(result, key, value)
    return result


def _skip(spec: ScenarioSpec, reason: str, **obs) -> ScenarioResult:
    return ScenarioResult(
        id=spec.id,
        result=Result.SKIP.value,
        reason=reason,
        observations=obs,
        **_state_fields(spec),
    )


def _fail(spec: ScenarioSpec, reason: str, **obs) -> ScenarioResult:
    return ScenarioResult(
        id=spec.id,
        result=Result.FAIL.value,
        reason=reason,
        observations=obs,
        **_state_fields(spec),
    )


def _pass(spec: ScenarioSpec, reason: str = "", **obs) -> ScenarioResult:
    return ScenarioResult(
        id=spec.id,
        result=Result.PASS.value,
        reason=reason,
        observations=obs,
        **_state_fields(spec),
    )


def _not_implemented(spec: ScenarioSpec, reason: str = "") -> ScenarioResult:
    text = reason or (
        f"Production capability is {spec.production.value}; harness={spec.harness.value}. "
        "This is not a silent claim that the feature is missing from the matrix only because "
        "automation is incomplete."
        if spec.production != ProductionState.NOT_IMPLEMENTED
        else "Production behavior is not implemented on current develop; scenario cannot PASS."
    )
    return ScenarioResult(
        id=spec.id,
        result=Result.NOT_IMPLEMENTED.value,
        reason=text,
        **_state_fields(spec),
    )


def _read_git_sha(repo_root: Path) -> str:
    git_dir = repo_root / ".git"
    if not git_dir.exists():
        return "unknown"
    try:
        import subprocess

        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
            shell=False,
        )
        if proc.returncode == 0:
            return proc.stdout.strip() or "unknown"
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    return "unknown"


def handle_harness_self_check(ctx: RunContext, spec: ScenarioSpec) -> ScenarioResult:
    return _pass(
        spec,
        "harness identity recorded",
        harness_version=HARNESS_VERSION,
        git_sha=ctx.git_sha,
    )


def handle_capability_honesty(ctx: RunContext, spec: ScenarioSpec) -> ScenarioResult:
    debt = [dict(item) for item in ENVY_KNOWN_ADVERTISE_DEBT]
    observations = {
        "advertised": dict(ENVY_ADVERTISED),
        "implemented": dict(ENVY_IMPLEMENTED),
        "capability_matrix": {k: dict(v) for k, v in ENVY_CAPABILITY_MATRIX.items()},
        "known_debt": debt,
        "issues": {
            "aich": 87,
            "secureident": 75,
            "cryptlayer": 121,
            "ext_multipacket": 129,
            "compression_send": 87,
            "kad": 86,
            "lowid_callback": 87,
            "live_evidence": 160,
        },
    }
    if ENVY_ADVERTISED["aich"] != 0 or ENVY_IMPLEMENTED["aich_c2c"]:
        return _fail(spec, "AICH table no longer matches develop honesty policy", **observations)
    if ENVY_ADVERTISED["secureident"] != 0 or ENVY_IMPLEMENTED["secureident_rsa"]:
        return _fail(spec, "SecureIdent table no longer matches #75", **observations)
    if ENVY_ADVERTISED["cryptlayer_supports"] != 0:
        return _fail(spec, "CryptLayer advertise bit changed; do not patch from this harness", **observations)
    if ENVY_ADVERTISED["ext_multipacket"] != 0:
        return _fail(spec, "Ext Multipacket advertise bit changed", **observations)
    if ENVY_ADVERTISED["kad"] != 0:
        return _fail(spec, "Kad nibble changed; Hello must stay 0 until Buddy/UDP firewall + live interop", **observations)
    if ENVY_ADVERTISED["compression"] != 1:
        return _fail(spec, "compression advertise nibble drifted from develop (expected 1)", **observations)
    if not ENVY_IMPLEMENTED["compression_send"]:
        return _fail(
            spec,
            "stale capability regression: compression_send must be True after #252",
            **observations,
        )
    if ENVY_KNOWN_ADVERTISE_DEBT:
        return _fail(
            spec,
            "ENVY_KNOWN_ADVERTISE_DEBT must be empty while compression advertise matches send",
            **observations,
        )
    if not ENVY_IMPLEMENTED["publicip"] or not ENVY_IMPLEMENTED["c2c_callback"]:
        return _fail(spec, "LowID PUBLICIP/CALLBACK baseline flags drifted", **observations)
    if not ENVY_IMPLEMENTED["kad_search_res_delivery"] or not ENVY_IMPLEMENTED["kad_search_source"]:
        return _fail(spec, "Kad SearchSource / SEARCH_RES flags drifted after #251/#261", **observations)
    if ENVY_IMPLEMENTED["buddy"] or ENVY_IMPLEMENTED["kad_udp_firewall"] or ENVY_IMPLEMENTED["reaskcallbacktcp"]:
        return _fail(spec, "Buddy/UDP-firewall/REASK unexpectedly marked implemented", **observations)
    return _pass(
        spec,
        "develop advertise/implement table recorded; compression_send=True; live evidence still #160",
        **observations,
    )


def _golden_path(ctx: RunContext, name: str) -> Path:
    return ctx.cfg.repo_root / "tools" / "interop" / "fixtures" / "golden" / name


def handle_golden_parse(ctx: RunContext, spec: ScenarioSpec) -> ScenarioResult:
    filename = (
        "envy-self-hello.json"
        if spec.id == "golden_envy_hello_parse"
        else "envy-self-helloanswer.json"
    )
    path = _golden_path(ctx, filename)
    try:
        meta = load_golden_json(path)
        parsed = parse_hello_tcp(bytes.fromhex(meta["tcp_frame_hex"]))
        cmp_ = compare_envy_advertisement(parsed)
    except (GoldenError, HelloParseError, OSError) as exc:
        return _fail(spec, str(exc))
    evidence = hello_evidence(parsed)
    if cmp_["mismatches"]:
        return _fail(spec, "golden Hello bits diverged from advertise table", **cmp_)
    return _pass(
        spec,
        f"parsed {path.name}",
        opcode=parsed.opcode,
        client_id=parsed.client_id,
        tcp_port=parsed.tcp_port,
        features1=parsed.features1,
        features2=parsed.features2,
        comparison=cmp_,
        evidence=evidence,
        artifacts=[str(path.relative_to(ctx.cfg.repo_root))],
    )


def handle_fixture(ctx: RunContext, spec: ScenarioSpec) -> ScenarioResult:
    target = ctx.isolation.share_dir()
    meta = write_fixture(target)
    path = target / meta.name
    try:
        rel = str(path.relative_to(ctx.run_dir))
    except ValueError:
        rel = str(path.relative_to(ctx.isolation.root))
    return _pass(
        spec,
        f"wrote {meta.name} ({meta.size} bytes)",
        size=meta.size,
        ed2k=meta.ed2k_hex,
        sha256=meta.sha256_hex,
        artifacts=[rel],
    )


def handle_hello_import(ctx: RunContext, spec: ScenarioSpec) -> ScenarioResult:
    if ctx.cfg.hello_capture is None:
        return _skip(spec, "no --hello-capture / ENVY_INTEROP_HELLO_CAPTURE supplied")
    dest = ctx.run_dir / "captures" / "ingested"
    try:
        meta = ingest_hello(
            ctx.cfg.hello_capture,
            dest,
            reference_client=ctx.cfg.resolved_reference_client(),
            reference_version=ctx.cfg.reference_version or "unspecified",
            direction="recv",
        )
        parsed = parse_hello_tcp(bytes.fromhex(meta["tcp_frame_hex"]))
    except (GoldenError, HelloParseError) as exc:
        return _fail(spec, str(exc))
    cmp_ = compare_envy_advertisement(parsed) if ctx.cfg.resolved_reference_client() == "none" else {}
    return _pass(
        spec,
        "imported Hello capture (sanitized candidate, not auto-committed)",
        opcode=parsed.opcode,
        features1=parsed.features1,
        features2=parsed.features2,
        comparison=cmp_,
        evidence=hello_evidence(parsed),
        artifacts=["captures/ingested/hello-candidate.json"],
    )


def handle_optional_pcap(ctx: RunContext, spec: ScenarioSpec) -> ScenarioResult:
    from .capture import find_capture_tool

    tool = find_capture_tool()
    tool_name = Path(tool).name if tool else "capture"
    if ctx.pcap_start_error:
        return _fail(
            spec,
            f"owned capture failed to start: {ctx.pcap_start_error}",
            tool=tool_name,
        )
    if ctx.pcap_owned is not None:
        owned = ctx.pcap_owned
        # Detect early death (permissions / bad iface) before harness teardown.
        poll = getattr(owned, "poll", None)
        if callable(poll) and not ctx.pcap_stopped:
            code = poll()
            if code is not None and int(code) != 0:
                return _fail(
                    spec,
                    f"capture process exited early with code {code} before harness stop",
                    tool=tool_name,
                    exit_code=int(code),
                )
        if not ctx.pcap_stopped:
            # Do not PASS until runner confirms stop + usable outcome.
            return _skip(
                spec,
                f"owned capture started via {tool_name}; PASS deferred until harness teardown",
                tool=tool_name,
                pcap=ctx.pcap_path.name if ctx.pcap_path else "",
            )
        if ctx.pcap_usable is False:
            return _fail(
                spec,
                "owned capture stopped but produced no usable pcap "
                f"(exit={getattr(owned, 'exit_code', None)})",
                tool=tool_name,
            )
        return _pass(
            spec,
            f"owned capture started and stopped via {tool_name}",
            tool=tool_name,
            pcap=ctx.pcap_path.name if ctx.pcap_path else "",
        )
    if not tool:
        return _skip(
            spec,
            "dumpcap/tshark/tcpdump not found; pcap remains optional (do not install from harness)",
        )
    # Availability alone is not an owned capture start/stop (pass criterion).
    if ctx.cfg.dry_run or not ctx.cfg.live or not ctx.cfg.enable_pcap:
        return _skip(
            spec,
            f"capture tool available ({tool_name}) but no owned capture was started "
            "(need --live --enable-pcap). Availability-only must not PASS.",
            tool=tool_name,
        )
    return _skip(
        spec,
        f"capture tool {tool_name} present and --enable-pcap set, but owned capture "
        "did not start (see logs/pcap-start-error.txt or pcap-skipped.txt)",
        tool=tool_name,
    )


def handle_kad_nodes_dat_local(ctx: RunContext, spec: ScenarioSpec) -> ScenarioResult:
    """Local deterministic evidence hook — not live Kad interop.

    Dry-run writing a note alone must SKIP (not PASS): that is documentation,
    not parser or bootstrap evidence. EnvyTests (test_kad_nodes_dat.cpp) owns
    the real parse coverage; operators attach sanitized Windows logs for live.
    """
    note_path = ctx.run_dir / "evidence" / "kad-nodes-dat-note.txt"
    note_path.parent.mkdir(parents=True, exist_ok=True)
    note_path.write_text(
        "Local nodes.dat v1/v2/v3 parse lives in Envy/KadNodesDat.h + EnvyTests "
        "(test_kad_nodes_dat.cpp). This harness scenario records that production "
        "support exists (#254) and that live Kad bootstrap/interop remains unverified (#160).\n"
        "Operator Windows run: place a reviewed nodes.dat under the isolated profile "
        "DataPath and attach sanitized bootstrap logs — do not invent captures here.\n",
        encoding="utf-8",
    )
    return _skip(
        spec,
        "nodes.dat parse is covered by EnvyTests (#254); harness does not claim PASS "
        "from a documentation note. Attach sanitized Windows bootstrap logs for "
        "live_evidence claims (#160).",
        artifacts=["evidence/kad-nodes-dat-note.txt"],
    )


def _live_gate(ctx: RunContext, spec: ScenarioSpec) -> Optional[ScenarioResult]:
    if spec.production == ProductionState.NOT_IMPLEMENTED:
        return _not_implemented(spec)
    if spec.requires_external and not ctx.cfg.allow_external_network:
        return _skip(spec, "external ED2K/Kad network required; pass --allow-external-network")
    if ctx.cfg.dry_run or not ctx.cfg.live:
        return _skip(
            spec,
            "dry-run / no --live: production="
            f"{spec.production.value}, harness={spec.harness.value}, "
            f"live_evidence={spec.evidence_state.value}. "
            "Not production NOT_IMPLEMENTED.",
        )
    try:
        reasons = validate_live_executables(
            ctx.cfg, require_envy=spec.requires_envy
        )
    except ConfigError as exc:
        return _fail(spec, str(exc))
    if spec.requires_envy and any("ENVY executable" in item for item in reasons):
        return _skip(spec, reasons[0])
    if spec.requires_reference and ctx.cfg.selected_reference_exe() is None:
        return _skip(spec, "no eMule/aMule executable configured")
    return None


def handle_envy_startup(ctx: RunContext, spec: ScenarioSpec) -> ScenarioResult:
    gated = _live_gate(ctx, spec)
    if gated:
        return gated
    exe = ctx.cfg.envy_exe
    assert exe is not None
    argv = [str(exe), "-nosplash", "-nowarn"]
    log_dir = ctx.logs_dir / "envy"
    try:
        owned = ctx.processes.launch(
            "envy",
            argv,
            cwd=ctx.isolation.envy_profile(),
            extra_env=ctx.isolation.envy_launch_env(),
            stdout_path=log_dir / "stdout.bin",
            stderr_path=log_dir / "stderr.bin",
        )
        ctx.processes.wait_running(owned, ctx.cfg.startup_timeout_sec)
    except ProcessError as exc:
        return _fail(spec, str(exc), argv=argv)
    return _pass(
        spec,
        f"ENVY running pid={owned.pid}",
        pid=owned.pid,
        isolated_profile="scratch/.../profiles/envy",
        limitation="Envy has no --datadir; APPDATA is redirected. Global\\Envy mutex prevents a second instance; the harness never kills a user Envy.",
        pass_note="Startup PASS is process-alive only; protocol scenarios still need packet evidence.",
    )


def _reference_argv(ctx: RunContext) -> List[str]:
    exe = ctx.cfg.selected_reference_exe()
    assert exe is not None
    client = ctx.cfg.resolved_reference_client()
    if client in {"amule", "amuled"} or exe.name.lower().startswith("amule"):
        cfg_dir = ctx.isolation.amule_profile()
        return [str(exe), "-c", str(cfg_dir)]
    return [str(exe)]


def handle_reference_startup(ctx: RunContext, spec: ScenarioSpec) -> ScenarioResult:
    gated = _live_gate(ctx, spec)
    if gated:
        return gated
    argv = _reference_argv(ctx)
    client = ctx.cfg.resolved_reference_client()
    profile = ctx.isolation.amule_profile() if client.startswith("amule") else ctx.isolation.emule_profile()
    env = ctx.isolation.emule_launch_env()
    if client.startswith("amule"):
        env = {"HOME": str(profile)}
    log_dir = ctx.logs_dir / "reference"
    try:
        owned = ctx.processes.launch(
            "reference",
            argv,
            cwd=profile,
            extra_env=env,
            stdout_path=log_dir / "stdout.bin",
            stderr_path=log_dir / "stderr.bin",
        )
        ctx.processes.wait_running(owned, ctx.cfg.startup_timeout_sec)
    except ProcessError as exc:
        return _fail(spec, str(exc), argv=argv)
    return _pass(
        spec,
        f"{client} running pid={owned.pid}",
        pid=owned.pid,
        argv_note="arguments passed as a list (paths with spaces/Unicode are safe)",
        limitation=(
            "eMule has no documented --config-dir in this harness; APPDATA is redirected. "
            "aMule uses -c <isolated>. Existing user instances are never killed."
        ),
    )


def _frame_slice(raw: bytes, hit) -> bytes:
    return raw[hit.offset : hit.offset + hit.length]


def _first_hit(hits, *labels: str):
    wanted = set(labels)
    for hit in hits:
        if hit.label in wanted and not hit.details.get("parse_error"):
            return hit
    return None


# Scenarios where matching wire labels/parse is enough for packet-evidence PASS.
# Transfer/delivery/consumption criteria still require live operator logs.
_PACKET_WIRE_PASS_IDS = frozenset(
    {
        "hello",
        "hello_answer",
        "muleinfo",
        "capability_negotiation",
        "source_exchange",
        "lowid_publicip_req",
        "lowid_publicip_answer",
        "kad_hello",
        "kad_ping_pong",
        "kad_find_node",
        # kad_search_source stays SKIP from opcode-only dumps — needs app-trigger evidence.
    }
)


# Label groups that satisfy the same scenario (any one group is enough).
_LABEL_ALTERNATIVES: Dict[str, Tuple[Tuple[str, ...], ...]] = {
    "source_exchange": (
        ("sourceex_req", "sourceex_ans"),
        ("sourceex2_req", "sourceex2_ans"),
    ),
}


def _evidence_label_groups(spec: ScenarioSpec) -> Tuple[Tuple[str, ...], ...]:
    alt = _LABEL_ALTERNATIVES.get(spec.id)
    if alt:
        return alt
    if spec.evidence_labels:
        return (tuple(spec.evidence_labels),)
    return tuple()


def _try_packet_evidence(ctx: RunContext, spec: ScenarioSpec) -> Optional[ScenarioResult]:
    """Attempt PASS from --packet-evidence / --hello-capture / evidence dir.

    Label matching aggregates across candidate files (and TCP-concat reassembles
    ED2K frames split across segments). Per-file Hello/MuleInfo parse paths
    remain for dedicated handlers that need a concrete frame slice.
    """
    configured: List[Path] = []
    if ctx.cfg.packet_evidence is not None:
        configured.append(ctx.cfg.packet_evidence)
    if ctx.cfg.hello_capture is not None:
        configured.append(ctx.cfg.hello_capture)
    missing_configured = [p for p in configured if p is not None and not p.is_file()]
    if missing_configured and (
        spec.evidence_labels
        or spec.id in {"hello", "hello_answer", "muleinfo", "capability_negotiation"}
    ):
        return _fail(
            spec,
            f"configured evidence path missing ({len(missing_configured)} path(s))",
        )

    candidates: List[Path] = list(configured)
    if ctx.packet_evidence_path is not None:
        candidates.append(ctx.packet_evidence_path)
    evidence_dir = ctx.run_dir / "captures" / "evidence"
    if evidence_dir.is_dir():
        candidates.extend(sorted(p for p in evidence_dir.glob("*") if p.is_file()))

    files = [p for p in candidates if p and p.is_file()]
    label_groups = _evidence_label_groups(spec)
    wanted_labels = {lab for group in label_groups for lab in group}
    if label_groups and files:
        try:
            hits = collect_hits_from_paths(files)
            summary = summarize_hits(hits)
            ok, reason, matched = require_any_label_group(hits, label_groups)
            if ok:
                dest_dir = ctx.run_dir / "evidence" / spec.id
                dest_dir.mkdir(parents=True, exist_ok=True)
                summary["source_name"] = safe_evidence_source_name("aggregated")
                summary["required_ok"] = True
                summary["required_reason"] = reason
                summary["matched_labels"] = list(matched)
                write_evidence_summary(dest_dir / "packet-evidence.json", summary)
                artifacts = [f"evidence/{spec.id}/packet-evidence.json"]
                if spec.id not in _PACKET_WIRE_PASS_IDS:
                    return _skip(
                        spec,
                        f"packet labels {list(matched)} present across "
                        f"{len(files)} evidence file(s), "
                        "but documented transaction criteria need live operator logs "
                        "(not opcode-only PASS)",
                        evidence=summary,
                        artifacts=artifacts,
                    )
                return _pass(
                    spec,
                    f"packet evidence matched labels {list(matched)} across "
                    f"{len(files)} evidence file(s)",
                    evidence=summary,
                    artifacts=artifacts,
                )
            # Malformed present labels FAIL even when other required labels are missing.
            malformed = [
                h
                for h in hits
                if h.label in wanted_labels and h.details.get("parse_error")
            ]
            if malformed:
                detail = "; ".join(
                    f"{h.label}: {h.details.get('parse_error')}" for h in malformed[:3]
                )
                return _fail(spec, f"malformed packet evidence: {detail}", evidence=summary)
        except (EvidenceError, GoldenError, OSError):
            return _fail(spec, "packet evidence read failed (details in local logs only)")

    for path in files:
        try:
            raw = load_bytes(path)
            hits = extract_frames(raw)
            if spec.id in {"hello", "hello_answer"}:
                label = "hello" if spec.id == "hello" else "hello_answer"
                malformed = [
                    h for h in hits if h.label == label and h.details.get("parse_error")
                ]
                if malformed and _first_hit(hits, label) is None:
                    return _fail(spec, f"malformed {label} frame in packet evidence")
                hit = _first_hit(hits, label)
                if hit is None:
                    continue
                parsed = parse_hello_tcp(_frame_slice(raw, hit))
                return _pass(
                    spec,
                    f"Hello-family packet parsed from multi-frame capture "
                    f"({safe_evidence_source_name(path.name)})",
                    comparison=compare_envy_advertisement(parsed),
                    evidence=hello_evidence(parsed),
                )
            if spec.id == "muleinfo":
                hit = _first_hit(hits, "muleinfo", "muleinfo_answer")
                if hit is None:
                    continue
                info = parse_emule_info_tcp(_frame_slice(raw, hit))
                return _pass(spec, "MuleInfo frame parsed from multi-frame capture", **info)
        except (EvidenceError, HelloParseError, GoldenError, OSError):
            continue

    # capability_negotiation needs Hello + HelloAnswer, possibly in separate files.
    if spec.id == "capability_negotiation" and files:
        try:
            hello_raw = hello_hit = None
            answer_raw = answer_hit = None
            for blob in tcp_reassembly_blobs(files):
                concat_hits = extract_ed2k_frames(blob)
                if hello_hit is None:
                    hello_hit = _first_hit(concat_hits, "hello")
                    if hello_hit is not None:
                        hello_raw = blob
                if answer_hit is None:
                    answer_hit = _first_hit(concat_hits, "hello_answer")
                    if answer_hit is not None:
                        answer_raw = blob
                if hello_hit is not None and answer_hit is not None:
                    break
            if hello_hit is None or answer_hit is None:
                hello_hit = answer_hit = None
                hello_raw = answer_raw = None
                saw_malformed = False
                for path in files:
                    raw = load_bytes(path)
                    hits = extract_frames(raw)
                    if any(
                        h.label in {"hello", "hello_answer"} and h.details.get("parse_error")
                        for h in hits
                    ) and _first_hit(hits, "hello", "hello_answer") is None:
                        saw_malformed = True
                    if hello_hit is None:
                        hit = _first_hit(hits, "hello")
                        if hit is not None:
                            hello_hit, hello_raw = hit, raw
                    if answer_hit is None:
                        hit = _first_hit(hits, "hello_answer")
                        if hit is not None:
                            answer_hit, answer_raw = hit, raw
                if saw_malformed and (hello_hit is None or answer_hit is None):
                    return _fail(spec, "malformed Hello-family frame in packet evidence")
            if hello_hit is not None and answer_hit is not None and hello_raw and answer_raw:
                parsed_hello = parse_hello_tcp(_frame_slice(hello_raw, hello_hit))
                parsed_answer = parse_hello_tcp(_frame_slice(answer_raw, answer_hit))
                cmp_hello = compare_envy_advertisement(parsed_hello)
                cmp_answer = compare_envy_advertisement(parsed_answer)
                if ctx.cfg.resolved_reference_client() == "none":
                    bad = list(cmp_hello.get("mismatches") or []) + list(
                        cmp_answer.get("mismatches") or []
                    )
                    if bad:
                        return _fail(
                            spec,
                            "capability mismatches vs ENVY advertise table",
                            comparison={"hello": cmp_hello, "hello_answer": cmp_answer},
                            mismatches=bad,
                        )
                return _pass(
                    spec,
                    "capability bits recorded from Hello + HelloAnswer capture",
                    comparison={"hello": cmp_hello, "hello_answer": cmp_answer},
                    evidence={
                        "hello": hello_evidence(parsed_hello),
                        "hello_answer": hello_evidence(parsed_answer),
                    },
                )
        except (EvidenceError, HelloParseError, GoldenError, OSError):
            pass
    return None


def handle_live_observe(ctx: RunContext, spec: ScenarioSpec) -> ScenarioResult:
    """Protocol scenarios require packet/log evidence — never fake PASS from process alive."""
    if spec.production == ProductionState.NOT_IMPLEMENTED:
        return _not_implemented(spec)
    # Evidence can PASS even without --live (operator-supplied capture).
    evidenced = _try_packet_evidence(ctx, spec)
    if evidenced is not None:
        return evidenced
    gated = _live_gate(ctx, spec)
    if gated:
        return gated
    return _skip(
        spec,
        "no packet/log evidence collected yet; stage isolated profiles and attach "
        "logs/captures (--packet-evidence / captures/evidence). "
        f"PASS requires: {criteria_for(spec.id)} "
        "A live launch alone is not a protocol PASS.",
    )


HANDLERS: Dict[str, Handler] = {
    "harness_self_check": handle_harness_self_check,
    "envy_capability_honesty": handle_capability_honesty,
    "golden_envy_hello_parse": handle_golden_parse,
    "golden_envy_helloanswer_parse": handle_golden_parse,
    "fixture_generation": handle_fixture,
    "hello_capture_import": handle_hello_import,
    "optional_pcap": handle_optional_pcap,
    "kad_nodes_dat_local": handle_kad_nodes_dat_local,
    "envy_startup": handle_envy_startup,
    "reference_startup": handle_reference_startup,
}


def _default_handler(ctx: RunContext, spec: ScenarioSpec) -> ScenarioResult:
    if spec.production == ProductionState.NOT_IMPLEMENTED:
        return _not_implemented(spec)
    if spec.harness in {HarnessState.EVIDENCE_HOOKS, HarnessState.REGISTERED_ONLY}:
        return handle_live_observe(ctx, spec)
    return _not_implemented(spec, "no handler registered for automated scenario")


def run_scenario(ctx: RunContext, spec: ScenarioSpec) -> ScenarioResult:
    def inner() -> ScenarioResult:
        handler = HANDLERS.get(spec.id, _default_handler)
        try:
            return handler(ctx, spec)
        except Exception as exc:  # noqa: BLE001 — scenario isolation
            return _fail(spec, f"unhandled error: {exc}")

    return _timed(spec, inner)
