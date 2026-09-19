"""Scenario registry and execution.

Phase 1 implements harness mechanics, golden Hello parse, capability honesty,
isolated launch hooks, and evidence collection. Future compressed-transfer,
LowID/callback, and Kad scenarios are registered as NOT_IMPLEMENTED.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Set

from . import HARNESS_VERSION
from .config import ConfigError, HarnessConfig, validate_live_executables
from .constants import (
    ENVY_ADVERTISED,
    ENVY_IMPLEMENTED,
    ENVY_KNOWN_ADVERTISE_DEBT,
    EvidenceClass,
    NetworkClass,
    Result,
)
from .fixtures import write_fixture
from .golden import GoldenError, ingest_hello, load_golden_json
from .hello import HelloParseError, compare_envy_advertisement, parse_hello_tcp
from .process import ProcessError, ProcessManager
from .report import ScenarioResult


@dataclass(frozen=True)
class ScenarioSpec:
    id: str
    title: str
    network: NetworkClass
    evidence: EvidenceClass
    phase: str  # "1" or "future"
    implemented: bool
    requires_envy: bool = False
    requires_reference: bool = False
    requires_external: bool = False
    requires_hello_capture: bool = False


SCENARIOS: Dict[str, ScenarioSpec] = {}


def _add(spec: ScenarioSpec) -> None:
    SCENARIOS[spec.id] = spec


_add(ScenarioSpec("harness_self_check", "Harness version and git SHA", NetworkClass.NONE, EvidenceClass.DETERMINISTIC, "1", True))
_add(ScenarioSpec("envy_capability_honesty", "Advertised Hello bits vs implemented capabilities", NetworkClass.NONE, EvidenceClass.DETERMINISTIC, "1", True))
_add(ScenarioSpec("golden_envy_hello_parse", "Parse committed Envy self-golden Hello", NetworkClass.NONE, EvidenceClass.DETERMINISTIC, "1", True))
_add(ScenarioSpec("golden_envy_helloanswer_parse", "Parse committed Envy self-golden HelloAnswer", NetworkClass.NONE, EvidenceClass.DETERMINISTIC, "1", True))
_add(ScenarioSpec("fixture_generation", "Deterministic harmless transfer fixture", NetworkClass.NONE, EvidenceClass.DETERMINISTIC, "1", True))
_add(ScenarioSpec("hello_capture_import", "Parse operator-supplied Hello capture", NetworkClass.NONE, EvidenceClass.CAPTURED_EVIDENCE, "1", True, requires_hello_capture=True))
_add(ScenarioSpec("envy_startup", "Launch ENVY into an isolated profile", NetworkClass.LOCAL, EvidenceClass.LOCAL_INTEGRATION, "1", True, requires_envy=True))
_add(ScenarioSpec("reference_startup", "Launch or attach eMule/aMule isolated", NetworkClass.LOCAL, EvidenceClass.LOCAL_INTEGRATION, "1", True, requires_reference=True))
_add(ScenarioSpec("ed2k_connection", "ED2K TCP connection establishment", NetworkClass.LOCAL, EvidenceClass.LOCAL_INTEGRATION, "1", True, requires_envy=True, requires_reference=True))
_add(ScenarioSpec("hello", "Observe Hello (0x01)", NetworkClass.LOCAL, EvidenceClass.LOCAL_INTEGRATION, "1", True, requires_envy=True, requires_reference=True))
_add(ScenarioSpec("hello_answer", "Observe HelloAnswer (0x4C)", NetworkClass.LOCAL, EvidenceClass.LOCAL_INTEGRATION, "1", True, requires_envy=True, requires_reference=True))
_add(ScenarioSpec("muleinfo", "Observe MuleInfo where applicable", NetworkClass.LOCAL, EvidenceClass.LOCAL_INTEGRATION, "1", True, requires_envy=True, requires_reference=True))
_add(ScenarioSpec("peer_transfer", "Basic peer transfer of the generated fixture", NetworkClass.LOCAL, EvidenceClass.LOCAL_INTEGRATION, "1", True, requires_envy=True, requires_reference=True))
_add(ScenarioSpec("source_exchange", "Source Exchange observation", NetworkClass.LOCAL, EvidenceClass.LOCAL_INTEGRATION, "1", True, requires_envy=True, requires_reference=True))

# Future matrix — registered so later PRs do not redesign the runner.
_add(ScenarioSpec("compressed_transfer_ref_to_envy", "reference → ENVY COMPRESSEDPART", NetworkClass.LOCAL, EvidenceClass.LOCAL_INTEGRATION, "future", False))
_add(ScenarioSpec("compressed_transfer_envy_to_ref", "ENVY → reference COMPRESSEDPART", NetworkClass.LOCAL, EvidenceClass.LOCAL_INTEGRATION, "future", False))
_add(ScenarioSpec("compressed_transfer_i64", "COMPRESSEDPART_I64", NetworkClass.LOCAL, EvidenceClass.LOCAL_INTEGRATION, "future", False))
_add(ScenarioSpec("compressed_transfer_uncompressed_fallback", "uncompressed fallback", NetworkClass.LOCAL, EvidenceClass.LOCAL_INTEGRATION, "future", False))
_add(ScenarioSpec("lowid_highid_highid", "HighID ↔ HighID", NetworkClass.LOCAL, EvidenceClass.LOCAL_INTEGRATION, "future", False))
_add(ScenarioSpec("lowid_highid_lowid", "HighID ↔ LowID", NetworkClass.LOCAL, EvidenceClass.LOCAL_INTEGRATION, "future", False))
_add(ScenarioSpec("lowid_server_callback", "server callback", NetworkClass.EXTERNAL, EvidenceClass.PUBLIC_NETWORK, "future", False, requires_external=True))
_add(ScenarioSpec("lowid_emule_extended_callback", "eMule extended callback", NetworkClass.LOCAL, EvidenceClass.LOCAL_INTEGRATION, "future", False))
_add(ScenarioSpec("lowid_buddy", "Buddy path", NetworkClass.LOCAL, EvidenceClass.LOCAL_INTEGRATION, "future", False))
_add(ScenarioSpec("lowid_reaskcallback", "REASKCALLBACK", NetworkClass.LOCAL, EvidenceClass.LOCAL_INTEGRATION, "future", False))
_add(ScenarioSpec("lowid_firewall", "firewall behavior", NetworkClass.LOCAL, EvidenceClass.LOCAL_INTEGRATION, "future", False))
_add(ScenarioSpec("kad_bootstrap", "Kad bootstrap", NetworkClass.EXTERNAL, EvidenceClass.PUBLIC_NETWORK, "future", False, requires_external=True))
_add(ScenarioSpec("kad_hello", "Kad HELLO", NetworkClass.LOCAL, EvidenceClass.LOCAL_INTEGRATION, "future", False))
_add(ScenarioSpec("kad_ping_pong", "Kad PING/PONG", NetworkClass.LOCAL, EvidenceClass.LOCAL_INTEGRATION, "future", False))
_add(ScenarioSpec("kad_find_node", "Kad FIND_NODE", NetworkClass.LOCAL, EvidenceClass.LOCAL_INTEGRATION, "future", False))
_add(ScenarioSpec("kad_source_search", "Kad source search", NetworkClass.LOCAL, EvidenceClass.LOCAL_INTEGRATION, "future", False))
_add(ScenarioSpec("kad_search_res", "SEARCH_RES source delivery", NetworkClass.LOCAL, EvidenceClass.LOCAL_INTEGRATION, "future", False))
_add(ScenarioSpec("kad_publish_source", "publish source", NetworkClass.LOCAL, EvidenceClass.LOCAL_INTEGRATION, "future", False))
_add(ScenarioSpec("kad_routing", "routing maintenance", NetworkClass.LOCAL, EvidenceClass.LOCAL_INTEGRATION, "future", False))
_add(ScenarioSpec("kad_firewall_buddy", "Kad firewall/Buddy paths", NetworkClass.LOCAL, EvidenceClass.LOCAL_INTEGRATION, "future", False))

PHASE1_IDS = [key for key, spec in SCENARIOS.items() if spec.phase == "1"]
FUTURE_IDS = [key for key, spec in SCENARIOS.items() if spec.phase == "future"]
ALL_IDS = list(SCENARIOS.keys())

ALIASES = {
    "phase1": PHASE1_IDS,
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


def _timed(spec: ScenarioSpec, fn: Callable[[], ScenarioResult]) -> ScenarioResult:
    started = time.monotonic()
    result = fn()
    result.duration_ms = int((time.monotonic() - started) * 1000)
    result.network_class = spec.network.value
    result.evidence_class = spec.evidence.value
    return result


def _skip(spec: ScenarioSpec, reason: str) -> ScenarioResult:
    return ScenarioResult(id=spec.id, result=Result.SKIP.value, reason=reason)


def _fail(spec: ScenarioSpec, reason: str, **obs) -> ScenarioResult:
    return ScenarioResult(id=spec.id, result=Result.FAIL.value, reason=reason, observations=obs)


def _pass(spec: ScenarioSpec, reason: str = "", **obs) -> ScenarioResult:
    return ScenarioResult(id=spec.id, result=Result.PASS.value, reason=reason, observations=obs)


def _not_implemented(spec: ScenarioSpec) -> ScenarioResult:
    return ScenarioResult(
        id=spec.id,
        result=Result.NOT_IMPLEMENTED.value,
        reason="Registered for a later PR; not implemented in phase 1.",
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
        "known_debt": debt,
        "issues": {
            "aich": 87,
            "secureident": 75,
            "cryptlayer": 121,
            "ext_multipacket": 129,
            "compression_send": 87,
            "kad": 86,
            "lowid_callback": 87,
        },
    }
    # Honesty check PASSES when the table is internally consistent: advertised
    # zeros for unimplemented AICH/SecureIdent/CryptLayer/ExtMP/Kad, and the
    # known compression-send debt is explicitly recorded rather than hidden.
    if ENVY_ADVERTISED["aich"] != 0 or ENVY_IMPLEMENTED["aich_c2c"]:
        return _fail(spec, "AICH table no longer matches develop honesty policy", **observations)
    if ENVY_ADVERTISED["secureident"] != 0 or ENVY_IMPLEMENTED["secureident_rsa"]:
        return _fail(spec, "SecureIdent table no longer matches #75", **observations)
    if ENVY_ADVERTISED["cryptlayer_supports"] != 0:
        return _fail(spec, "CryptLayer advertise bit changed; do not patch from this harness", **observations)
    if ENVY_ADVERTISED["ext_multipacket"] != 0:
        return _fail(spec, "Ext Multipacket advertise bit changed", **observations)
    if ENVY_ADVERTISED["kad"] != 0:
        return _fail(spec, "Kad nibble changed; live Kad remains unverified (#86)", **observations)
    if ENVY_ADVERTISED["compression"] != 1 or ENVY_IMPLEMENTED["compression_send"]:
        return _fail(
            spec,
            "compression advertise/implement table drifted; update docs, do not silent-patch",
            **observations,
        )
    return _pass(spec, "develop advertise/implement table recorded; known debt listed", **observations)


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
        artifacts=["captures/ingested/hello-candidate.json"],
    )


def _live_gate(ctx: RunContext, spec: ScenarioSpec) -> Optional[ScenarioResult]:
    if not spec.implemented:
        return _not_implemented(spec)
    if spec.requires_external and not ctx.cfg.allow_external_network:
        return _skip(spec, "external ED2K/Kad network required; pass --allow-external-network")
    if ctx.cfg.dry_run or not ctx.cfg.live:
        return _skip(spec, "dry-run (pass --live to launch processes)")
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
    )


def _reference_argv(ctx: RunContext) -> List[str]:
    exe = ctx.cfg.selected_reference_exe()
    assert exe is not None
    client = ctx.cfg.resolved_reference_client()
    if client in {"amule", "amuled"} or exe.name.lower().startswith("amule"):
        cfg_dir = ctx.isolation.amule_profile()
        return [str(exe), "-c", str(cfg_dir)]
    # eMule Community: no supported isolated-config CLI in this harness.
    # APPDATA redirect only; never write a config folder next to emule.exe.
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


def handle_live_observe(ctx: RunContext, spec: ScenarioSpec) -> ScenarioResult:
    """Connection/Hello/MuleInfo/transfer/SourceEx: require evidence, never fake PASS."""
    gated = _live_gate(ctx, spec)
    if gated:
        return gated
    if spec.id in {"hello", "hello_answer"} and ctx.cfg.hello_capture:
        try:
            raw = ctx.cfg.hello_capture.read_bytes()
            # Reuse ingest parser via golden.load
            from .golden import load_bytes

            parsed = parse_hello_tcp(load_bytes(ctx.cfg.hello_capture))
            expected = 0x01 if spec.id == "hello" else 0x4C
            if parsed.opcode != expected:
                return _fail(spec, f"capture opcode 0x{parsed.opcode:02X} != 0x{expected:02X}")
            cmp_ = compare_envy_advertisement(parsed)
            return _pass(spec, "Hello-family packet parsed from supplied capture", comparison=cmp_)
        except (HelloParseError, OSError, GoldenError) as exc:
            return _fail(spec, str(exc))
    return _skip(
        spec,
        "no packet/log evidence collected yet; stage isolated profiles and attach logs/captures. "
        "Do not treat a live launch as a protocol PASS.",
    )


HANDLERS: Dict[str, Handler] = {
    "harness_self_check": handle_harness_self_check,
    "envy_capability_honesty": handle_capability_honesty,
    "golden_envy_hello_parse": handle_golden_parse,
    "golden_envy_helloanswer_parse": handle_golden_parse,
    "fixture_generation": handle_fixture,
    "hello_capture_import": handle_hello_import,
    "envy_startup": handle_envy_startup,
    "reference_startup": handle_reference_startup,
    "ed2k_connection": handle_live_observe,
    "hello": handle_live_observe,
    "hello_answer": handle_live_observe,
    "muleinfo": handle_live_observe,
    "peer_transfer": handle_live_observe,
    "source_exchange": handle_live_observe,
}


def run_scenario(ctx: RunContext, spec: ScenarioSpec) -> ScenarioResult:
    def inner() -> ScenarioResult:
        if not spec.implemented:
            return _not_implemented(spec)
        handler = HANDLERS.get(spec.id)
        if handler is None:
            return _not_implemented(spec)
        try:
            return handler(ctx, spec)
        except Exception as exc:  # noqa: BLE001 — scenario isolation
            return _fail(spec, f"unhandled error: {exc}")

    return _timed(spec, inner)
