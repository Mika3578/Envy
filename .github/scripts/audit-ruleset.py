#!/usr/bin/env python3
"""Read-only drift report for Protect develop vs desired policy JSON."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DESIRED_PATH = REPO_ROOT / ".github" / "rulesets" / "protect-develop.desired.json"
DEFAULT_RULESET_ID = 16457466


def _path_escapes_repo(path: Path) -> bool:
    """True when path resolves outside REPO_ROOT (absolute-under-repo is allowed)."""
    text = str(path)
    # Reject UNC / device paths that are never repo-relative.
    if text.startswith("\\\\") or text.startswith("//"):
        return True
    try:
        resolved = path.resolve() if path.is_absolute() else (REPO_ROOT / path).resolve()
        resolved.relative_to(REPO_ROOT.resolve())
    except ValueError:
        return True
    return False


def load_json(path: Path) -> dict[str, Any]:
    if _path_escapes_repo(path):
        raise ValueError(f"JSON path must stay inside the repository: {path}")
    resolved_path = path.resolve() if path.is_absolute() else (REPO_ROOT / path).resolve()
    try:
        value = json.loads(resolved_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Unable to read valid JSON from {resolved_path}: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"JSON document {resolved_path} must contain an object")
    return value


def validate_repo(repo: str) -> str:
    match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9-]*)/([A-Za-z0-9][A-Za-z0-9._-]*)", repo)
    if not match:
        raise ValueError("--repo must be an OWNER/REPOSITORY name")
    owner, name = match.group(1), match.group(2)
    if owner in {".", ".."} or name in {".", ".."}:
        raise ValueError("--repo must not use '.' or '..' path segments")
    if "/" in name or "\\" in name:
        raise ValueError("--repo repository component must not contain path separators")
    return f"{owner}/{name}"


def fetch_live_ruleset(repo: str, ruleset_id: int) -> dict[str, Any]:
    safe_repo = validate_repo(repo)
    if ruleset_id <= 0:
        raise ValueError("--ruleset-id must be a positive integer")
    cmd = ["gh", "api", f"repos/{safe_repo}/rulesets/{ruleset_id}"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "gh returned no diagnostic"
        raise RuntimeError(f"GitHub CLI request failed: {detail}")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"GitHub CLI returned malformed JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeError("GitHub CLI returned JSON that is not an object")
    return value


def rule_by_type(ruleset: dict[str, Any], rule_type: str) -> dict[str, Any] | None:
    for rule in ruleset.get("rules", []):
        if rule.get("type") == rule_type:
            return rule
    return None


def required_contexts(ruleset: dict[str, Any]) -> list[tuple[str, int | None]]:
    """Return sorted (context, integration_id) pairs from required_status_checks.

    Entries with a missing/empty context are preserved as a sentinel so a live
    ruleset with malformed checks cannot silently compare equal to desired.
    """
    rule = rule_by_type(ruleset, "required_status_checks")
    if not rule:
        return []
    checks = rule.get("parameters", {}).get("required_status_checks", [])
    pairs: list[tuple[str, int | None]] = []
    for check in checks:
        context = check.get("context")
        if not context:
            context = "<missing-context>"
        integration = check.get("integration_id")
        pairs.append((str(context), int(integration) if integration is not None else None))
    return sorted(pairs, key=lambda item: (item[0], -1 if item[1] is None else item[1]))


def rule_types(ruleset: dict[str, Any]) -> set[str]:
    return {rule.get("type") for rule in ruleset.get("rules", []) if rule.get("type")}


def pull_request_params(ruleset: dict[str, Any]) -> dict[str, Any]:
    rule = rule_by_type(ruleset, "pull_request")
    return dict(rule.get("parameters", {})) if rule else {}


def copilot_params(ruleset: dict[str, Any]) -> dict[str, Any]:
    rule = rule_by_type(ruleset, "copilot_code_review")
    return dict(rule.get("parameters", {})) if rule else {}


def compare(desired: dict[str, Any], live: dict[str, Any]) -> list[str]:
    drift: list[str] = []

    for key in ("name", "target", "enforcement"):
        if desired.get(key) != live.get(key):
            drift.append(f"{key}: live={live.get(key)!r} desired={desired.get(key)!r}")

    desired_conds = desired.get("conditions") or {}
    live_conds = live.get("conditions") or {}
    if desired_conds != live_conds:
        drift.append(f"conditions: live={live_conds!r} desired={desired_conds!r}")

    desired_bypass = desired.get("bypass_actors", [])
    live_bypass = live.get("bypass_actors", [])
    if desired_bypass != live_bypass:
        drift.append(f"bypass_actors: live={live_bypass!r} desired={desired_bypass!r}")

    desired_types = rule_types(desired)
    live_types = rule_types(live)
    missing_types = sorted(desired_types - live_types)
    extra_types = sorted(live_types - desired_types)
    if missing_types:
        drift.append(f"rules missing on live: {missing_types}")
    if extra_types:
        drift.append(f"rules extra on live: {extra_types}")

    desired_pr = pull_request_params(desired)
    live_pr = pull_request_params(live)
    for key in (
        "required_approving_review_count",
        "required_review_thread_resolution",
        "require_last_push_approval",
        "dismiss_stale_reviews_on_push",
        "require_code_owner_review",
        "required_reviewers",
        "require_extra_approval_for_unattributed_changes",
        "allowed_merge_methods",
    ):
        if desired_pr.get(key) != live_pr.get(key):
            drift.append(f"pull_request.{key}: live={live_pr.get(key)!r} desired={desired_pr.get(key)!r}")

    desired_checks = rule_by_type(desired, "required_status_checks")
    live_checks = rule_by_type(live, "required_status_checks")
    if bool(desired_checks) != bool(live_checks):
        drift.append(
            f"required_status_checks present: live={bool(live_checks)} desired={bool(desired_checks)}"
        )
    if desired_checks and live_checks:
        for key in ("strict_required_status_checks_policy", "do_not_enforce_on_create"):
            d_val = desired_checks.get("parameters", {}).get(key)
            l_val = live_checks.get("parameters", {}).get(key)
            if d_val != l_val:
                drift.append(f"required_status_checks.{key}: live={l_val!r} desired={d_val!r}")

    desired_ctx = required_contexts(desired)
    live_ctx = required_contexts(live)
    if desired_ctx != live_ctx:
        missing = sorted(set(desired_ctx) - set(live_ctx))
        extra = sorted(set(live_ctx) - set(desired_ctx))
        if missing:
            drift.append(f"required_status_checks missing on live: {missing}")
        if extra:
            drift.append(f"required_status_checks extra on live: {extra}")
        if not missing and not extra:
            # Lists differ by multiplicity/order even when unique sets match.
            drift.append(
                f"required_status_checks list mismatch: desired={desired_ctx!r} live={live_ctx!r}"
            )

    desired_scan = rule_by_type(desired, "code_scanning")
    live_scan = rule_by_type(live, "code_scanning")
    if bool(desired_scan) != bool(live_scan):
        drift.append(f"code_scanning present: live={bool(live_scan)} desired={bool(desired_scan)}")
    elif desired_scan and live_scan:
        d_thr = desired_scan.get("parameters", {})
        l_thr = live_scan.get("parameters", {})
        if d_thr != l_thr:
            drift.append(f"code_scanning.parameters: live={l_thr!r} desired={d_thr!r}")

    desired_copilot = copilot_params(desired)
    live_copilot = copilot_params(live)
    for key in ("review_on_push", "review_draft_pull_requests"):
        if desired_copilot.get(key) != live_copilot.get(key):
            drift.append(f"copilot_code_review.{key}: live={live_copilot.get(key)!r} desired={desired_copilot.get(key)!r}")

    desired_quality = rule_by_type(desired, "code_quality")
    live_quality = rule_by_type(live, "code_quality")
    if desired_quality and live_quality:
        if desired_quality.get("parameters", {}) != live_quality.get("parameters", {}):
            drift.append(
                f"code_quality.parameters: live={live_quality.get('parameters', {})!r} "
                f"desired={desired_quality.get('parameters', {})!r}"
            )

    return drift


def migration_command(
    repo: str,
    ruleset_id: int,
    desired: dict[str, Any],
    live: dict[str, Any] | None = None,
) -> str:
    safe_repo = validate_repo(repo)
    if ruleset_id <= 0:
        raise ValueError("--ruleset-id must be a positive integer")
    payload = {
        "name": desired["name"],
        "target": desired["target"],
        "enforcement": desired["enforcement"],
        "conditions": desired["conditions"],
        "rules": list(desired["rules"]),
        "bypass_actors": desired.get("bypass_actors", []),
    }
    if live is not None:
        for key in ("conditions", "bypass_actors", "target", "enforcement"):
            default = [] if key == "bypass_actors" else None
            if live.get(key, default) != payload[key]:
                return f"# Migration refused: reconcile differing live {key} before generating a PUT."
    # The PUT replaces every rule. Keep a live code_quality rule that the
    # desired file omits so this migration cannot demote that gate as a side
    # effect; retiring it needs its own reviewed migration.
    if live is not None and not rule_by_type(desired, "code_quality"):
        live_quality = rule_by_type(live, "code_quality")
        if live_quality:
            payload["rules"].append(live_quality)
    # Refuse to print a destructive replacement when an enforced gate is absent
    # or changed. A maintainer must reconcile the desired snapshot explicitly.
    for rule in (live or {}).get("rules", []):
        if rule not in payload["rules"]:
            return "# Migration refused: reconcile extra or differing live protection rules before generating a PUT."
    body = json.dumps(payload, indent=2)
    return (
        f"# Apply after merging the governance PR (does not run in CI):\n"
        f"gh api --method PUT repos/{safe_repo}/rulesets/{ruleset_id} "
        f"--input - <<'EOF'\n{body}\nEOF"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default="Mika3578/Envy")
    parser.add_argument("--ruleset-id", type=int, default=DEFAULT_RULESET_ID)
    parser.add_argument("--desired", type=Path, default=DESIRED_PATH)
    parser.add_argument("--live-json", type=Path, help="Fixture for offline tests")
    parser.add_argument(
        "--migration",
        action="store_true",
        help="Print the post-merge gh api PUT command only (does not apply it)",
    )
    args = parser.parse_args()

    try:
        safe_repo = validate_repo(args.repo)
        desired = load_json(args.desired)
        desired_rules = {
            "name": desired["name"],
            "target": desired["target"],
            "enforcement": desired["enforcement"],
            "conditions": desired["conditions"],
            "rules": desired["rules"],
            "bypass_actors": desired.get("bypass_actors", []),
        }

        if args.live_json:
            live = load_json(args.live_json)
        else:
            live = fetch_live_ruleset(safe_repo, args.ruleset_id)
    except (KeyError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    drift = compare(desired_rules, live)
    print(f"Protect develop ruleset {args.ruleset_id} drift report ({args.repo})")
    if drift:
        print("DRIFT:")
        for line in drift:
            print(f"  - {line}")
    else:
        print("OK: live ruleset matches desired policy.")

    if args.migration:
        print()
        print(
            "# NOTE: --migration prints a command only. Copy/paste it after merge;"
            " this script never applies ruleset changes."
        )
        print(migration_command(safe_repo, args.ruleset_id, desired_rules, live))

    return 1 if drift else 0


if __name__ == "__main__":
    sys.exit(main())
