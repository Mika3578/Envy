#!/usr/bin/env python3
"""Collect, evaluate, re-read HEAD, and post Final review gate status."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import importlib.util

_COLLECT_SPEC = importlib.util.spec_from_file_location(
    "collect_final_review_snapshot", SCRIPTS / "collect-final-review-snapshot.py"
)
COLLECT = importlib.util.module_from_spec(_COLLECT_SPEC)
_COLLECT_SPEC.loader.exec_module(COLLECT)

_GATE_SPEC = importlib.util.spec_from_file_location(
    "final_review_gate_mod", SCRIPTS / "final-review-gate.py"
)
GATE = importlib.util.module_from_spec(_GATE_SPEC)
_GATE_SPEC.loader.exec_module(GATE)


def live_head(repository: str, pr: int) -> str:
    proc = subprocess.run(
        ["gh", "api", f"repos/{repository}/pulls/{pr}", "--jq", ".head.sha"],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return ""
    return (proc.stdout or "").strip()


def post_status(repository: str, sha: str, state: str, description: str, target_url: str) -> None:
    subprocess.run(
        [
            "gh",
            "api",
            "-X",
            "POST",
            f"repos/{repository}/statuses/{sha}",
            "-f",
            f"state={state}",
            "-f",
            f"context={GATE.GATE_CONTEXT}",
            "-f",
            f"description={description[:120]}",
            "-f",
            f"target_url={target_url}",
        ],
        check=True,
    )


def main() -> int:
    repository = os.environ.get("REPOSITORY") or os.environ.get("GITHUB_REPOSITORY")
    pr_raw = os.environ.get("PR_NUMBER")
    run_url = os.environ.get("RUN_URL") or ""
    missing = os.environ.get("SCRIPTS_MISSING") == "1"
    if not repository or not pr_raw or not pr_raw.isdigit():
        print("REPOSITORY and PR_NUMBER are required", file=sys.stderr)
        return 1
    pr = int(pr_raw)
    sha = live_head(repository, pr)
    if missing:
        state = "pending" if sha else "error"
        desc = "gate scripts not on default branch yet"
        if not sha:
            print(desc, file=sys.stderr)
            return 1
        post_status(repository, sha, state, desc, run_url)
        print(json.dumps({"state": state, "reason": desc, "publish_sha": sha}, indent=2))
        return 0
    try:
        snapshot = COLLECT.collect(repository, pr)
        result = GATE.evaluate_final_review_gate(snapshot)
    except Exception as exc:  # noqa: BLE001 — fail closed
        sha = live_head(repository, pr)
        if not sha:
            print(f"collection/eval failed and HEAD unread: {exc}", file=sys.stderr)
            return 1
        post_status(repository, sha, "error", "GitHub API error", run_url)
        print(json.dumps({"state": "error", "reason": str(exc)}, indent=2))
        return 0
    live = live_head(repository, pr)
    state = str(result.get("state") or "error")
    desc = str(result.get("reason") or state)
    if not live:
        print("could not re-read current HEAD before publish", file=sys.stderr)
        return 1
    if state == "success":
        try:
            live_snapshot = COLLECT.collect(repository, pr)
            result = GATE.revalidate_gate_before_success(result, live_snapshot)
            state = str(result.get("state") or "error")
            desc = str(result.get("reason") or state)
            live = str(live_snapshot.get("current_head_sha") or live)
        except Exception as exc:  # noqa: BLE001 — fail closed
            state = "error"
            desc = f"post-success revalidation failed: {exc}"
    if state == "success" and live != result.get("publish_sha"):
        state = "pending"
        desc = "HEAD changed before status publish; refusing stale success"
    if state == "success" and live != snapshot.get("current_head_sha"):
        state = "pending"
        desc = "HEAD changed before status publish; refusing stale success"
    post_status(repository, live, state, desc, run_url)
    print(json.dumps({"state": state, "reason": desc, "publish_sha": live}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
