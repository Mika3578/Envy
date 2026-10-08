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

GATE_CONTEXT = "Final review gate"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise FileNotFoundError(path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


def post_check_run(repository: str, sha: str, state: str, description: str, target_url: str) -> None:
    if state == "pending":
        payload = {
            "name": GATE_CONTEXT,
            "head_sha": sha,
            "status": "in_progress",
            "details_url": target_url,
            "output": {"title": GATE_CONTEXT, "summary": description[:1024]},
        }
    else:
        conclusion = "success" if state == "success" else "failure"
        payload = {
            "name": GATE_CONTEXT,
            "head_sha": sha,
            "status": "completed",
            "conclusion": conclusion,
            "details_url": target_url,
            "output": {"title": GATE_CONTEXT, "summary": description[:1024]},
        }
    subprocess.run(
        [
            "gh",
            "api",
            "-X",
            "POST",
            f"repos/{repository}/check-runs",
            "--input",
            "-",
        ],
        input=json.dumps(payload),
        text=True,
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
        post_check_run(repository, sha, state, desc, run_url)
        print(json.dumps({"state": state, "reason": desc, "publish_sha": sha}, indent=2))
        return 0
    collect_mod = load_module("collect_final_review_snapshot", SCRIPTS / "collect-final-review-snapshot.py")
    gate_mod = load_module("final_review_gate_mod", SCRIPTS / "final-review-gate.py")
    try:
        snapshot = collect_mod.collect(repository, pr)
        result = gate_mod.evaluate_final_review_gate(snapshot)
    except Exception as exc:  # noqa: BLE001 — fail closed
        sha = live_head(repository, pr)
        if not sha:
            print(f"collection/eval failed and HEAD unread: {exc}", file=sys.stderr)
            return 1
        post_check_run(repository, sha, "error", "GitHub API error", run_url)
        print(json.dumps({"state": "error", "reason": str(exc)}, indent=2))
        return 0
    collected_head = str(snapshot.get("current_head_sha") or "")
    live = live_head(repository, pr)
    state = str(result.get("state") or "error")
    desc = str(result.get("reason") or state)
    if not live:
        # Invalidate any prior success on the last known SHA instead of exiting
        # silently and leaving a stale required green check.
        fallback = collected_head or str(result.get("publish_sha") or "")
        if fallback:
            post_check_run(
                repository,
                fallback,
                "error",
                "could not re-read current HEAD before publish",
                run_url,
            )
        print("could not re-read current HEAD before publish", file=sys.stderr)
        return 1
    if live != collected_head or live != str(result.get("publish_sha") or live):
        # Any HEAD race invalidates the collected result, not only SUCCESS.
        state = "pending"
        desc = "HEAD changed before status publish; refusing stale gate result"
        post_check_run(repository, live, state, desc, run_url)
        print(json.dumps({"state": state, "reason": desc, "publish_sha": live}, indent=2))
        return 0
    if state == "success":
        try:
            live_snapshot = collect_mod.collect(repository, pr)
            result = gate_mod.revalidate_gate_before_success(result, live_snapshot)
            state = str(result.get("state") or "error")
            desc = str(result.get("reason") or state)
            live = str(live_snapshot.get("current_head_sha") or live)
            if live != collected_head:
                state = "pending"
                desc = "HEAD changed during post-success revalidation; refusing stale success"
        except Exception as exc:  # noqa: BLE001 — fail closed
            state = "error"
            desc = f"post-success revalidation failed: {exc}"
    # Immediate pre-publish barrier: CHANGES_REQUESTED / new threads can arrive
    # after the revalidation collect without moving HEAD.
    if state == "success":
        try:
            barrier = collect_mod.collect(repository, pr)
            barrier_head = str(barrier.get("current_head_sha") or "")
            if not barrier_head or barrier_head != collected_head:
                state = "pending"
                desc = "HEAD changed immediately before publish; refusing stale success"
                live = barrier_head or live
            else:
                barrier_result = gate_mod.revalidate_gate_before_success(
                    {
                        "state": "success",
                        "head_sha": collected_head,
                        "publish_sha": collected_head,
                    },
                    barrier,
                )
                state = str(barrier_result.get("state") or "error")
                desc = str(barrier_result.get("reason") or state)
                live = barrier_head
        except Exception as exc:  # noqa: BLE001 — fail closed
            state = "error"
            desc = f"pre-publish barrier failed: {exc}"
    post_check_run(repository, live, state, desc, run_url)
    print(json.dumps({"state": state, "reason": desc, "publish_sha": live}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
