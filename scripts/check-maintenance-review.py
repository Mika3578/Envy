#!/usr/bin/env python3
"""Advisory signal for periodic idea-inbox / backlog review.

Never creates Issues or pull requests, never accepts ideas, and never
modifies product code. Missing .local/inbox/ is valid.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import date, datetime
from pathlib import Path

PENDING_THRESHOLD = 10
MERGED_PR_THRESHOLD = 10
DAYS_THRESHOLD = 30

DEFAULT_IDEAS = Path("docs") / "10_dev" / "ideas.md"
DEFAULT_INBOX = Path(".local") / "inbox"


def repo_root_from(start: Path | None = None) -> Path:
    here = (start or Path.cwd()).resolve()
    for candidate in [here, *here.parents]:
        if (candidate / "AGENTS.md").is_file() and (candidate / "docs").is_dir():
            return candidate
    return here


def _markdown_table_value(line: str) -> str | None:
    cells = [part.strip() for part in line.strip().strip("|").split("|")]
    if len(cells) < 2:
        return None
    return cells[1]


def parse_last_review(ideas_text: str) -> dict[str, str | None]:
    parsed: dict[str, str | None] = {
        "date": None,
        "revision": None,
        "merged_pr_baseline": None,
    }
    for raw in ideas_text.splitlines():
        stripped = raw.strip()
        if not stripped.startswith("|"):
            continue
        label = stripped.lower()
        value = _markdown_table_value(stripped)
        if not value or value.lower() == "value":
            continue
        if label.startswith("| date |"):
            parsed["date"] = value[:10]
        elif "development revision" in label:
            token = value.strip("`").split()[0]
            parsed["revision"] = token.strip("`")
        elif "merged pr baseline" in label:
            hash_at = value.find("#")
            if hash_at < 0:
                continue
            digits: list[str] = []
            for ch in value[hash_at + 1 :]:
                if ch.isdigit():
                    digits.append(ch)
                else:
                    break
            if digits:
                parsed["merged_pr_baseline"] = "".join(digits)
    return parsed


def count_pending_in_text(text: str) -> int:
    count = 0
    lines = text.splitlines()
    for index, raw in enumerate(lines):
        line = raw.strip().lower()
        if line == "status: pending review":
            count += 1
        elif line == "### status":
            nxt = lines[index + 1].strip().lower() if index + 1 < len(lines) else ""
            if nxt == "pending review":
                count += 1
    return count


def count_inbox_pending(inbox_dir: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    if not inbox_dir.is_dir():
        return counts
    for path in sorted(inbox_dir.glob("*.md")):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        n = count_pending_in_text(text)
        if n:
            counts[path.stem] = n
    return counts


def days_since(review_iso: str | None, today: date | None = None) -> int | None:
    if not review_iso:
        return None
    try:
        parsed = datetime.strptime(review_iso, "%Y-%m-%d").date()
    except ValueError:
        return None
    return ((today or date.today()) - parsed).days


def run_gh_merged_count(since_iso: str | None, repo: str | None) -> int | None:
    if not since_iso:
        return None
    if os.environ.get("ENVY_MAINT_REVIEW_SKIP_GH") == "1":
        return None
    cmd = [
        "gh",
        "pr",
        "list",
        "--state",
        "merged",
        "--search",
        f"merged:>={since_iso}",
        "--limit",
        "100",
        "--json",
        "number",
    ]
    if repo:
        cmd.extend(["--repo", repo])
    try:
        completed = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    text = completed.stdout.strip()
    if not text:
        return 0
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return len(data)
    except json.JSONDecodeError:
        return None
    return None


def recommend(
    pending_total: int,
    merged_prs: int | None,
    elapsed_days: int | None,
    pending_threshold: int = PENDING_THRESHOLD,
    merged_threshold: int = MERGED_PR_THRESHOLD,
    days_threshold: int = DAYS_THRESHOLD,
) -> tuple[bool, str]:
    reasons: list[str] = []
    if pending_total >= pending_threshold:
        reasons.append("pending inbox threshold reached")
    if merged_prs is not None and merged_prs >= merged_threshold:
        reasons.append("merged PR threshold reached")
    if elapsed_days is not None and elapsed_days >= days_threshold:
        reasons.append("day threshold reached")
    if reasons:
        return True, "; ".join(reasons)
    return False, "no configured threshold reached"


def format_report(
    *,
    inbox_counts: dict[str, int],
    inbox_present: bool,
    merged_prs: int | None,
    elapsed_days: int | None,
    review: dict[str, str | None],
    yes: bool,
    reason: str,
) -> str:
    lines = ["Maintenance inbox:"]
    if not inbox_present:
        lines.append("- (no .local/inbox/; optional)")
    elif not inbox_counts:
        lines.append("- (no pending entries)")
    else:
        for name, count in inbox_counts.items():
            lines.append(f"- {name}: {count}")
    pending_total = sum(inbox_counts.values())
    lines.append("")
    merged_s = "unavailable (install GitHub CLI or set repo access)" if merged_prs is None else str(merged_prs)
    days_s = "unknown" if elapsed_days is None else str(elapsed_days)
    lines.append(f"Pending total: {pending_total}")
    lines.append(f"Merged PRs since review: {merged_s}")
    lines.append(f"Days since review: {days_s}")
    if review.get("date"):
        lines.append(f"Last review date: {review['date']}")
    if review.get("revision"):
        lines.append(f"Last review revision: {review['revision']}")
    if review.get("merged_pr_baseline"):
        lines.append(f"Merged PR baseline: #{review['merged_pr_baseline']}")
    lines.append("")
    lines.append(f"Review recommended: {'YES' if yes else 'NO'}")
    lines.append(f"Reason: {reason}")
    return "\n".join(lines) + "\n"


def detect_github_repo(root: Path) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "remote", "get-url", "origin"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    url = completed.stdout.strip()
    m = re.search(r"github\.com[:/]([^/]+)/([^/]+?)(?:\.git)?$", url)
    if not m:
        return None
    return f"{m.group(1)}/{m.group(2)}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Print whether a maintenance idea review is recommended."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="Repository root (default: detect from cwd)",
    )
    parser.add_argument(
        "--pending-threshold",
        type=int,
        default=PENDING_THRESHOLD,
    )
    parser.add_argument(
        "--merged-threshold",
        type=int,
        default=MERGED_PR_THRESHOLD,
    )
    parser.add_argument(
        "--days-threshold",
        type=int,
        default=DAYS_THRESHOLD,
    )
    args = parser.parse_args(argv)
    root = repo_root_from(args.root)
    ideas_path = root / DEFAULT_IDEAS
    inbox_dir = root / DEFAULT_INBOX
    if ideas_path.is_file():
        review = parse_last_review(ideas_path.read_text(encoding="utf-8"))
    else:
        review = {"date": None, "revision": None, "merged_pr_baseline": None}
    inbox_present = inbox_dir.is_dir()
    inbox_counts = count_inbox_pending(inbox_dir)
    pending_total = sum(inbox_counts.values())
    elapsed = days_since(review["date"])
    repo = detect_github_repo(root)
    merged = run_gh_merged_count(review["date"], repo)
    yes, reason = recommend(
        pending_total,
        merged,
        elapsed,
        pending_threshold=args.pending_threshold,
        merged_threshold=args.merged_threshold,
        days_threshold=args.days_threshold,
    )
    sys.stdout.write(
        format_report(
            inbox_counts=inbox_counts,
            inbox_present=inbox_present,
            merged_prs=merged,
            elapsed_days=elapsed,
            review=review,
            yes=yes,
            reason=reason,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
