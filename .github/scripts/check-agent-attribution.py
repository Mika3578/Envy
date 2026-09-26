#!/usr/bin/env python3
"""Scan PR git metadata and added text for authorship/privacy policy.

Positive allowlist only. Do not maintain a denylist of personal addresses.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

AI_COAUTHOR_NAME_RE = re.compile(
    r"(?i)(Cursor(?:\s+Agent)?|cursoragent|GitHub\s+Copilot|copilot-swe-agent|"
    r"Copilot|Codex|Claude|ChatGPT|OpenAI|Anthropic|CodeRabbit|cubic\.dev|"
    r"Cubic|Aider|Cline|Windsurf|Sourcery|Gemini|Grok|Amazon\s+Q(?:\s+Developer)?)"
)
GENERATED_LINE_RE = re.compile(
    r"(?im)^[ \t]*(?://|/\*|\*)?[ \t]*(Generated[ \t]+(with|by)|Created[ \t]+with|AI-generated|Made-with)"
    r"[ \t]+(Cursor(?:[ \t]+Agent)?|Copilot|Codex|Claude|ChatGPT|OpenAI|Aider|"
    r"CodeRabbit|Cline|Windsurf|Anthropic|Cubic|Sourcery|Gemini|Grok|Amazon[ \t]+Q(?:[ \t]+Developer)?)\b"
)
GENERATED_DIFF_TEXT_RE = re.compile(
    r"(?i)\b(Generated[ \t]+(with|by)|Created[ \t]+with|AI-generated|Made-with)"
    r"[ \t]+(Cursor(?:[ \t]+Agent)?|Copilot|Codex|Claude|ChatGPT|OpenAI|Aider|"
    r"CodeRabbit|Cline|Windsurf|Anthropic|Cubic|Sourcery|Gemini|Grok|Amazon[ \t]+Q(?:[ \t]+Developer)?)\b"
)
TRAILER_RE = re.compile(
    r"(?im)^(Co-authored-by|Signed-off-by|Reviewed-by|Acked-by|Reported-by|"
    r"Tested-by|Helped-by|Suggested-by)[ \t]*:[ \t]*(.+)$"
)
EMAIL_RE = re.compile(r"(?i)\b([A-Z0-9._%+\-]+)@([A-Z0-9.\-]+\.[A-Z]{2,})\b")
URL_USERINFO_RE = re.compile(r"(?i)[a-z][a-z0-9+\-.]*://[^\s/]*@")
PROCESS_COMMENT_RE = re.compile(
    r"(?i)^\+[ \t]*(//|/\*|\*)[ \t].*(Requested by Copilot|Cursor changed this|"
    r"CodeRabbit complained|Generated with Cursor|Generated with Copilot)"
)
CONTRIBUTOR_AGENT_MARKER_RE = re.compile(
    r"(?i)<!--\s*(CURSOR_AGENT_|CODEX_|COPILOT_)[A-Z0-9_-]*\s*-->"
)
AUTOMATED_PR_SECTION_RES = (
    re.compile(
        r"<!--\s*This is an auto-generated description by cubic\.\s*-->"
        r".*?<!--\s*End of auto-generated description by cubic\.\s*-->",
        re.DOTALL | re.IGNORECASE,
    ),
    re.compile(
        r"<!--\s*CURSOR_AGENT_PR_BODY_BEGIN\s*-->.*?<!--\s*CURSOR_AGENT_PR_BODY_END\s*-->",
        re.DOTALL | re.IGNORECASE,
    ),
    re.compile(
        r"<!--\s*This is an auto-generated comment by CodeRabbit\s*-->.*?<!--\s*End of auto-generated comment by CodeRabbit\s*-->",
        re.DOTALL | re.IGNORECASE,
    ),
)
# GitHub / Actions mailboxes only. AI runner identities such as
# cursoragent@cursor.com are not allowed as author, committer, or trailer.
ALLOWED_TECHNICAL_EMAILS = {
    "noreply@github.com",
    "support@github.com",
    "notifications@github.com",
    "security@github.com",
}
ALLOWED_PROJECT_EMAILS: set[str] = set()
BOT_COMMENT_LOGINS = {
    "dependabot[bot]",
    "github-actions[bot]",
    "copilot-pull-request-reviewer",
    "copilot-swe-agent",
    "cursor[bot]",
    "coderabbitai[bot]",
    "cubic-dev-ai[bot]",
    "sonarcloud[bot]",
    "snyk-bot",
    "amazon-q-developer[bot]",
    "sourcery-ai[bot]",
    "github-copilot[bot]",
}


def is_allowed_email(email: str) -> bool:
    e = email.strip().lower()
    if e in ALLOWED_TECHNICAL_EMAILS or e in ALLOWED_PROJECT_EMAILS:
        return True
    return e.endswith(("@users.noreply.github.com", "@noreply.github.com"))


def is_ai_identity(name: str, email: str) -> bool:
    blob = f"{name} {email}"
    if AI_COAUTHOR_NAME_RE.search(blob):
        return True
    return email.strip().lower() in {
        "cursoragent@cursor.com",
        "copilot@github.com",
    }


DOC_OR_REMOTE_DOMAINS = {
    "example.com",
    "example.org",
    "example.net",
    "example.edu",
    "invalid",
    "test",
    "localhost",
}


def emails_in_text(text: str) -> list[str]:
    # Drop URL userinfo matches so https://user@host/path is not treated as mail.
    masked = URL_USERINFO_RE.sub(" ", text)
    found = []
    for match in EMAIL_RE.finditer(masked):
        email = match.group(0)
        domain = match.group(2).lower()
        # git@github.com:org/repo.git is an SCP-style remote, not a mailbox.
        if email.lower() == "git@github.com":
            continue
        if domain in DOC_OR_REMOTE_DOMAINS or domain.endswith(".example.com"):
            continue
        found.append(email)
    return found


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True, errors="replace")


def report(errors: list[str], msg: str) -> None:
    print(msg, file=sys.stderr)
    if os.environ.get("ATTRIBUTION_CI_ANNOTATE") == "1":
        print(f"::error::{msg}", file=sys.stderr)
    errors.append(msg)


def strip_automated_pr_sections(text: str) -> str:
    """Remove known third-party PR summary blocks (bots), not contributor prose."""
    out = text
    for pattern in AUTOMATED_PR_SECTION_RES:
        out = pattern.sub("", out)
    return out


def _reject_email(errors: list[str], message: str, email: str, *, allow_technical: bool) -> None:
    if allow_technical and email.lower() in ALLOWED_TECHNICAL_EMAILS:
        return
    if not is_allowed_email(email):
        report(errors, message)


def _scan_trailers(errors: list[str], label: str, text: str) -> None:
    for trailer, value in TRAILER_RE.findall(text):
        emails = emails_in_text(value)
        if trailer.lower() == "co-authored-by" and is_ai_identity(value, emails[0] if emails else ""):
            report(errors, f"{label}: AI-tool Co-authored-by trailer is not allowed.")
            continue
        for email in emails:
            _reject_email(
                errors,
                f"{label}: attribution trailer {trailer} uses a non-allowlisted email.",
                email,
                allow_technical=False,
            )


def scan_text(errors: list[str], label: str, text: str, *, allow_ai_author_email: bool = False) -> None:
    if GENERATED_LINE_RE.search(text):
        report(errors, f"{label}: AI-tool generation signature is not allowed.")
    _scan_trailers(errors, label, text)
    for email in emails_in_text(text):
        _reject_email(
            errors,
            f"{label}: non-allowlisted email address in generated git/GitHub text.",
            email,
            allow_technical=allow_ai_author_email,
        )


def scan_pr_text(errors: list[str], label: str, text: str) -> None:
    """Scan contributor-authored PR text; ignore recognized bot summary blocks."""
    contributor = strip_automated_pr_sections(text)
    if CONTRIBUTOR_AGENT_MARKER_RE.search(contributor):
        report(errors, f"{label}: agent automation marker is not allowed in contributor text.")
    scan_text(errors, label, contributor)


def scan_identity(errors: list[str], label: str, name: str, email: str) -> None:
    email = email.strip()
    name = name.strip()
    if not email:
        report(errors, f"{label}: missing email.")
        return
    if is_ai_identity(name, email):
        report(errors, f"{label}: AI-tool git identity is not allowed.")
        return
    if not is_allowed_email(email):
        report(errors, f"{label}: non-allowlisted git identity email.")


def scan_commits(errors: list[str], from_sha: str, to_sha: str) -> None:
    commits = git("rev-list", f"{from_sha}..{to_sha}").splitlines()
    for commit in commits:
        email = git("log", "-1", "--format=%ae", commit).strip()
        name = git("log", "-1", "--format=%an", commit).strip()
        cemail = git("log", "-1", "--format=%ce", commit).strip()
        cname = git("log", "-1", "--format=%cn", commit).strip()
        body = git("log", "-1", "--format=%B", commit)
        short = commit[:12]
        scan_identity(errors, f"commit {short} author", name, email)
        scan_identity(errors, f"commit {short} committer", cname, cemail)
        scan_text(errors, f"commit {short} message", body)


def _scan_added_diff_line(errors: list[str], payload: str, skip_signatures: bool, skip_policy_emails: bool) -> None:
    if PROCESS_COMMENT_RE.search("+" + payload):
        report(
            errors,
            "Added C++ comment looks like development-process text, not a technical comment.",
        )
    if not skip_signatures and GENERATED_DIFF_TEXT_RE.search(payload):
        report(errors, "added diff line: AI-tool generation signature is not allowed.")
    policy_emails = set(ALLOWED_TECHNICAL_EMAILS) | {
        "cursoragent@cursor.com",
        "copilot@github.com",
    }
    if skip_signatures or skip_policy_emails:
        for email in emails_in_text(payload):
            if email.lower() in policy_emails:
                continue
            _reject_email(
                errors,
                "Added diff contains a non-allowlisted email address.",
                email,
                allow_technical=False,
            )
        if not skip_signatures and GENERATED_LINE_RE.search(payload):
            report(errors, "added diff line: AI-tool generation signature is not allowed.")
        if not skip_signatures:
            _scan_trailers(errors, "added diff line", payload)
        return
    scan_text(errors, "added diff line", payload)


def scan_diff(errors: list[str], from_sha: str, to_sha: str) -> None:
    skip_signatures = False
    skip_policy_emails = False
    for line in git("diff", "-U0", from_sha, to_sha).splitlines():
        if line.startswith("diff --git "):
            skip_signatures = False
            skip_policy_emails = False
            continue
        if line.startswith("+++ b/"):
            path = line[6:]
            skip_signatures = path == ".github/scripts/check-agent-attribution.selftest.sh"
            skip_policy_emails = path == ".github/scripts/check-agent-attribution.py"
            continue
        if line.startswith("--- a/") or not line.startswith("+"):
            continue
        _scan_added_diff_line(errors, line[1:], skip_signatures, skip_policy_emails)


def scan_file(errors: list[str], label: str, path: Path) -> None:
    if not path.is_file():
        report(errors, f"{label} file not found: {path}")
        return
    text = path.read_text(encoding="utf-8", errors="replace")
    scan_text(errors, label, text)


def scan_pr_file(errors: list[str], label: str, path: Path) -> None:
    if not path.is_file():
        report(errors, f"{label} file not found: {path}")
        return
    text = path.read_text(encoding="utf-8", errors="replace")
    scan_pr_text(errors, label, text)


def parse_paginated_json(raw: str, url: str) -> list:
    text = raw.strip()
    if not text:
        raise RuntimeError(f"empty GitHub API response for {url}")
    items: list = []
    decoder = json.JSONDecoder()
    idx = 0
    length = len(text)
    while idx < length:
        while idx < length and text[idx].isspace():
            idx += 1
        if idx >= length:
            break
        obj, idx = decoder.raw_decode(text, idx)
        if not isinstance(obj, list):
            raise RuntimeError(f"unexpected JSON type for {url}")
        items.extend(obj)
    return items


def gh_api_list(url: str) -> list:
    raw = subprocess.check_output(["gh", "api", "--paginate", url], text=True)
    return parse_paginated_json(raw, url)


def _is_bot_user(user: dict) -> bool:
    login = (user.get("login") or "").lower()
    utype = user.get("type") or ""
    if utype == "Bot" or login.endswith("[bot]"):
        return True
    return login in {item.lower() for item in BOT_COMMENT_LOGINS}


def collect_human_review_text(repo: str, number: str) -> str:
    chunks: list[str] = []
    for url in (
        f"repos/{repo}/issues/{number}/comments",
        f"repos/{repo}/pulls/{number}/comments",
        f"repos/{repo}/pulls/{number}/reviews",
    ):
        for item in gh_api_list(url):
            user = item.get("user") or {}
            if _is_bot_user(user):
                continue
            body = item.get("body") or ""
            if body.strip():
                chunks.append(body)
    return "\n\n".join(chunks)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--from", dest="from_sha")
    parser.add_argument("--to", dest="to_sha", default="HEAD")
    parser.add_argument("--diff", action="store_true")
    parser.add_argument("--pr-body")
    parser.add_argument("--pr-title")
    parser.add_argument("--pr-comments")
    parser.add_argument("--github-repo")
    parser.add_argument("--github-pr")
    args = parser.parse_args()
    errors: list[str] = []

    if args.from_sha:
        scan_commits(errors, args.from_sha, args.to_sha)
        if args.diff:
            scan_diff(errors, args.from_sha, args.to_sha)
    if args.pr_body:
        scan_pr_file(errors, "pull request body", Path(args.pr_body))
    if args.pr_title:
        scan_pr_file(errors, "pull request title", Path(args.pr_title))
    if args.pr_comments:
        scan_pr_file(errors, "pull request comments", Path(args.pr_comments))
    if args.github_repo and args.github_pr:
        text = collect_human_review_text(args.github_repo, args.github_pr)
        if text:
            scan_pr_text(errors, "pull request comments", text)

    if errors:
        print("Authorship hygiene check failed. See AGENTS.md hard rule 16.", file=sys.stderr)
        return 1
    print("Authorship hygiene check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
