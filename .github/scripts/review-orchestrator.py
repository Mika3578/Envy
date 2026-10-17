#!/usr/bin/env python3
"""Request free AI reviews once per stable head and keep one review digest.

Usage:
  review-orchestrator.py request --pr N [--dry-run]
  review-orchestrator.py digest --pr N [--print]

The orchestrator never approves, merges, or judges findings. It only posts the
reviewer trigger commands and summarizes unresolved review threads so agents
read one compact comment instead of the whole pull request conversation.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

API = "https://api.github.com"
STATE_MARKER = "<!-- envy-review-orchestrator"
DIGEST_MARKER = "<!-- envy-review-digest -->"
REQUEST_LABEL = "review:request"

# Trigger comment per reviewer. Every entry is a free tier for public repos.
REVIEWERS = {
    "coderabbit": "@coderabbitai review",
    "gemini": "/gemini review",
    "sourcery": "@sourcery-ai review",
    "amazonq": "/q review",
    "qodo": "/review",
}
DEFAULT_REVIEWERS = "coderabbit,gemini,sourcery,amazonq"
DEFAULT_MAX_ROUNDS = 2
# Sourcery spends a rolling diff-character budget; skip it on large diffs so
# small pull requests keep getting reviews.
SOURCERY_MAX_CHANGED_LINES = 1500
MAX_LISTED_THREADS = 50
MAX_STATE_CHARS = 20000

NIT_PATTERN = re.compile(
    r"nitpick|\bnit\b|\(style\)|!\[low\]|low[- ]priority|refactor suggestion",
    re.IGNORECASE,
)
# "this is not a nit" must stay a finding.
NOT_NIT_PATTERN = re.compile(r"\bnot\s+(?:a\s+|just\s+a\s+)?nit(?:pick)?\b", re.IGNORECASE)
# Untrusted thread text must not render links, images, or HTML in a bot comment.
MARKDOWN_ACTIVE = re.compile(r"([\\\[\]<>])")
# Severity badges that bots put on their first line; the finding follows.
LABEL_LINE = re.compile(
    r"^\W*(?:(?:potential issue|nitpick|refactor suggestion|agentic security review|"
    r"critical|major|minor|trivial|caution|warning)\b[^:]{0,30}|severity:\s*\w+)$",
    re.IGNORECASE,
)


def enabled_reviewers(raw):
    names = [n.strip().lower() for n in (raw or DEFAULT_REVIEWERS).split(",")]
    unknown = [n for n in names if n and n not in REVIEWERS]
    if unknown:
        raise ValueError(f"unknown reviewers: {', '.join(unknown)}")
    # dict.fromkeys keeps the configured order and drops repeats.
    return list(dict.fromkeys(n for n in names if n))


def parse_state(body):
    match = re.search(re.escape(STATE_MARKER) + r" (\{.*?\}) -->", body or "")
    if not match:
        return {"rounds": []}
    if len(match.group(1)) > MAX_STATE_CHARS:
        raise ValueError("orchestrator state comment is too large")
    state = json.loads(match.group(1))
    if not isinstance(state.get("rounds"), list):
        raise ValueError("orchestrator state must contain a rounds list")
    return state


def render_state(state, max_rounds):
    lines = [
        f"{STATE_MARKER} {json.dumps(state, separators=(',', ':'))} -->",
        f"### Review rounds ({len(state['rounds'])}/{max_rounds})",
    ]
    for entry in state["rounds"]:
        lines.append(f"- `{entry['sha'][:8]}`: {', '.join(entry['reviewers'])}")
    if len(state["rounds"]) < max_rounds:
        lines.append(
            "\nNext round: treat every thread (fix or justified reply, then "
            f"resolve), keep required checks green, then add `{REQUEST_LABEL}`."
        )
    else:
        lines.append("\nRound budget used. The maintainer decides further reviews.")
    return "\n".join(lines) + "\n"


def plan_request(pr, state, reviewers, max_rounds, repo=None, open_threads=0):
    """Return (reviewers to trigger, reason). Pure for regression tests."""
    if pr["state"] != "open":
        return [], "pull request is not open"
    if pr["draft"]:
        return [], "pull request is a draft"
    head_repo = ((pr["head"].get("repo") or {}).get("full_name"))
    if repo and head_repo != repo:
        return [], "fork pull requests are not sent to reviewers"
    head = pr["head"]["sha"]
    if any(entry["sha"] == head for entry in state["rounds"]):
        return [], f"head {head[:8]} was already sent for review"
    if len(state["rounds"]) >= max_rounds:
        return [], f"round budget ({max_rounds}) is used"
    if state["rounds"] and open_threads:
        return [], f"{open_threads} current review thread(s) still open; treat them first"
    changed = pr["additions"] + pr["deletions"]
    chosen = [
        name
        for name in reviewers
        if not (name == "sourcery" and changed > SOURCERY_MAX_CHANGED_LINES)
    ]
    if not chosen:
        return [], "no reviewer enabled for this diff size"
    return chosen, "requested"


def summarize(body):
    text = re.sub(r"<!--.*?-->", "", body or "", flags=re.DOTALL)
    text = re.sub(r"<[^>]+>|!\[[^\]]*\]\([^)]*\)", "", text)
    text = re.sub(r":[a-z_]+:", "", text)  # emoji shortcodes such as :stop_sign:
    for line in text.splitlines():
        line = line.strip(" #*_>`-")
        if line and not LABEL_LINE.match(line):
            line = line if len(line) <= 140 else line[:137] + "..."
            return MARKDOWN_ACTIVE.sub(r"\\\1", line)
    return "(no text)"


def is_nit(body):
    # Bots put the severity badge in the opening lines; later prose that merely
    # mentions "nit" must not hide a finding.
    head = "\n".join((body or "").strip().splitlines()[:2])[:200]
    return bool(NIT_PATTERN.search(head)) and not NOT_NIT_PATTERN.search(head)


def render_digest(pr_number, head_sha, threads, limit=MAX_LISTED_THREADS):
    open_threads = [t for t in threads if not t["isResolved"]]
    current = [t for t in open_threads if not t["isOutdated"]]
    outdated = [t for t in open_threads if t["isOutdated"]]
    blocking = [t for t in current if not is_nit(t["body"])]
    nits = [t for t in current if is_nit(t["body"])]

    def item(t):
        where = f"`{t['path']}:{t['line']}`" if t["line"] else f"`{t['path']}`"
        return f"- **{t['author']}** {where} {summarize(t['body'])} ([thread]({t['url']}))"

    lines = [
        DIGEST_MARKER,
        f"### Review digest for `{head_sha[:8]}`",
        f"**{len(blocking)} to treat** | {len(nits)} nits | "
        f"{len(outdated)} outdated | {len(threads) - len(open_threads)} resolved",
    ]
    def listed(group):
        shown = group if limit is None else group[:limit]
        rest = len(group) - len(shown)
        more = [f"- _{rest} more not listed; run the `--print` command below._"] if rest else []
        return [item(t) for t in shown] + more

    if blocking:
        lines += ["", "#### To treat"] + listed(blocking)
    for title, group in (("Nits", nits), ("Outdated, verify then resolve", outdated)):
        if group:
            lines += ["", f"<details><summary>{title} ({len(group)})</summary>", ""]
            lines += listed(group)
            lines += ["", "</details>"]
    lines += [
        "",
        "_Updated by the review orchestrator. Agents: "
        f"`python3 .github/scripts/review-orchestrator.py digest --pr {pr_number} --print`._",
    ]
    return "\n".join(lines) + "\n"


class GitHub:
    def __init__(self, repo, token):
        self.repo = repo
        self.token = token
        self._login = None

    def call(self, method, path, body=None):
        url = path if path.startswith("https://") else API + path
        request = urllib.request.Request(
            url,
            data=None if body is None else json.dumps(body).encode(),
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "envy-review-orchestrator",
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
        return json.loads(raw) if raw else None

    def pull(self, number):
        return self.call("GET", f"/repos/{self.repo}/pulls/{number}")

    def comments(self, number):
        result, page = [], 1
        while True:
            batch = self.call(
                "GET",
                f"/repos/{self.repo}/issues/{number}/comments?per_page=100&page={page}",
            )
            result += batch or []
            if not batch or len(batch) < 100:
                return result
            page += 1

    def comment(self, number, body):
        self.call("POST", f"/repos/{self.repo}/issues/{number}/comments", {"body": body})

    def token_login(self):
        """Login behind a user token (REVIEW_TRIGGER_TOKEN); empty for GITHUB_TOKEN."""
        if self._login is None:
            try:
                self._login = (self.call("GET", "/user") or {}).get("login") or ""
            except urllib.error.HTTPError:
                self._login = ""
        return self._login

    def find(self, number, marker):
        # Only the workflow identities may own state; a pasted marker is ignored.
        # The trigger token's owner writes the state when that secret is set.
        trusted = {"github-actions[bot]", self.repo.split("/")[0]}
        if self.token_login():
            trusted.add(self.token_login())
        return next(
            (c for c in self.comments(number)
             if marker in c["body"] and c["user"]["login"] in trusted),
            None,
        )

    def upsert(self, number, existing, body):
        if existing is None:
            self.comment(number, body)
        elif existing["body"] != body:
            self.call("PATCH", existing["url"], {"body": body})

    def remove_label(self, number, label):
        try:
            self.call(
                "DELETE",
                f"/repos/{self.repo}/issues/{number}/labels/{label.replace(':', '%3A')}",
            )
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise

    def threads(self, number):
        owner, name = self.repo.split("/")
        query = """
query($owner: String!, $name: String!, $number: Int!, $after: String) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      reviewThreads(first: 100, after: $after) {
        pageInfo { hasNextPage endCursor }
        nodes {
          isResolved isOutdated path line
          comments(first: 1) { nodes { author { login } body url } }
        }
      }
    }
  }
}"""
        result, after = [], None
        while True:
            data = self.call(
                "POST",
                "/graphql",
                {"query": query, "variables": {
                    "owner": owner, "name": name, "number": number, "after": after}},
            )
            if data.get("errors"):
                raise RuntimeError(f"GraphQL error: {data['errors']}")
            page = data["data"]["repository"]["pullRequest"]["reviewThreads"]
            for node in page["nodes"]:
                first = (node["comments"]["nodes"] or [{}])[0]
                result.append({
                    "isResolved": node["isResolved"],
                    "isOutdated": node["isOutdated"],
                    "path": node["path"],
                    "line": node["line"],
                    "author": ((first.get("author") or {}).get("login")) or "unknown",
                    "body": first.get("body", ""),
                    "url": first.get("url", ""),
                })
            if not page["pageInfo"]["hasNextPage"]:
                return result
            after = page["pageInfo"]["endCursor"]


def token_from_env():
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        return token
    try:
        token = subprocess.run(
            ["gh", "auth", "token"], check=True, capture_output=True, text=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        token = ""
    if not token:
        sys.exit("No GitHub token: set GITHUB_TOKEN or GH_TOKEN, or run `gh auth login`.")
    return token


def report(message):
    print(message)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as stream:
            stream.write(message + "\n")


def run_request(github, number, dry_run):
    pr = github.pull(number)
    max_rounds = int(os.environ.get("ENVY_REVIEW_MAX_ROUNDS") or DEFAULT_MAX_ROUNDS)
    reviewers = enabled_reviewers(os.environ.get("ENVY_REVIEWERS"))
    existing = github.find(number, STATE_MARKER)
    state = parse_state(existing["body"] if existing else "")
    open_threads = 0
    if state["rounds"]:
        open_threads = sum(
            1 for t in github.threads(number) if not t["isResolved"] and not t["isOutdated"]
        )
    chosen, reason = plan_request(
        pr, state, reviewers, max_rounds, repo=github.repo, open_threads=open_threads
    )
    report(f"PR #{number}: {reason}; reviewers: {', '.join(chosen) or 'none'}")
    if dry_run:
        return
    # The label is a one-shot trigger: a skipped request must not leave it
    # set, or re-adding it later would not fire a new labeled event.
    github.remove_label(number, REQUEST_LABEL)
    if not chosen:
        return
    # Record the round before posting: a retry after a partial failure then
    # skips this head instead of sending duplicate reviewer commands.
    state["rounds"].append({"sha": pr["head"]["sha"], "reviewers": chosen})
    github.upsert(number, existing, render_state(state, max_rounds))
    for name in chosen:
        github.comment(number, REVIEWERS[name])


def run_digest(github, number, print_only):
    pr = github.pull(number)
    body = render_digest(
        number, pr["head"]["sha"], github.threads(number),
        limit=None if print_only else MAX_LISTED_THREADS,
    )
    if print_only:
        sys.stdout.buffer.write(body.encode("utf-8"))
        return
    github.upsert(number, github.find(number, DIGEST_MARKER), body)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("mode", choices=("request", "digest"))
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "Mika3578/Envy"))
    parser.add_argument("--dry-run", action="store_true", help="request: plan only")
    parser.add_argument("--print", dest="print_only", action="store_true",
                        help="digest: print instead of commenting")
    args = parser.parse_args(argv)
    github = GitHub(args.repo, token_from_env())
    if args.mode == "request":
        run_request(github, args.pr, args.dry_run)
    else:
        run_digest(github, args.pr, args.print_only)


if __name__ == "__main__":
    main()
