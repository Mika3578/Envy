#!/usr/bin/env python3
"""Keep one compact digest comment of the unresolved review threads on a PR.

Usage:
  review-digest.py --pr N [--print]

Agents read the digest (or print it locally) instead of the whole pull
request conversation. The script never requests reviews, approves, merges,
or judges findings; thread text is rendered inert.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request

API = "https://api.github.com"
DIGEST_MARKER = "<!-- envy-review-digest -->"
MAX_LISTED_THREADS = 50

NIT_PATTERN = re.compile(
    r"nitpick|\bnit\b|\(style\)|!\[low\]|low[- ]priority|refactor suggestion",
    re.IGNORECASE,
)
# "this is not a nit" must stay a finding.
NOT_NIT_PATTERN = re.compile(r"\bnot\s+(?:a\s+|just\s+a\s+)?nit(?:pick)?\b", re.IGNORECASE)

# Severity badges that bots put on their first line; the finding follows.
LABEL_LINE = re.compile(
    r"^\W*(?:(?:potential issue|nitpick|refactor suggestion|agentic security review|"
    r"critical|major|minor|trivial|caution|warning)\b[^:]{0,30}|severity:\s*\w+)$",
    re.IGNORECASE,
)


def summarize(body):
    text = re.sub(r"<!--.*?-->", "", body or "", flags=re.DOTALL)
    text = re.sub(r"<[^>]+>|!\[[^\]]*\]\([^)]*\)", "", text)
    text = re.sub(r":[a-z_]+:", "", text)  # emoji shortcodes such as :stop_sign:
    for line in text.splitlines():
        line = line.strip(" #*_>`-")
        if line and not LABEL_LINE.match(line):
            return line if len(line) <= 140 else line[:137] + "..."
    return "(no text)"


def inert(text):
    """Render untrusted text as a code span in a bot comment.

    Inside a code span GitHub renders no links, autolinked URLs, images, HTML,
    @mentions, or reviewer commands, so thread text cannot act under the
    workflow identity.
    """
    return "`" + (text or "").replace("`", "'").replace("\n", " ") + "`"


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
        where = inert(f"{t['path']}:{t['line']}" if t["line"] else t["path"])
        return f"- **{t['author']}** {where} {inert(summarize(t['body']))} ([thread]({t['url']}))"

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
        "_Updated by the review digest workflow. Agents: "
        f"`python3 .github/scripts/review-digest.py --pr {pr_number} --print`._",
    ]
    return "\n".join(lines) + "\n"


class GitHub:
    def __init__(self, repo, token):
        self.repo = repo
        self.token = token

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
                "User-Agent": "envy-review-digest",
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
        return json.loads(raw) if raw else None

    def pull(self, number):
        return self.call("GET", f"/repos/{self.repo}/pulls/{number}")

    def paged(self, path):
        result, page = [], 1
        while True:
            batch = self.call("GET", f"{path}?per_page=100&page={page}")
            result += batch or []
            if not batch or len(batch) < 100:
                return result
            page += 1

    def comments(self, number):
        return self.paged(f"/repos/{self.repo}/issues/{number}/comments")

    def comment(self, number, body):
        self.call("POST", f"/repos/{self.repo}/issues/{number}/comments", {"body": body})

    def find(self, number, marker):
        # Only the workflow identity or the owner may own the digest; a pasted
        # marker is ignored.
        trusted = {"github-actions[bot]", self.repo.split("/")[0]}
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
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "Mika3578/Envy"))
    parser.add_argument("--print", dest="print_only", action="store_true",
                        help="print the digest instead of writing it to the PR")
    args = parser.parse_args(argv)
    run_digest(GitHub(args.repo, token_from_env()), args.pr, args.print_only)


if __name__ == "__main__":
    main()
