#!/usr/bin/env python3
"""Request free AI reviews once per stable head and keep one review digest.

Usage:
  review-orchestrator.py request --pr N [--dry-run]
  review-orchestrator.py digest --pr N [--print]
  review-orchestrator.py quorum --pr N [--print]
  review-orchestrator.py scoreboard [--print]

The orchestrator never approves, merges, or judges findings. It only posts the
reviewer trigger commands and summarizes unresolved review threads so agents
read one compact comment instead of the whole pull request conversation.
The quorum mode counts approvals that independent review apps already gave on
the current head and reports them as an advisory commit status.
Reviewers are not all triggered at once: request picks the best available app
from the scoreboard (review_scoreboard.py), and scoreboard mode recomputes the
ranking and escalates to the next app when the chosen one is limited or silent.
"""

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import review_scoreboard as scoreboard  # noqa: E402

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
# Enabled reviewers; the order is the cold-start ranking before any statistics.
DEFAULT_REVIEWERS = "coderabbit,gemini,sourcery,amazonq"
DEFAULT_MAX_ROUNDS = 2
# One reviewer per head by default; high-risk pull requests get a second,
# distinct one. Never more than two in flight on one head.
DEFAULT_REVIEWERS_PER_HEAD = 1
MAX_REVIEWERS_PER_HEAD = 2
HIGH_RISK_LABELS = {"security", "protocol", "network", "crypto"}
SCOREBOARD_MAX_PRS = 40
# Sourcery spends a rolling diff-character budget; skip it on large diffs so
# small pull requests keep getting reviews.
SOURCERY_MAX_CHANGED_LINES = 1500
MAX_LISTED_THREADS = 50
MAX_STATE_CHARS = 20000

# Review apps whose APPROVED review counts as one vote. The correction agent's
# identity must never be listed: a fixer that votes approves its own work.
DEFAULT_QUORUM_VOTERS = "coderabbitai[bot],cubic-dev-ai[bot],greptile-apps[bot]"
DEFAULT_QUORUM_REQUIRED = 3
QUORUM_CONTEXT = "Review quorum"
# Privileged governance paths (AGENTS.md rule 12): bot votes never stand in
# for the maintainer's review of these.
GOVERNANCE_PATHS = (
    "AGENTS.md", "CLAUDE.md", ".coderabbit.yaml", ".greptile", ".gemini/*",
    ".github/copilot-instructions.md", ".github/settings.yml", ".github/CODEOWNERS",
    ".github/skills/*", ".github/workflows/*", ".github/rulesets/*",
    ".github/scripts/*", ".github/actions/*",
)
# Commands that make a reviewer approve or resolve without a real review.
BYPASS_COMMAND = re.compile(
    r"@coderabbitai\s+(?:approve|resolve|ignore|pause)\b|@cubic-dev-ai\s+approve\b",
    re.IGNORECASE,
)
DECISIVE_STATES = {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}

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
        note = f" (escalated to {entry['escalated']})" if entry.get("escalated") else ""
        lines.append(f"- `{entry['sha'][:8]}`: {', '.join(entry['reviewers'])}{note}")
    if len(state["rounds"]) < max_rounds:
        lines.append(
            "\nNext round: treat every thread (fix or justified reply, then "
            f"resolve), keep required checks green, then add `{REQUEST_LABEL}`."
        )
    else:
        lines.append("\nRound budget used. The maintainer decides further reviews.")
    return "\n".join(lines) + "\n"


def is_high_risk(pr, files):
    labels = {(label.get("name") or "").lower() for label in pr.get("labels") or []}
    governance = any(fnmatch.fnmatchcase(f, pat) for f in files for pat in GOVERNANCE_PATHS)
    return governance or bool(labels & HIGH_RISK_LABELS)


def plan_request(pr, state, ranking, max_rounds, repo=None, open_threads=0,
                 per_head=DEFAULT_REVIEWERS_PER_HEAD, high_risk=False):
    """Return (reviewers to trigger, reason). Pure for regression tests.

    `ranking` is review_scoreboard.rank() output, best first.
    """
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
    skip = {"sourcery"} if changed > SOURCERY_MAX_CHANGED_LINES else set()
    count = min(MAX_REVIEWERS_PER_HEAD, max(per_head, 2 if high_risk else 1))
    chosen = scoreboard.choose(ranking, count, skip=skip)
    if not chosen:
        return [], "no reviewer available (all limited, silent, or capped)"
    return chosen, "requested (high risk)" if high_risk and len(chosen) > 1 else "requested"


def plan_escalation(entry, ranking, answered, logins, now, timeout_hours):
    """Return the next reviewer for a round whose reviewers stayed silent, or None.

    A round escalates once, only when none of its reviewers answered and each
    is now held (limited, capped, silent) or the round outlived the timeout.
    """
    if entry.get("escalated") or not entry.get("at"):
        return None
    if any(logins.get(key) in answered for key in entry["reviewers"]):
        return None
    held = {row["key"] for row in ranking if not row["available"]}
    started = scoreboard.parse_time(entry["at"])
    expired = now - started > scoreboard.timedelta(hours=timeout_hours)
    if not expired and not all(key in held for key in entry["reviewers"]):
        return None
    chosen = scoreboard.choose(ranking, 1, exclude=entry["reviewers"])
    return chosen[0] if chosen else None


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
    orchestrator identity.
    """
    return "`" + (text or "").replace("`", "'").replace("\n", " ") + "`"


def is_nit(body):
    # Bots put the severity badge in the opening lines; later prose that merely
    # mentions "nit" must not hide a finding.
    head = "\n".join((body or "").strip().splitlines()[:2])[:200]
    return bool(NIT_PATTERN.search(head)) and not NOT_NIT_PATTERN.search(head)


def link(url):
    """Render a thread link only for a GitHub https URL; anything else is plain inert text."""
    if (url or "").startswith("https://github.com/") and ")" not in url and " " not in url:
        return f"[thread]({url})"
    return "thread link unavailable"


def render_digest(pr_number, head_sha, threads, limit=MAX_LISTED_THREADS):
    open_threads = [t for t in threads if not t["isResolved"]]
    current = [t for t in open_threads if not t["isOutdated"]]
    outdated = [t for t in open_threads if t["isOutdated"]]
    blocking = [t for t in current if not is_nit(t["body"])]
    nits = [t for t in current if is_nit(t["body"])]

    def item(t):
        where = inert(f"{t['path']}:{t['line']}" if t["line"] else t["path"])
        return f"- **{t['author']}** {where} {inert(summarize(t['body']))} ({link(t['url'])})"

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


def quorum_voters(raw, author=None):
    names = [n.strip().lower() for n in (raw or DEFAULT_QUORUM_VOTERS).split(",")]
    # The PR author never votes on its own pull request.
    return list(dict.fromkeys(n for n in names if n and n != (author or "").lower()))


def is_bypass_command(comment):
    # Review apps list their own commands in help text, and quoted or
    # code-formatted text does not run, so only live commands from people count.
    login = ((comment.get("user") or {}).get("login") or "")
    if login.endswith("[bot]"):
        return False
    body = re.sub(r"```.*?```|`[^`\n]*`", "", comment.get("body") or "", flags=re.DOTALL)
    body = "\n".join(line for line in body.splitlines() if not line.lstrip().startswith(">"))
    return bool(BYPASS_COMMAND.search(body))


def bypass_sources(pr, issue_comments, reviews, review_comments):
    """Every place a person can write a reviewer command on a pull request.

    CodeRabbit reads `ignore` from the PR description, and people answer review
    threads with `resolve`, so both count with PR comments and review bodies.
    """
    def entry(item):
        return {"user": item.get("user"), "body": item.get("body")}

    return ([entry(pr)] + [entry(c) for c in issue_comments]
            + [entry(r) for r in reviews] + [entry(c) for c in review_comments])


def evaluate_quorum(pr, reviews, comments, files, voters, required):
    """Return (state, description, details) for the advisory quorum status.

    state is "success", "pending", or "failure". Pure for regression tests.
    """
    head = pr["head"]["sha"]
    if pr["draft"]:
        return "pending", "Draft: no quorum", []
    # GitHub keeps a reviewer's latest APPROVED / CHANGES_REQUESTED / DISMISSED
    # review as its decision; a later COMMENTED review does not replace it.
    latest = {}
    for review in reviews:
        login = ((review.get("user") or {}).get("login") or "").lower()
        if login in voters and review.get("state") in DECISIVE_STATES:
            latest[login] = review
    approved = sorted(
        login for login, review in latest.items()
        if review["state"] == "APPROVED" and review.get("commit_id") == head
    )
    blocking = sorted(
        login for login, review in latest.items() if review["state"] == "CHANGES_REQUESTED"
    )
    bypass = [c for c in comments if is_bypass_command(c)]
    governance = sorted(
        f for f in files if any(fnmatch.fnmatchcase(f, p) for p in GOVERNANCE_PATHS)
    )
    details = [f"Head `{head[:8]}`: {len(approved)}/{required} approvals from {', '.join(voters)}"]
    details += [f"- approved: `{login}`" for login in approved]
    details += [f"- changes requested: `{login}`" for login in blocking]
    details += [f"- bypass command by `{c['user']['login']}`: {inert(summarize(c['body']))}"
                for c in bypass]
    details += [f"- governance path: {inert(path)}" for path in governance[:20]]
    if bypass:
        return "failure", "Reviewer bypass command on this PR", details
    if blocking:
        return "failure", f"Changes requested by {', '.join(blocking)}", details
    if len(approved) < required:
        return "pending", f"{len(approved)}/{required} bot approvals on this head", details
    if governance:
        return "pending", f"{len(approved)}/{required} approvals; governance paths need the maintainer", details
    return "success", f"{len(approved)}/{required} bot approvals on this head", details


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

    def reviews(self, number):
        return self.paged(f"/repos/{self.repo}/pulls/{number}/reviews")

    def review_comments(self, number):
        return self.paged(f"/repos/{self.repo}/pulls/{number}/comments")

    def files(self, number):
        return [f["filename"] for f in self.paged(f"/repos/{self.repo}/pulls/{number}/files")]

    def set_status(self, sha, state, description, target_url=None):
        body = {"state": state, "context": QUORUM_CONTEXT, "description": description[:140]}
        if target_url:
            body["target_url"] = target_url
        self.call("POST", f"/repos/{self.repo}/statuses/{sha}", body)

    def recent_pulls(self, since, limit):
        result, page = [], 1
        while len(result) < limit:
            batch = self.call(
                "GET",
                f"/repos/{self.repo}/pulls?state=all&sort=updated&direction=desc"
                f"&per_page=50&page={page}",
            ) or []
            for item in batch:
                if scoreboard.parse_time(item["updated_at"]) < since:
                    return result
                result.append(item)
            if len(batch) < 50:
                return result
            page += 1
        return result[:limit]

    def trusted_logins(self):
        trusted = {"github-actions[bot]", self.repo.split("/")[0]}
        if self.token_login():
            trusted.add(self.token_login())
        return trusted

    def find_scoreboard(self):
        # Pull requests are issues too; the marker and author filter pick the board.
        for issue in self.paged(f"/repos/{self.repo}/issues"):
            if (issue.get("pull_request") is None
                    and scoreboard.SCOREBOARD_MARKER in (issue.get("body") or "")
                    and issue["user"]["login"] in self.trusted_logins()):
                return issue
        return None

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
        trusted = self.trusted_logins()
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
          comments(first: 20) { nodes { author { login __typename } body url } }
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
                nodes = node["comments"]["nodes"] or [{}]
                first = nodes[0]
                result.append({
                    "isResolved": node["isResolved"],
                    "isOutdated": node["isOutdated"],
                    "path": node["path"],
                    "line": node["line"],
                    "author": rest_login(first.get("author")),
                    "body": first.get("body", ""),
                    "url": first.get("url", ""),
                    "replies": [
                        {"author": rest_login(c.get("author")),
                         "body": c.get("body", "")}
                        for c in nodes[1:]
                    ],
                })
            if not page["pageInfo"]["hasNextPage"]:
                return result
            after = page["pageInfo"]["endCursor"]


def rest_login(author):
    """GraphQL omits the "[bot]" suffix that REST logins carry; add it back."""
    login = (author or {}).get("login") or "unknown"
    if (author or {}).get("__typename") == "Bot" and not login.endswith("[bot]"):
        login += "[bot]"
    return login


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


class Config:
    """Repository variables that steer selection, with safe defaults."""

    def __init__(self, env=None):
        env = os.environ if env is None else env
        self.reviewers = enabled_reviewers(env.get("ENVY_REVIEWERS"))
        self.logins = scoreboard.reviewer_logins(env.get("ENVY_REVIEWER_LOGINS"))
        self.reset_days = scoreboard.parse_mapping(env.get("ENVY_REVIEWER_RESET_DAYS"), int)
        self.caps = scoreboard.parse_mapping(env.get("ENVY_REVIEWER_MONTHLY_CAPS"), int)
        self.timeout = float(env.get("ENVY_REVIEW_TIMEOUT_HOURS") or scoreboard.DEFAULT_TIMEOUT_HOURS)
        self.per_head = int(env.get("ENVY_REVIEWERS_PER_HEAD") or DEFAULT_REVIEWERS_PER_HEAD)
        self.window = int(env.get("ENVY_SCOREBOARD_WINDOW_DAYS") or scoreboard.DEFAULT_WINDOW_DAYS)

    def rank(self, stats, now):
        return scoreboard.rank(stats, self.reviewers, self.logins, now,
                               self.reset_days, self.caps, self.timeout)


def stored_stats(github):
    """Statistics from the scoreboard issue; empty (cold start) when absent."""
    issue = github.find_scoreboard()
    data = scoreboard.parse_scoreboard(issue["body"]) if issue else None
    return (data or {}).get("stats", {})


def run_request(github, number, dry_run):
    pr = github.pull(number)
    max_rounds = int(os.environ.get("ENVY_REVIEW_MAX_ROUNDS") or DEFAULT_MAX_ROUNDS)
    config = Config()
    now = scoreboard.now_utc()
    ranking = config.rank(stored_stats(github), now)
    existing = github.find(number, STATE_MARKER)
    state = parse_state(existing["body"] if existing else "")
    open_threads = 0
    if state["rounds"]:
        open_threads = sum(
            1 for t in github.threads(number) if not t["isResolved"] and not t["isOutdated"]
        )
    chosen, reason = plan_request(
        pr, state, ranking, max_rounds, repo=github.repo, open_threads=open_threads,
        per_head=config.per_head, high_risk=is_high_risk(pr, github.files(number)),
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
    state["rounds"].append({"sha": pr["head"]["sha"], "reviewers": chosen,
                            "at": scoreboard.iso(now)})
    github.upsert(number, existing, render_state(state, max_rounds))
    for name in chosen:
        github.comment(number, REVIEWERS[name])


def collect_record(github, number):
    return {
        "threads": github.threads(number),
        "reviews": [{"login": ((r.get("user") or {}).get("login") or ""),
                     "submitted_at": r.get("submitted_at")} for r in github.reviews(number)],
        "comments": [{"login": ((c.get("user") or {}).get("login") or ""),
                      "body": c.get("body") or "", "created_at": c.get("created_at")}
                     for c in github.comments(number)],
    }


def escalate(github, pr, record, ranking, config, now, dry_run):
    """Trigger the next reviewer when the current head's reviewers stayed silent."""
    number = pr["number"]
    existing = github.find(number, STATE_MARKER)
    state = parse_state(existing["body"] if existing else "")
    entry = next((e for e in state["rounds"] if e["sha"] == pr["head"]["sha"]), None)
    if entry is None or pr["draft"] or pr["state"] != "open":
        return
    answered = {r["login"] for r in record["reviews"]}
    answered |= {c["login"] for c in record["comments"]
                 if scoreboard.is_review_app(c["login"])
                 and not scoreboard.LIMIT_MESSAGE.search(c["body"])}
    key = plan_escalation(entry, ranking, answered, config.logins, now, config.timeout)
    if key is None:
        return
    report(f"PR #{number}: escalating from {', '.join(entry['reviewers'])} to {key}")
    if dry_run:
        return
    entry["reviewers"].append(key)
    entry["escalated"] = key
    max_rounds = int(os.environ.get("ENVY_REVIEW_MAX_ROUNDS") or DEFAULT_MAX_ROUNDS)
    github.upsert(number, existing, render_state(state, max_rounds))
    github.comment(number, REVIEWERS[key])


def run_scoreboard(github, print_only):
    config = Config()
    now = scoreboard.now_utc()
    since = now - scoreboard.timedelta(days=config.window)
    pulls = github.recent_pulls(since, SCOREBOARD_MAX_PRS)
    records = {pr["number"]: collect_record(github, pr["number"]) for pr in pulls}
    stats = scoreboard.analyze(list(records.values()), REVIEWERS, config.logins, now,
                               config.timeout)
    ranking = config.rank(stats, now)
    body = scoreboard.render_scoreboard(stats, ranking, now, config.window, len(pulls))
    if print_only:
        sys.stdout.buffer.write(body.encode("utf-8"))
        return
    issue = github.find_scoreboard()
    if issue is None:
        github.call("POST", f"/repos/{github.repo}/issues",
                    {"title": scoreboard.SCOREBOARD_TITLE, "body": body})
    elif issue["body"] != body:
        github.call("PATCH", issue["url"], {"body": body})
    for pr in pulls:
        same_repo = ((pr["head"].get("repo") or {}).get("full_name")) == github.repo
        if pr["state"] == "open" and not pr["draft"] and same_repo:
            escalate(github, pr, records[pr["number"]], ranking, config, now, False)


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


def run_quorum(github, number, print_only):
    pr = github.pull(number)
    if pr["state"] != "open":
        report(f"PR #{number}: not open; no quorum status")
        return
    voters = quorum_voters(os.environ.get("ENVY_QUORUM_VOTERS"), pr["user"]["login"])
    required = int(os.environ.get("ENVY_QUORUM_REQUIRED") or DEFAULT_QUORUM_REQUIRED)
    reviews = github.reviews(number)
    comments = bypass_sources(pr, github.comments(number), reviews,
                              github.review_comments(number))
    state, description, details = evaluate_quorum(
        pr, reviews, comments, github.files(number), voters, required
    )
    report(f"PR #{number}: {QUORUM_CONTEXT} {state}: {description}")
    for line in details:
        report(line)
    if print_only:
        return
    run_url = None
    if os.environ.get("GITHUB_RUN_ID"):
        run_url = (f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/"
                   f"{github.repo}/actions/runs/{os.environ['GITHUB_RUN_ID']}")
    github.set_status(pr["head"]["sha"], state, description, run_url)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("mode", choices=("request", "digest", "quorum", "scoreboard"))
    parser.add_argument("--pr", type=int, help="pull request number (not for scoreboard)")
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "Mika3578/Envy"))
    parser.add_argument("--dry-run", action="store_true", help="request: plan only")
    parser.add_argument("--print", dest="print_only", action="store_true",
                        help="digest/quorum/scoreboard: print instead of writing")
    args = parser.parse_args(argv)
    if args.mode != "scoreboard" and args.pr is None:
        parser.error("--pr is required for this mode")
    github = GitHub(args.repo, token_from_env())
    if args.mode == "scoreboard":
        run_scoreboard(github, args.print_only)
    elif args.mode == "request":
        run_request(github, args.pr, args.dry_run)
    elif args.mode == "quorum":
        run_quorum(github, args.pr, args.print_only)
    else:
        run_digest(github, args.pr, args.print_only)


if __name__ == "__main__":
    main()
