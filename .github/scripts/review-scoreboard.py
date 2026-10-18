#!/usr/bin/env python3
"""Rank AI review apps from recent pull requests and recommend whom to ask.

Usage:
  review-scoreboard.py [--print]        print the scoreboard (default)
  review-scoreboard.py --update-issue   rewrite the "Review bot scoreboard" issue

The scoreboard never requests a review, approves, or posts on a pull request.
It only measures past behaviour so an agent or the maintainer can pick the
reviewer to ask by hand under the review-request rules: one primary reviewer
per HEAD, a second only for a named risk.

Statistics are recomputed from scratch over a rolling window of recent pull
requests, so reruns never double-count. No review app exposes its quota
through an API, so availability is inferred from limit messages, unanswered
requests, and optional monthly caps; treat it as a hint, not a fact.
"""

import argparse
import calendar
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

API = "https://api.github.com"
SCOREBOARD_TITLE = "Review bot scoreboard"
SCOREBOARD_MARKER = "<!-- envy-review-scoreboard"
MAX_SCOREBOARD_CHARS = 60000
MAX_PRS = 40

# Reviewers that can be asked by hand, in the default preference order
# (CodeRabbit is the default primary). Each maps to its GitHub login and to
# the comment that asks it; Copilot is asked through a reviewer request.
REVIEWERS = {
    "coderabbit": ("coderabbitai[bot]", "@coderabbitai review"),
    "copilot": ("copilot-pull-request-reviewer[bot]", None),
    "amazonq": ("amazon-q-developer[bot]", "/q review"),
    "sourcery": ("sourcery-ai[bot]", "@sourcery-ai review"),
    "gemini": ("gemini-code-assist[bot]", "/gemini review"),
}
DEFAULT_REVIEWERS = "coderabbit,copilot,amazonq,sourcery,gemini"
# Automation identities that are not review apps.
IGNORED_LOGINS = {"github-actions[bot]", "dependabot[bot]", "renovate[bot]"}
# Reviewer-request events name some apps differently from their review author.
REQUEST_ALIASES = {"copilot": "copilot-pull-request-reviewer[bot]"}

DEFAULT_WINDOW_DAYS = 90
DEFAULT_TIMEOUT_HOURS = 6
# Without a known monthly reset day, a limit message holds the app this long.
DEFAULT_LIMIT_COOLDOWN_HOURS = 24
# After a timeout, the app is worth asking again once this much time passed.
UNRESPONSIVE_RETRY_HOURS = 24
# Decided outcomes needed before measured precision replaces the 0.5 prior.
CONFIDENCE_OUTCOMES = 10
SLOW_MEDIAN_HOURS = 12

# Replies that treat a finding (fix, or justified no-change) before resolving.
USEFUL_REPLY = re.compile(
    r"^\W*(?:partly\s+)?(?:fixed|addressed)\b.*?\b[0-9a-f]{7,40}\b",
    re.IGNORECASE | re.DOTALL,
)
REJECTED_REPLY = re.compile(
    r"^\W*(?:no change|not reproduced|acknowledged;\s*no change|not applicable|won't fix)\b",
    re.IGNORECASE,
)
# Messages review apps post when a quota or rate limit stops them.
LIMIT_MESSAGE = re.compile(
    r"rate[- ]limit|review limit|usage limit|quota (?:exceeded|exhausted|reached)|"
    r"limit (?:reached|exceeded)|reached (?:its|the|your)\b[^.\n]{0,60}\blimit|"
    r"out of (?:credits|reviews)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------- pure logic

def parse_time(value):
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def iso(value):
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if value else None


def parse_mapping(raw, cast=str):
    """Parse "key=value,key=value" repository variables."""
    result = {}
    for item in (raw or "").split(","):
        if "=" in item:
            key, value = item.split("=", 1)
            if key.strip():
                result[key.strip().lower()] = cast(value.strip())
    return result


class Config:
    """Repository variables, with safe defaults."""

    def __init__(self, env=None):
        env = os.environ if env is None else env
        names = [n.strip().lower() for n in (env.get("ENVY_REVIEWERS") or DEFAULT_REVIEWERS).split(",")]
        unknown = [n for n in names if n and n not in REVIEWERS]
        if unknown:
            raise ValueError(f"unknown reviewers: {', '.join(unknown)}")
        self.reviewers = list(dict.fromkeys(n for n in names if n))
        self.logins = {key: login for key, (login, _) in REVIEWERS.items()}
        self.logins.update(parse_mapping(env.get("ENVY_REVIEWER_LOGINS")))
        self.commands = {key: cmd for key, (_, cmd) in REVIEWERS.items() if cmd}
        self.reset_days = parse_mapping(env.get("ENVY_REVIEWER_RESET_DAYS"), int)
        self.cooldowns = parse_mapping(env.get("ENVY_REVIEWER_COOLDOWN_HOURS"), float)
        # Known exhausted quotas with no app message (Copilot): key=YYYY-MM-DD.
        self.held = {key: parse_time(value + "T00:00:00Z")
                     for key, value in parse_mapping(env.get("ENVY_REVIEWER_HELD")).items()}
        self.caps = parse_mapping(env.get("ENVY_REVIEWER_MONTHLY_CAPS"), int)
        self.timeout = float(env.get("ENVY_REVIEW_TIMEOUT_HOURS") or DEFAULT_TIMEOUT_HOURS)
        self.window = int(env.get("ENVY_SCOREBOARD_WINDOW_DAYS") or DEFAULT_WINDOW_DAYS)


def classify_thread(thread):
    """Return "useful", "rejected", or "unclassified" for one review thread."""
    author = thread["author"]
    for reply in thread.get("replies", []):
        if reply["author"] == author:
            continue
        if USEFUL_REPLY.search(reply["body"] or ""):
            return "useful"
        if REJECTED_REPLY.search(reply["body"] or ""):
            return "rejected"
    return "unclassified"


def is_review_app(login):
    return bool(login) and login.endswith("[bot]") and login not in IGNORED_LOGINS


def request_key(body, commands):
    """Reviewer key a comment asks, or None. The command must open the comment."""
    text = (body or "").strip()
    for key, command in commands.items():
        if text == command or text.startswith(command + " ") or text.startswith(command + "\n"):
            return key
    return None


def blank():
    return {
        "requests": 0, "requests_month": 0, "answered": 0, "timeouts": 0,
        "findings": 0, "useful": 0, "rejected": 0, "unclassified": 0,
        "latencies": [], "limited_at": None, "last_request_at": None,
        "last_answer_at": None, "pending_since": None,
    }


def analyze(records, config, now):
    """Aggregate per-app statistics over pull request records.

    Each record: {"threads": [{"author", "replies": [{"author", "body"}]}],
    "reviews": [{"login", "submitted_at"}], "comments": [{"login", "body",
    "created_at"}], "requested": [{"login", "created_at"}]}. "requested" holds
    reviewer requests (Copilot) from the PR timeline.
    """
    stats = {}
    month = (now.year, now.month)
    timeout = timedelta(hours=config.timeout)

    def entry(login):
        return stats.setdefault(login, blank())

    for record in records:
        for thread in record["threads"]:
            if is_review_app(thread["author"]):
                item = entry(thread["author"])
                item["findings"] += 1
                item[classify_thread(thread)] += 1
        answers = {}
        for review in record["reviews"]:
            when = parse_time(review.get("submitted_at"))
            if is_review_app(review["login"]) and when:
                answers.setdefault(review["login"], []).append(when)
        requests = [(r["login"], parse_time(r["created_at"])) for r in record.get("requested", [])
                    if r.get("created_at")]
        for comment in record["comments"]:
            when = parse_time(comment.get("created_at"))
            login = comment["login"]
            if when is None:
                continue
            if is_review_app(login):
                if LIMIT_MESSAGE.search(comment["body"] or ""):
                    item = entry(login)
                    if not item["limited_at"] or iso(when) > item["limited_at"]:
                        item["limited_at"] = iso(when)
                else:
                    answers.setdefault(login, []).append(when)
                continue
            key = request_key(comment["body"], config.commands)
            if key:
                requests.append((config.logins[key], when))
        for login, when in requests:
            item = entry(login)
            item["requests"] += 1
            if (when.year, when.month) == month:
                item["requests_month"] += 1
            if not item["last_request_at"] or iso(when) > item["last_request_at"]:
                item["last_request_at"] = iso(when)
            later = sorted(t for t in answers.get(login, []) if t >= when)
            if later:
                item["answered"] += 1
                item["latencies"].append(round((later[0] - when).total_seconds() / 3600, 2))
                if not item["last_answer_at"] or iso(later[0]) > item["last_answer_at"]:
                    item["last_answer_at"] = iso(later[0])
            else:
                if now - when > timeout:
                    item["timeouts"] += 1
                if not item["pending_since"] or iso(when) > item["pending_since"]:
                    item["pending_since"] = iso(when)
    for item in stats.values():
        # A later answer anywhere clears an older unanswered request.
        if item["pending_since"] and item["last_answer_at"] and item["last_answer_at"] > item["pending_since"]:
            item["pending_since"] = None
        item["latencies"] = sorted(item["latencies"])[-50:]
    return stats


def window_start(now, reset_day):
    """Start of the current monthly quota window for a reset day of the month."""
    def at(year, month):
        day = min(reset_day, calendar.monthrange(year, month)[1])
        return datetime(year, month, day, tzinfo=timezone.utc)

    start = at(now.year, now.month)
    if now < start:
        year, month = (now.year - 1, 12) if now.month == 1 else (now.year, now.month - 1)
        start = at(year, month)
    return start


def availability(item, key, now, config):
    """Return (available, reason) for one app; a hint, not a guarantee."""
    until = config.held.get(key)
    if until and now < until:
        return False, f"held by configuration until {iso(until)[:10]}"
    limited = parse_time(item.get("limited_at"))
    if limited:
        if key in config.reset_days:
            if limited >= window_start(now, config.reset_days[key]):
                return False, f"limit reported {iso(limited)[:10]}; resets on day {config.reset_days[key]}"
        else:
            cooldown = config.cooldowns.get(key, DEFAULT_LIMIT_COOLDOWN_HOURS)
            if now - limited < timedelta(hours=cooldown):
                return False, f"limit reported {iso(limited)}"
    cap = config.caps.get(key)
    if cap is not None and item.get("requests_month", 0) >= cap:
        return False, f"monthly cap {cap} reached"
    pending = parse_time(item.get("pending_since"))
    if pending and timedelta(hours=config.timeout) < now - pending < timedelta(hours=UNRESPONSIVE_RETRY_HOURS):
        return False, f"no answer since {iso(pending)}"
    return True, "available"


def score(item):
    """Smoothed precision weighted by volume, penalized for timeouts and slowness."""
    useful, rejected = item.get("useful", 0), item.get("rejected", 0)
    precision = (useful + 1) / (useful + rejected + 2)
    confidence = min(1.0, (useful + rejected) / CONFIDENCE_OUTCOMES)
    value = 0.5 + (precision - 0.5) * confidence
    requests = item.get("requests", 0)
    if requests:
        value *= 1 - 0.5 * item.get("timeouts", 0) / requests
    latencies = item.get("latencies") or []
    if latencies and latencies[len(latencies) // 2] > SLOW_MEDIAN_HOURS:
        value *= 0.9
    return round(value, 4)


def rank(stats, config, now):
    """Enabled reviewers, best first; ties keep the configured order."""
    rows = []
    for order, key in enumerate(config.reviewers):
        item = stats.get(config.logins[key], blank())
        ok, reason = availability(item, key, now, config)
        rows.append({"key": key, "score": score(item), "available": ok, "reason": reason,
                     "order": order})
    rows.sort(key=lambda row: (-row["score"], row["order"]))
    return rows


def recommend(ranking):
    """(primary, second) reviewer keys among available apps, or None."""
    available = [row["key"] for row in ranking if row["available"]]
    return (available[0] if available else None, available[1] if len(available) > 1 else None)


def how_to_ask(key):
    command = REVIEWERS[key][1]
    return f"`{command}`" if command else "a reviewer request on the pull request"


def parse_scoreboard(body):
    match = re.search(re.escape(SCOREBOARD_MARKER) + r" (\{.*?\}) -->", body or "", re.DOTALL)
    if not match:
        return None
    if len(match.group(1)) > MAX_SCOREBOARD_CHARS:
        raise ValueError("scoreboard state is too large")
    data = json.loads(match.group(1))
    if not isinstance(data.get("ranking"), list) or not isinstance(data.get("stats"), dict):
        raise ValueError("scoreboard state must contain ranking and stats")
    return data


def render_scoreboard(stats, ranking, now, window_days, prs_scanned):
    data = {"updated_at": iso(now), "window_days": window_days, "prs": prs_scanned,
            "ranking": ranking, "stats": stats}
    primary, second = recommend(ranking)
    lines = [
        f"{SCOREBOARD_MARKER} {json.dumps(data, separators=(',', ':'))} -->",
        f"### {SCOREBOARD_TITLE}",
        f"Last {window_days} days, {prs_scanned} pull requests, updated {iso(now)}. "
        "Recomputed from scratch; do not edit. Nothing here requests a review.",
        "",
        "#### Recommendation (a hint, not a rule)",
    ]
    if primary:
        lines.append(f"- Primary reviewer: `{primary}`, ask with {how_to_ask(primary)}.")
        if second:
            lines.append(f"- Second reviewer, only for a named risk or if the primary is "
                         f"unavailable: `{second}`, ask with {how_to_ask(second)}.")
    else:
        lines.append("- No reviewer looks available; rely on CI and ask the maintainer.")
    lines += [
        "- Ask at most once per reviewer per HEAD and put `Head: <sha>` in the request.",
        "",
        "#### Ranking",
        "| # | Reviewer | Score | Status |",
        "| --- | --- | --- | --- |",
    ]
    for position, row in enumerate(ranking, 1):
        status = "available" if row["available"] else f"held: {row['reason']}"
        lines.append(f"| {position} | `{row['key']}` | {row['score']:.2f} | {status} |")
    lines += [
        "",
        "#### All review apps",
        "| App | Requests (month) | Answered | Timeouts | Findings | Useful | Rejected | "
        "Unclassified | Precision | Median latency | Last limit |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for login in sorted(stats, key=lambda name: (-stats[name]["findings"], name)):
        item = stats[login]
        decided = item["useful"] + item["rejected"]
        precision = f"{item['useful'] / decided:.0%}" if decided else "n/a"
        latencies = item["latencies"]
        median = f"{latencies[len(latencies) // 2]:.1f} h" if latencies else "n/a"
        lines.append(
            f"| `{login}` | {item['requests']} ({item['requests_month']}) | {item['answered']} | "
            f"{item['timeouts']} | {item['findings']} | {item['useful']} | {item['rejected']} | "
            f"{item['unclassified']} | {precision} | {median} | {(item['limited_at'] or 'none')[:10]} |"
        )
    lines += [
        "",
        "_Useful = the treating reply starts with \"Fixed in <sha>\" or \"Addressed in <sha>\"; "
        "rejected = it starts with \"No change\" or \"Not reproduced\". "
        "See docs/10_dev/review-scoreboard.md._",
    ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- GitHub I/O

def rest_login(author):
    """GraphQL omits the "[bot]" suffix that REST logins carry; add it back."""
    login = (author or {}).get("login") or "unknown"
    if (author or {}).get("__typename") == "Bot" and not login.endswith("[bot]"):
        login += "[bot]"
    return login


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
                "User-Agent": "envy-review-scoreboard",
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
        return json.loads(raw) if raw else None

    def paged(self, path):
        result, page = [], 1
        separator = "&" if "?" in path else "?"
        while True:
            batch = self.call("GET", f"{path}{separator}per_page=100&page={page}") or []
            result += batch
            if len(batch) < 100:
                return result
            page += 1

    def recent_pulls(self, since, limit):
        result, page = [], 1
        while len(result) < limit:
            batch = self.call(
                "GET",
                f"/repos/{self.repo}/pulls?state=all&sort=updated&direction=desc"
                f"&per_page=50&page={page}",
            ) or []
            for item in batch:
                if parse_time(item["updated_at"]) < since:
                    return result
                result.append(item)
            if len(batch) < 50:
                return result
            page += 1
        return result[:limit]

    def threads(self, number):
        owner, name = self.repo.split("/")
        query = """
query($owner: String!, $name: String!, $number: Int!, $after: String) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      reviewThreads(first: 100, after: $after) {
        pageInfo { hasNextPage endCursor }
        nodes { comments(first: 20) { nodes { author { login __typename } body } } }
      }
    }
  }
}"""
        result, after = [], None
        while True:
            data = self.call("POST", "/graphql", {"query": query, "variables": {
                "owner": owner, "name": name, "number": number, "after": after}})
            if data.get("errors"):
                raise RuntimeError(f"GraphQL error: {data['errors']}")
            page = data["data"]["repository"]["pullRequest"]["reviewThreads"]
            for node in page["nodes"]:
                comments = node["comments"]["nodes"] or [{}]
                result.append({
                    "author": rest_login(comments[0].get("author")),
                    "replies": [{"author": rest_login(c.get("author")), "body": c.get("body", "")}
                                for c in comments[1:]],
                })
            if not page["pageInfo"]["hasNextPage"]:
                return result
            after = page["pageInfo"]["endCursor"]

    def record(self, number):
        reviews = self.paged(f"/repos/{self.repo}/pulls/{number}/reviews")
        comments = self.paged(f"/repos/{self.repo}/issues/{number}/comments")
        events = self.paged(f"/repos/{self.repo}/issues/{number}/events")
        return {
            "threads": self.threads(number),
            "reviews": [{"login": ((r.get("user") or {}).get("login") or ""),
                         "submitted_at": r.get("submitted_at")} for r in reviews],
            "comments": [{"login": ((c.get("user") or {}).get("login") or ""),
                          "body": c.get("body") or "", "created_at": c.get("created_at")}
                         for c in comments],
            "requested": requested_apps(events),
        }

    def find_scoreboard(self):
        trusted = {"github-actions[bot]", self.repo.split("/")[0]}
        for issue in self.paged(f"/repos/{self.repo}/issues?state=open"):
            if (issue.get("pull_request") is None
                    and SCOREBOARD_MARKER in (issue.get("body") or "")
                    and issue["user"]["login"] in trusted):
                return issue
        return None


def requested_apps(events):
    """Reviewer requests to review apps, from issue timeline events."""
    result = []
    for event in events:
        if event.get("event") != "review_requested":
            continue
        login = ((event.get("requested_reviewer") or {}).get("login") or "")
        login = REQUEST_ALIASES.get(login.lower(), login)
        if is_review_app(login):
            result.append({"login": login, "created_at": event.get("created_at")})
    return result


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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "Mika3578/Envy"))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--print", dest="print_only", action="store_true",
                      help="print the scoreboard (default)")
    mode.add_argument("--update-issue", action="store_true",
                      help="rewrite the scoreboard issue instead of printing")
    args = parser.parse_args(argv)
    config = Config()
    github = GitHub(args.repo, token_from_env())
    now = datetime.now(timezone.utc)
    pulls = github.recent_pulls(now - timedelta(days=config.window), MAX_PRS)
    stats = analyze([github.record(pr["number"]) for pr in pulls], config, now)
    body = render_scoreboard(stats, rank(stats, config, now), now, config.window, len(pulls))
    if not args.update_issue:
        sys.stdout.buffer.write(body.encode("utf-8"))
        return
    issue = github.find_scoreboard()
    if issue is None:
        github.call("POST", f"/repos/{github.repo}/issues",
                    {"title": SCOREBOARD_TITLE, "body": body})
    elif issue["body"] != body:
        github.call("PATCH", issue["url"], {"body": body})


if __name__ == "__main__":
    main()
