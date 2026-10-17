"""Pure scoring and selection logic for the review orchestrator (no network).

The scoreboard is recomputed from scratch over a rolling window of recent pull
requests, so reruns never double-count and the ranking follows each review
app's current behaviour. No review app exposes its quota through an API, so
availability is inferred from what the apps and our own requests leave on the
pull requests.
"""

import calendar
import json
import re
from datetime import datetime, timedelta, timezone

SCOREBOARD_TITLE = "Review bot scoreboard"
SCOREBOARD_MARKER = "<!-- envy-review-scoreboard"
MAX_SCOREBOARD_CHARS = 60000

# GitHub login of each triggerable reviewer; override with ENVY_REVIEWER_LOGINS.
DEFAULT_LOGINS = {
    "coderabbit": "coderabbitai[bot]",
    "gemini": "gemini-code-assist[bot]",
    "sourcery": "sourcery-ai[bot]",
    "amazonq": "amazon-q-developer[bot]",
    "qodo": "qodo-merge-pro[bot]",
}
# Automation identities that are not review apps.
IGNORED_LOGINS = {"github-actions[bot]", "dependabot[bot]", "renovate[bot]"}

DEFAULT_WINDOW_DAYS = 90
DEFAULT_TIMEOUT_HOURS = 6
# Without a known monthly reset day, a limit message blocks the app this long.
DEFAULT_LIMIT_COOLDOWN_HOURS = 24
# After a timeout, retry the app once this much time has passed since the request.
UNRESPONSIVE_RETRY_HOURS = 24
# Outcomes needed before the measured precision fully replaces the prior.
CONFIDENCE_OUTCOMES = 10
SLOW_MEDIAN_HOURS = 12

# Replies that treat a finding. Agents reply before resolving (AGENTS.md section 5),
# so the first matching reply is the outcome of the finding.
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


def reviewer_logins(raw=None):
    logins = dict(DEFAULT_LOGINS)
    logins.update(parse_mapping(raw))
    return logins


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


def trigger_key(body, commands):
    """Reviewer key a comment triggers, or None. Commands must start the comment."""
    text = (body or "").strip()
    for key, command in commands.items():
        if text == command or text.startswith(command + " ") or text.startswith(command + "\n"):
            return key
    return None


def _blank():
    return {
        "requests": 0, "requests_month": 0, "answered": 0, "timeouts": 0,
        "findings": 0, "useful": 0, "rejected": 0, "unclassified": 0,
        "latencies": [], "limited_at": None, "last_request_at": None,
        "last_answer_at": None, "pending_since": None,
    }


def analyze(records, commands, logins, now, timeout_hours=DEFAULT_TIMEOUT_HOURS):
    """Aggregate per-app statistics over pull request records.

    Each record: {"threads": [...], "reviews": [{"login", "submitted_at"}],
    "comments": [{"login", "body", "created_at"}]}; thread replies are
    {"author", "body"} dicts.
    """
    key_of = {login: key for key, login in logins.items()}
    stats = {}
    month = (now.year, now.month)
    timeout = timedelta(hours=timeout_hours)

    def entry(login):
        return stats.setdefault(login, _blank())

    for record in records:
        for thread in record["threads"]:
            if not is_review_app(thread["author"]):
                continue
            item = entry(thread["author"])
            item["findings"] += 1
            item[classify_thread(thread)] += 1
        answers = {}
        for review in record["reviews"]:
            when = parse_time(review.get("submitted_at"))
            if is_review_app(review["login"]) and when:
                answers.setdefault(review["login"], []).append(when)
        requests = []
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
            key = trigger_key(comment["body"], commands)
            if key and key in logins:
                requests.append((logins[key], when))
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
            elif now - when > timeout:
                item["timeouts"] += 1
            if not later and (not item["pending_since"] or iso(when) > item["pending_since"]):
                item["pending_since"] = iso(when)
    for login, item in stats.items():
        # A later answer anywhere clears an older unanswered request.
        if item["pending_since"] and item["last_answer_at"] and item["last_answer_at"] > item["pending_since"]:
            item["pending_since"] = None
        item["latencies"] = sorted(item["latencies"])[-50:]
        item["key"] = key_of.get(login)
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


def availability(item, key, now, reset_days, monthly_caps, timeout_hours=DEFAULT_TIMEOUT_HOURS):
    """Return (available, reason) for one app."""
    limited = parse_time(item.get("limited_at"))
    if limited:
        if key in reset_days:
            if limited >= window_start(now, reset_days[key]):
                return False, f"limit reported {iso(limited)[:10]}; resets on day {reset_days[key]}"
        elif now - limited < timedelta(hours=DEFAULT_LIMIT_COOLDOWN_HOURS):
            return False, f"limit reported {iso(limited)}"
    cap = monthly_caps.get(key)
    if cap is not None and item.get("requests_month", 0) >= cap:
        return False, f"monthly cap {cap} reached"
    pending = parse_time(item.get("pending_since"))
    if pending and now - pending > timedelta(hours=timeout_hours):
        if now - pending < timedelta(hours=UNRESPONSIVE_RETRY_HOURS):
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


def rank(stats, enabled, logins, now, reset_days, monthly_caps, timeout_hours=DEFAULT_TIMEOUT_HOURS):
    """Return enabled reviewer keys ordered best first, with availability.

    Ties keep the configured order, so a cold start uses ENVY_REVIEWERS order.
    """
    rows = []
    for order, key in enumerate(enabled):
        item = stats.get(logins.get(key, ""), _blank())
        ok, reason = availability(item, key, now, reset_days, monthly_caps, timeout_hours)
        rows.append({"key": key, "score": score(item), "available": ok, "reason": reason,
                     "order": order})
    rows.sort(key=lambda row: (-row["score"], row["order"]))
    return rows


def choose(ranking, count, exclude=(), skip=()):
    """Pick up to `count` available reviewers, best first."""
    chosen = []
    for row in ranking:
        if len(chosen) >= count:
            break
        if row["available"] and row["key"] not in exclude and row["key"] not in skip:
            chosen.append(row["key"])
    return chosen


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
    lines = [
        f"{SCOREBOARD_MARKER} {json.dumps(data, separators=(',', ':'))} -->",
        f"### {SCOREBOARD_TITLE}",
        f"Last {window_days} days, {prs_scanned} pull requests, updated {iso(now)}. "
        "Recomputed from scratch on every run; do not edit.",
        "",
        "#### Selection order",
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
    for login in sorted(stats, key=lambda name: -stats[name]["findings"]):
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
        "See docs/10_dev/review-orchestration.md._",
    ]
    return "\n".join(lines) + "\n"


def now_utc():
    return datetime.now(timezone.utc)
