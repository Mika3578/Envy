#!/usr/bin/env python3
"""Read complete required-check policy and receipts for one exact commit."""
import argparse
import json
import re
import subprocess


def gh(args):
    return json.loads(subprocess.check_output(["gh", "api", *args], text=True, encoding="utf-8"))


def commit_checks(head, required, runs, statuses):
    latest = {}
    for item in runs:
        if item.get("head_sha") != head or item["name"] not in required:
            continue
        # REST exposes creation IDs, not created_at. Never sort by started_at:
        # an older generation can start after its replacement.
        key, name = item["id"], (item["name"], "check")
        state = item["conclusion"] if item["status"] == "completed" else item["status"]
        if name not in latest or key > latest[name][0]:
            latest[name] = (key, {"name": item["name"],
                "state": str(state or "PENDING").upper(), "link": item.get("html_url", "")})
    for item in statuses:
        if item["context"] not in required:
            continue
        key, name = item["id"], (item["context"], "status")
        if name not in latest or key > latest[name][0]:
            latest[name] = (key, {"name": item["context"],
                "state": item["state"].upper(), "link": item.get("target_url", "")})
    checks = [latest[name][1] for name in sorted(latest)]
    observed = {item["name"] for item in checks}
    checks.extend({"name": name, "state": "PENDING", "link": ""}
                  for name in sorted(set(required) - observed))
    return checks


def collect_checks(repository, head):
    if repository != "Mika3578/Envy" or not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ValueError("Expected the Envy fork and an exact commit ID")
    prefix = f"repos/{repository}"
    rules = gh([f"{prefix}/rules/branches/develop"])
    required = sorted({check["context"] for rule in rules
        if rule["type"] == "required_status_checks"
        for check in rule["parameters"]["required_status_checks"]})
    if not required:
        raise ValueError("Required check policy is missing")
    run_pages = gh([f"{prefix}/commits/{head}/check-runs?per_page=100", "--paginate", "--slurp"])
    runs = [item for page in run_pages for item in page["check_runs"]]
    status_pages = gh([f"{prefix}/commits/{head}/statuses?per_page=100", "--paginate", "--slurp"])
    statuses = [item for page in status_pages for item in page]
    return {"head": head, "required_names": required,
            "checks": commit_checks(head, required, runs, statuses)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--head", required=True)
    args = parser.parse_args()
    print(json.dumps(collect_checks(args.repository, args.head)))


if __name__ == "__main__":
    main()
