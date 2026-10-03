#!/usr/bin/env python3
"""Read complete required-check policy and receipts for one exact commit."""
import argparse
import json
import re
import subprocess

# Canonical required-check conclusions for Envy. SKIPPED is the documented
# deferred/N/A receipt (Draft Windows lanes, inapplicable matrix legs).
PASSING_CHECK_STATES = frozenset({"SUCCESS", "NEUTRAL", "SKIPPED"})
# Ready/final-review paths must not treat Draft deferral SKIPPED as green.
GATE_PASSING_CHECK_STATES = frozenset({"SUCCESS", "NEUTRAL"})
PENDING_CHECK_STATES = frozenset(
    {"PENDING", "QUEUED", "IN_PROGRESS", "WAITING", "REQUESTED", "EXPECTED"}
)


def gh(args):
    return json.loads(subprocess.check_output(["gh", "api", *args], text=True, encoding="utf-8"))


def required_specs(required):
    specs = []
    for item in required:
        if isinstance(item, str):
            specs.append({"context": item, "integration_id": None})
            continue
        context = str(item.get("context") or item.get("name") or "")
        if not context:
            raise ValueError("Required check context is missing")
        integration = item.get("integration_id")
        if integration is None:
            raise ValueError("Required check integration_id is missing")
        specs.append({"context": context, "integration_id": int(integration)})
    return specs


def _matches_integration(app, integration_id):
    if integration_id is None:
        return True
    if not isinstance(app, dict) or app.get("id") is None:
        return False
    return int(app["id"]) == int(integration_id)


def commit_checks(head, required, runs, statuses):
    """Preserve one receipt per required (context, integration_id) pair."""
    specs = required_specs(required)
    latest = {}
    for item in runs:
        if item.get("head_sha") != head:
            continue
        for index, spec in enumerate(specs):
            if item["name"] != spec["context"]:
                continue
            if not _matches_integration(item.get("app"), spec["integration_id"]):
                continue
            # REST exposes creation IDs, not created_at. Never sort by started_at:
            # an older generation can start after its replacement.
            key = item["id"]
            slot = (index, "check")
            state = item["conclusion"] if item["status"] == "completed" else item["status"]
            if slot not in latest or key > latest[slot][0]:
                latest[slot] = (key, {
                    "name": spec["context"],
                    "integration_id": spec["integration_id"],
                    "state": str(state or "PENDING").upper(),
                    "link": item.get("html_url", ""),
                })
    for item in statuses:
        # Commit statuses have no GitHub App id. They cannot satisfy a ruleset
        # receipt that names an integration.
        for index, spec in enumerate(specs):
            if item["context"] != spec["context"] or spec["integration_id"] is not None:
                continue
            key = item["id"]
            slot = (index, "status")
            if slot not in latest or key > latest[slot][0]:
                latest[slot] = (key, {
                    "name": spec["context"],
                    "integration_id": None,
                    "state": item["state"].upper(),
                    "link": item.get("target_url", ""),
                })
    checks = []
    for index, spec in enumerate(specs):
        for kind in ("check", "status"):
            slot = (index, kind)
            if slot in latest:
                checks.append(latest[slot][1])
        if (index, "check") not in latest and (index, "status") not in latest:
            checks.append({
                "name": spec["context"],
                "integration_id": spec["integration_id"],
                "state": "PENDING",
                "link": "",
            })
    return checks


def collect_checks(repository, head):
    if repository != "Mika3578/Envy" or not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ValueError("Expected the Envy fork and an exact commit ID")
    prefix = f"repos/{repository}"
    rules = gh([f"{prefix}/rules/branches/develop"])
    required = required_specs([
        {"context": check["context"], "integration_id": check["integration_id"]}
        for rule in rules
        if rule["type"] == "required_status_checks"
        for check in rule["parameters"]["required_status_checks"]
    ])
    if not required:
        raise ValueError("Required check policy is missing")
    run_pages = gh([f"{prefix}/commits/{head}/check-runs?per_page=100", "--paginate", "--slurp"])
    runs = [item for page in run_pages for item in page["check_runs"]]
    status_pages = gh([f"{prefix}/commits/{head}/statuses?per_page=100", "--paginate", "--slurp"])
    statuses = [item for page in status_pages for item in page]
    return {"head": head, "required_names": [spec["context"] for spec in required],
            "checks": commit_checks(head, required, runs, statuses)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--head", required=True)
    args = parser.parse_args()
    print(json.dumps(collect_checks(args.repository, args.head)))


if __name__ == "__main__":
    main()
