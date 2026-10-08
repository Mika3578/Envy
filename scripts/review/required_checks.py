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
GATE_CONTEXT = "Final review gate"
# GitHub Actions app id used by the current publisher check-run path.
GATE_PUBLISHER_INTEGRATION_ID = 15368
# Trusted publisher app IDs whose Final review gate receipts are advisory self-noise.
# When a dedicated publisher App is enrolled in Protect develop, add that app id
# here in the same change as the ruleset fragment (never enroll 15368 alone as
# an authenticity bound).
GATE_PUBLISHER_INTEGRATION_IDS = frozenset({GATE_PUBLISHER_INTEGRATION_ID})


def is_advisory_self_gate_check(check):
    """Ignore trusted publisher Final review gate receipts (self-noise)."""
    name = str(check.get("name") or check.get("context") or "")
    integration = check.get("integration_id")
    try:
        integration_id = int(integration) if integration is not None else None
    except (TypeError, ValueError):
        return False
    return name == GATE_CONTEXT and integration_id in GATE_PUBLISHER_INTEGRATION_IDS


def gh(args):
    return json.loads(subprocess.check_output(["gh", "api", *args], text=True, encoding="utf-8"))


def required_specs(required):
    specs = []
    for item in required:
        if isinstance(item, str):
            if item == GATE_CONTEXT:
                raise ValueError(
                    "Final review gate must not enroll as an unbound required check"
                )
            specs.append({"context": item, "integration_id": None})
            continue
        context = str(item.get("context") or item.get("name") or "")
        if not context:
            raise ValueError("Required check context is missing")
        # Rulesets may pin an integration or leave the context unbound (null).
        integration = item.get("integration_id")
        if integration is None:
            if context == GATE_CONTEXT:
                raise ValueError(
                    "Final review gate must not enroll as an unbound required check"
                )
            specs.append({"context": context, "integration_id": None})
        else:
            integration_id = int(integration)
            if (
                context == GATE_CONTEXT
                and integration_id in GATE_PUBLISHER_INTEGRATION_IDS
            ):
                # Shared Actions 15368 publishes advisory self-noise; enrolling it
                # as a required Protect develop slot would be silently ignored.
                raise ValueError(
                    "Final review gate must not enroll shared Actions integration "
                    f"{integration_id} as a required check"
                )
            specs.append({"context": context, "integration_id": integration_id})
    return specs


def _matches_integration(app, integration_id):
    if integration_id is None:
        return True
    if not isinstance(app, dict) or app.get("id") is None:
        return False
    return int(app["id"]) == int(integration_id)


def commit_checks(head, required, runs, statuses):
    """Preserve one latest receipt per required (context, integration_id) pair."""
    specs = required_specs(required)
    check_latest = {}
    status_latest = {}
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
            key = int(item["id"])
            state = item["conclusion"] if item["status"] == "completed" else item["status"]
            receipt = {
                "name": spec["context"],
                "integration_id": spec["integration_id"],
                "state": str(state or "PENDING").upper(),
                "link": item.get("html_url", ""),
            }
            if index not in check_latest or key > check_latest[index][0]:
                check_latest[index] = (key, receipt, item)
    for item in statuses:
        # Commit statuses have no GitHub App id. They cannot satisfy a ruleset
        # receipt that names an integration.
        for index, spec in enumerate(specs):
            if item["context"] != spec["context"] or spec["integration_id"] is not None:
                continue
            key = int(item["id"])
            receipt = {
                "name": spec["context"],
                "integration_id": None,
                "state": item["state"].upper(),
                "link": item.get("target_url", ""),
            }
            if index not in status_latest or key > status_latest[index][0]:
                status_latest[index] = (key, receipt, item)
    checks = []
    for index, spec in enumerate(specs):
        check_entry = check_latest.get(index)
        status_entry = status_latest.get(index)
        if spec["integration_id"] is not None:
            if check_entry:
                checks.append(check_entry[1])
            else:
                checks.append({
                    "name": spec["context"],
                    "integration_id": spec["integration_id"],
                    "state": "PENDING",
                    "link": "",
                })
            continue
        # Unbound context: one receipt. Prefer the newer API source by timestamp;
        # when timestamps are absent/equal, prefer the check-run receipt.
        if check_entry and status_entry:
            check_item = check_entry[2]
            check_status = str(check_item.get("status") or "").lower()
            # Queued/in-progress check runs often omit timestamps; never let a
            # status with created_at outrank an incomplete current-SHA check run.
            if check_status and check_status != "completed":
                checks.append(check_entry[1])
                continue
            check_time = str(
                check_item.get("completed_at")
                or check_item.get("started_at")
                or ""
            )
            status_time = str(
                status_entry[2].get("updated_at")
                or status_entry[2].get("created_at")
                or ""
            )
            if status_time > check_time:
                checks.append(status_entry[1])
            else:
                checks.append(check_entry[1])
        elif check_entry:
            checks.append(check_entry[1])
        elif status_entry:
            checks.append(status_entry[1])
        else:
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
    return {
        "head": head,
        # Keep required_names for older consumers; required_specs preserves
        # per-integration slots so duplicate context names cannot collapse.
        "required_names": [spec["context"] for spec in required],
        "required_specs": required,
        "checks": commit_checks(head, required, runs, statuses),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--head", required=True)
    args = parser.parse_args()
    print(json.dumps(collect_checks(args.repository, args.head)))


if __name__ == "__main__":
    main()
