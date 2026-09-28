#!/usr/bin/env python3
"""Classify CI effort, never review or merge eligibility, from a GitHub event."""

import json
import os
from pathlib import Path


def classify_phase(event_name, event):
    if event_name != "pull_request":
        return "full"
    pr = event["pull_request"]
    if type(pr.get("draft")) is not bool:
        raise ValueError("pull_request.draft must be a boolean")
    labels = pr["labels"]
    if not isinstance(labels, list) or any(
        not isinstance(label, dict) or not isinstance(label.get("name"), str)
        for label in labels
    ):
        raise ValueError("pull_request.labels must contain label names")
    if not pr["draft"]:
        return "ready"
    if any(label["name"] == "stage:live-test" for label in labels):
        return "live-test"
    return "draft"


if __name__ == "__main__":
    phase = classify_phase(
        os.environ["GITHUB_EVENT_NAME"],
        json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8")),
    )
    output = f"phase={phase}\nfull_validation={str(phase != 'draft').lower()}\n"
    print(output, end="")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
        stream.write(output)
