#!/usr/bin/env bash
# Shared conclusion helpers for PR Gate (sourced by pr-gate.sh and selftests).
# shellcheck shell=bash

# Historical GitHub "bad terminal" set. Keep cancelled here so other callers
# that want a strict terminal view stay unchanged. PR Gate itself must not
# treat cancelled as fail-fast (concurrency can supersede a run before the
# replacement check-run exists).
is_bad_conclusion() {
	local conclusion="$1"
	case "$conclusion" in
	failure | cancelled | timed_out | action_required | startup_failure | stale)
		return 0
		;;
	*)
		return 1
		;;
	esac
}

# Immediate PR Gate failures. cancelled is omitted on purpose.
is_fail_fast_conclusion() {
	local conclusion="$1"
	case "$conclusion" in
	failure | timed_out | action_required | startup_failure | stale)
		return 0
		;;
	*)
		return 1
		;;
	esac
}

# Completed conclusions that may be replaced by a newer generation on the
# same HEAD. Never treat these as success.
is_supersedable_conclusion() {
	local conclusion="$1"
	[[ "$conclusion" == "cancelled" ]]
}

# Classify one observed check for PR Gate.
# stdout: ok | pending | failed
# args: status conclusion allow_skip(true|false)
classify_gate_outcome() {
	local st="${1:-}"
	local conc="${2:-}"
	local allow_skip="${3:-false}"
	if [[ -z "$st" ]]; then
		printf '%s\n' pending
		return
	fi
	if [[ "$st" != "completed" ]]; then
		printf '%s\n' pending
		return
	fi
	if is_supersedable_conclusion "$conc"; then
		printf '%s\n' pending
		return
	fi
	if is_fail_fast_conclusion "$conc"; then
		printf '%s\n' failed
		return
	fi
	if [[ "$allow_skip" == "true" ]]; then
		if is_ok_may_skip "$conc"; then
			printf '%s\n' ok
			return
		fi
		printf '%s\n' failed
		return
	fi
	if is_ok_must_pass "$conc"; then
		printf '%s\n' ok
		return
	fi
	printf '%s\n' failed
}

# stdin: one or more check-runs API JSON payloads (possibly concatenated).
# $1: current HEAD sha. $2: current merge sha, when GitHub created one.
# Runs from other SHAs are ignored so stale head or merge generations cannot
# mask missing current pull-request state.
pr_gate_latest_check_rows() {
	local head_sha="${1:-}"
	local merge_sha="${2:-}"
	"${PYTHON:-python3}" -c '
import json
import sys
from json import JSONDecodeError

head_sha = sys.argv[1]
merge_sha = sys.argv[2]
allowed_shas = {sha for sha in (head_sha, merge_sha) if sha}
decoder = json.JSONDecoder()
text = sys.stdin.read().strip()
idx = 0
latest = {}
while idx < len(text):
	while idx < len(text) and text[idx].isspace():
		idx += 1
	if idx >= len(text):
		break
	try:
		page, idx = decoder.raw_decode(text, idx)
	except JSONDecodeError as exc:
		raise SystemExit(f"check-runs response was not valid JSON: {exc}") from None
	if not isinstance(page, dict):
		raise SystemExit("check-runs response was not an object")
	runs = page.get("check_runs")
	if not isinstance(runs, list):
		raise SystemExit("check-runs response did not include check_runs")
	for run in runs:
		if not isinstance(run, dict):
			raise SystemExit("check-runs response included a non-object check_run")
		run_id = run.get("id")
		name = run.get("name")
		run_sha = run.get("head_sha")
		status = run.get("status")
		conclusion = run.get("conclusion")
		if not isinstance(run_id, int) or isinstance(run_id, bool) or run_id <= 0:
			raise SystemExit("check-runs response included an invalid check_run id")
		if not isinstance(name, str) or not name:
			raise SystemExit("check-runs response included an invalid check_run name")
		if not isinstance(run_sha, str) or not run_sha:
			raise SystemExit("check-runs response included an invalid check_run head_sha")
		if not isinstance(status, str) or not status:
			raise SystemExit("check-runs response included an invalid check_run status")
		if conclusion is not None and not isinstance(conclusion, str):
			raise SystemExit("check-runs response included an invalid check_run conclusion")
		for field_name, value in (
			("name", name),
			("status", status),
			("conclusion", conclusion),
			("head_sha", run_sha),
		):
			if value is not None and any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in value):
				raise SystemExit(
					f"check-runs response included control characters in check_run {field_name}"
				)
		if name == "PR Gate":
			continue
		if allowed_shas and run_sha not in allowed_shas:
			continue
		current = latest.get(name)
		if current is None or run_id > current[0]:
			latest[name] = (run_id, run)
for name in sorted(latest):
	run = latest[name][1]
	print("{}\t{}\t{}\t{}".format(
		name,
		run.get("status") or "",
		run.get("conclusion") or "",
		run.get("head_sha") or "",
	))
' "$head_sha" "$merge_sha"
}

# must_pass: only success is OK (skipped/neutral/empty fail).
is_ok_must_pass() {
	local conclusion="$1"
	if [[ "$conclusion" == "success" ]]; then
		return 0
	fi
	return 1
}

# may_skip: success or skipped OK; neutral/empty fail.
is_ok_may_skip() {
	local conclusion="$1"
	case "$conclusion" in
	success | skipped)
		return 0
		;;
	*)
		return 1
		;;
	esac
}
