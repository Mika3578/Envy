#!/usr/bin/env bash
# Wait for the pull-request checks that classification says must run.
# Skipped required checks are accepted only when classification did not
# request them. This job is not itself part of the wait list.
#
# Semantic gate (stricter than GitHub required-check permissiveness):
#   must_pass → success only
#   may_skip  → success or skipped (neutral fails)
#   cancelled → pending (wait for a replacement generation or timeout)
#   failure/timed_out/action_required/startup_failure/stale → fail immediately
# Cancelled is never success. A superseded cancelled without replacement
# fails only when TIMEOUT_SEC elapses.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=pr-gate-conclusions.sh
source "${SCRIPT_DIR}/pr-gate-conclusions.sh"

REPO="${GITHUB_REPOSITORY:?}"
SHA="${HEAD_SHA:?}"
TIMEOUT_SEC="${TIMEOUT_SEC:-3000}"
POLL_SEC="${POLL_SEC:-15}"
SELF_NAME="${SELF_NAME:-PR Gate}"

RUN_WINDOWS_BUILD="${RUN_WINDOWS_BUILD:-false}"
RUN_REMOTE_JS="${RUN_REMOTE_JS:-false}"
RUN_DEP_REVIEW="${RUN_DEP_REVIEW:-false}"

must_pass=()
may_skip=()

add_must() { must_pass+=("$1"); }
add_skip() { may_skip+=("$1"); }

add_must "Lint build files"
add_must "secret-scan"
add_must "Vcpkg manifest sanity"
# Code Scanning expects all three develop CodeQL configurations on every PR.
add_must "Analyze (c-cpp)"
add_must "Analyze (javascript-typescript)"
add_must "Analyze (csharp)"
# Required Format Check — success no-op when no first-party C/C++ hunks.
add_must "Format Check"
# Protect develop requires Documentation Check; the job always emits success
# (full check or classify no-op). Keep it must_pass so a silent skip cannot
# green-wash the gate.
add_must "Documentation Check"

if [[ "$RUN_WINDOWS_BUILD" == "true" ]]; then
	add_must "Build x64 Release"
	add_must "Build Win32 Release"
else
	add_skip "Build x64 Release"
	add_skip "Build Win32 Release"
fi

if [[ "$RUN_REMOTE_JS" == "true" ]]; then
	add_must "Remote JS Security Tests"
fi

if [[ "$RUN_DEP_REVIEW" == "true" ]]; then
	add_must "Dependency review"
fi

echo "Must pass: ${must_pass[*]:-(none)}"
echo "May skip: ${may_skip[*]:-(none)}"

start_ts=$(date +%s)
summary_tmp="$(mktemp)"
trap 'rm -f "$summary_tmp"' EXIT

while true; do
	now=$(date +%s)
	elapsed=$((now - start_ts))
	if ((elapsed >= TIMEOUT_SEC)); then
		echo "::error::Timed out after ${TIMEOUT_SEC}s waiting for required checks."
		cat "$summary_tmp" || true
		exit 1
	fi

	json_head="$(gh api --paginate "repos/${REPO}/commits/${SHA}/check-runs")"
	json_merge=""
	if [[ -n "${MERGE_SHA:-}" && "${MERGE_SHA}" != "${SHA}" ]]; then
		json_merge="$(gh api --paginate "repos/${REPO}/commits/${MERGE_SHA}/check-runs")"
	fi
	json="${json_head}"$'\n'"${json_merge}"

	rows_text="$(printf '%s\n' "$json" | pr_gate_latest_check_rows "$SHA" "${MERGE_SHA:-}")" || {
		echo "::error::Failed to parse check-run payloads."
		exit 1
	}
	mapfile -t rows <<<"$rows_text"

	declare -A status_by_name=()
	declare -A conclusion_by_name=()
	for row in "${rows[@]:-}"; do
		[[ -z "$row" ]] && continue
		IFS=$'\t' read -r name st conc _head <<<"$row"
		status_by_name["$name"]="$st"
		conclusion_by_name["$name"]="$conc"
	done

	pending=()
	failed=()
	ok=()
	: >"$summary_tmp"

	check_one() {
		local name="$1"
		local allow_skip="$2"
		local st="${status_by_name[$name]:-}"
		local conc="${conclusion_by_name[$name]:-}"
		if [[ -z "$st" ]]; then
			pending+=("$name (not reported yet)")
			echo "- $name: waiting" >>"$summary_tmp"
			return
		fi
		local outcome
		outcome="$(classify_gate_outcome "$st" "$conc" "$allow_skip")"
		case "$outcome" in
		pending)
			if [[ "$st" == "completed" && "$conc" == "cancelled" ]]; then
				pending+=("$name (cancelled; waiting for replacement)")
				echo "- $name: cancelled (waiting for replacement)" >>"$summary_tmp"
			elif [[ -z "$st" ]]; then
				pending+=("$name (not reported yet)")
				echo "- $name: waiting" >>"$summary_tmp"
			else
				pending+=("$name ($st)")
				echo "- $name: $st" >>"$summary_tmp"
			fi
			;;
		failed)
			failed+=("$name ($conc)")
			echo "- $name: $conc" >>"$summary_tmp"
			;;
		ok)
			ok+=("$name ($conc)")
			echo "- $name: $conc" >>"$summary_tmp"
			;;
		*)
			failed+=("$name (unexpected classifier $outcome)")
			echo "- $name: unexpected classifier $outcome" >>"$summary_tmp"
			;;
		esac
	}

	for name in "${must_pass[@]}"; do
		check_one "$name" "false"
	done
	for name in "${may_skip[@]}"; do
		check_one "$name" "true"
	done

	echo "=== PR Gate ${elapsed}s ==="
	cat "$summary_tmp"

	if ((${#failed[@]} > 0)); then
		echo "::error::Required checks failed: ${failed[*]}"
		{
			echo "## PR Gate"
			echo
			echo "Failed: ${failed[*]}"
			echo
			cat "$summary_tmp"
		} >>"${GITHUB_STEP_SUMMARY:-/dev/null}"
		exit 1
	fi

	if ((${#pending[@]} == 0)); then
		echo "All expected checks completed successfully."
		{
			echo "## PR Gate"
			echo
			echo "All expected checks passed or were intentionally skipped."
			echo
			echo "| Check | Result |"
			echo "| --- | --- |"
			cat "$summary_tmp" | sed 's/^- /| /; s/: / | /; s/$/ |/'
		} >>"${GITHUB_STEP_SUMMARY:-/dev/null}"
		exit 0
	fi

	echo "Still waiting: ${pending[*]}"
	sleep "$POLL_SEC"
done
