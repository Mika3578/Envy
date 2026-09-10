#!/usr/bin/env bash
# Wait for the pull-request checks that classification says must run.
# Skipped required checks are accepted only when classification did not
# request them. This job is not itself part of the wait list.
set -euo pipefail

REPO="${GITHUB_REPOSITORY:?}"
SHA="${HEAD_SHA:?}"
TIMEOUT_SEC="${TIMEOUT_SEC:-3000}"
POLL_SEC="${POLL_SEC:-15}"
SELF_NAME="${SELF_NAME:-PR Gate}"

RUN_WINDOWS_BUILD="${RUN_WINDOWS_BUILD:-false}"
RUN_CODEQL_CPP="${RUN_CODEQL_CPP:-false}"
RUN_CODEQL_JS="${RUN_CODEQL_JS:-false}"
RUN_CODEQL_CSHARP="${RUN_CODEQL_CSHARP:-false}"
RUN_REMOTE_JS="${RUN_REMOTE_JS:-false}"
RUN_FORMAT="${RUN_FORMAT:-false}"
RUN_DEP_REVIEW="${RUN_DEP_REVIEW:-false}"

must_pass=()
may_skip=()

add_must() { must_pass+=("$1"); }
add_skip() { may_skip+=("$1"); }

add_must "Lint build files"
add_must "secret-scan"
add_must "Vcpkg manifest sanity"

if [[ "$RUN_WINDOWS_BUILD" == "true" ]]; then
	add_must "Build x64 Release"
	add_must "Build Win32 Release"
else
	add_skip "Build x64 Release"
	add_skip "Build Win32 Release"
fi

if [[ "$RUN_CODEQL_CPP" == "true" ]]; then
	add_must "Analyze (c-cpp)"
else
	add_skip "Analyze (c-cpp)"
fi

if [[ "$RUN_CODEQL_JS" == "true" ]]; then
	add_must "Analyze (javascript-typescript)"
else
	add_skip "Analyze (javascript-typescript)"
fi

if [[ "$RUN_FORMAT" == "true" ]]; then
	add_must "Format Check"
else
	add_skip "Format Check"
fi

if [[ "$RUN_CODEQL_CSHARP" == "true" ]]; then
	add_must "Analyze (csharp)"
fi

if [[ "$RUN_REMOTE_JS" == "true" ]]; then
	add_must "Remote JS Security Tests"
fi

if [[ "$RUN_DEP_REVIEW" == "true" ]]; then
	add_must "Dependency review"
fi

echo "Must pass: ${must_pass[*]:-(none)}"
echo "May skip: ${may_skip[*]:-(none)}"

is_bad_conclusion() {
	case "$1" in
	failure | cancelled | timed_out | action_required | startup_failure | stale)
		return 0
		;;
	*)
		return 1
		;;
	esac
}

is_ok_conclusion() {
	case "$1" in
	success | skipped | neutral)
		return 0
		;;
	*)
		return 1
		;;
	esac
}

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

	mapfile -t rows < <(printf '%s\n' "$json" | jq -s -r '
		[ .[] | .check_runs[]? ]
		| map(select(.name != null and .name != "PR Gate"))
		| group_by(.name)
		| map(sort_by(.id) | last)
		| .[]
		| [.name, (.status // ""), (.conclusion // "")]
		| @tsv
	')

	declare -A status_by_name=()
	declare -A conclusion_by_name=()
	for row in "${rows[@]:-}"; do
		[[ -z "$row" ]] && continue
		name="${row%%$'\t'*}"
		rest="${row#*$'\t'}"
		st="${rest%%$'\t'*}"
		conc="${rest#*$'\t'}"
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
		if [[ "$st" != "completed" ]]; then
			pending+=("$name ($st)")
			echo "- $name: $st" >>"$summary_tmp"
			return
		fi
		if is_bad_conclusion "$conc"; then
			failed+=("$name ($conc)")
			echo "- $name: $conc" >>"$summary_tmp"
			return
		fi
		if [[ "$conc" == "skipped" && "$allow_skip" != "true" ]]; then
			failed+=("$name (skipped but required for this PR)")
			echo "- $name: skipped (unexpected)" >>"$summary_tmp"
			return
		fi
		if is_ok_conclusion "$conc"; then
			ok+=("$name ($conc)")
			echo "- $name: $conc" >>"$summary_tmp"
			return
		fi
		pending+=("$name ($conc)")
		echo "- $name: $conc" >>"$summary_tmp"
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
