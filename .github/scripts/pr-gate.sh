#!/usr/bin/env bash
# Wait for the pull-request checks that classification says must run.
# Skipped required checks are accepted only when classification did not
# request them. This job is not itself part of the wait list.
#
# Semantic gate (stricter than GitHub required-check permissiveness):
#   must_pass → success only
#   may_skip  → success or skipped (neutral fails)
#   cancelled → pending until the replacement generation appears or timeout
#   other terminal failures → fail immediately
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=pr-gate-conclusions.sh
source "${SCRIPT_DIR}/pr-gate-conclusions.sh"

REPO="${GITHUB_REPOSITORY:?}"
SHA="${HEAD_SHA:?}"
TIMEOUT_SEC="${TIMEOUT_SEC:-3000}"
POLL_SEC="${POLL_SEC:-15}"
SELF_NAME="${SELF_NAME:-PR Gate}"

RUN_REMOTE_JS="${RUN_REMOTE_JS:-false}"
RUN_DEP_REVIEW="${RUN_DEP_REVIEW:-false}"

must_pass=()
may_skip=()

add_must() { must_pass+=("$1"); }
add_skip() { may_skip+=("$1"); }

# shellcheck source=pr-gate-policy.sh
source "${SCRIPT_DIR}/pr-gate-policy.sh"
pr_gate_policy

echo "Validation phase: ${CI_PHASE:-full}"
if [[ "${CI_PHASE:-full}" == draft ]]; then
	echo "DEFERRED: Windows builds, EnvyTests and C# analysis are not certified by this Draft gate."
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

	# The API defaults to the latest check-run generation. The gate must inspect
	# all generations so a cancelled run cannot mask its replacement.
	check_runs_query="?filter=all&per_page=100"
	json_head="$(gh api --paginate "repos/${REPO}/commits/${SHA}/check-runs${check_runs_query}")"
	json_merge=""
	if [[ -n "${MERGE_SHA:-}" && "${MERGE_SHA}" != "${SHA}" ]]; then
		json_merge="$(gh api --paginate "repos/${REPO}/commits/${MERGE_SHA}/check-runs${check_runs_query}")"
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
		local outcome
		outcome="$(classify_gate_outcome "$st" "$conc" "$allow_skip")"
		case "$outcome" in
		pending)
			if [[ "$st" == "completed" && "$conc" == "cancelled" ]]; then
				pending+=("$name (cancelled; waiting for replacement)")
				echo "- $name: cancelled (waiting for replacement)" >>"$summary_tmp"
			else
				pending+=("$name ($st)")
				echo "- $name: $st" >>"$summary_tmp"
			fi
			;;
		ok)
			ok+=("$name ($conc)")
			echo "- $name: $conc" >>"$summary_tmp"
			;;
		failed)
			failed+=("$name ($conc)")
			echo "- $name: $conc" >>"$summary_tmp"
			;;
		*)
			failed+=("$name (unexpected gate outcome)")
			echo "- $name: unexpected gate outcome" >>"$summary_tmp"
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
