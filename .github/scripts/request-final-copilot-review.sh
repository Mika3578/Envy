#!/usr/bin/env bash
# Request a fresh Copilot Code Review on an eligible develop PR (manual dispatch only).
# Eligibility failures exit 0 with a GitHub Actions summary; request failures exit 1.
set -euo pipefail

OWNER="${REPOSITORY%%/*}"
REPO="${REPOSITORY#*/}"
PR_NUMBER="${PR_NUMBER:?PR_NUMBER is required}"
SUMMARY_FILE="${GITHUB_STEP_SUMMARY:-/dev/stderr}"

COPILOT_REVIEWER_BOT='copilot-pull-request-reviewer[bot]'
FORBIDDEN_AUTHOR_LOGINS=(
	'copilot-swe-agent[bot]'
	'github-copilot[bot]'
)

declare -a INELIGIBLE_REASONS=()

note_ineligible() {
	INELIGIBLE_REASONS+=("$1")
}

write_summary() {
	local title="$1"
	shift
	{
		echo "## ${title}"
		echo
		for reason in "${INELIGIBLE_REASONS[@]}"; do
			echo "- ${reason}"
		done
		while (($#)); do
			echo "$1"
			shift
		done
	} >>"$SUMMARY_FILE"
}

require_int_pr_number() {
	if [[ ! "$PR_NUMBER" =~ ^[0-9]+$ ]]; then
		note_ineligible "Invalid \`pr_number\` input: must be a positive integer (got \`${PR_NUMBER}\`)."
		write_summary "Final Copilot review not requested"
		exit 0
	fi
}

fetch_pr_json() {
	local pr_json
	if ! pr_json="$(gh api graphql -f query='query($o:String!,$n:String!,$p:Int!){
		repository(owner:$o,name:$n){
			pullRequest(number:$p){
				id
				state
				isDraft
				baseRefName
				headRefOid
				reviewDecision
				mergeStateStatus
				author{login __typename}
				headRepository{nameWithOwner}
				reviewThreads(first:100){
					totalCount
					nodes{isResolved}
					pageInfo{hasNextPage endCursor}
				}
			}
		}
	}' -f o="$OWNER" -f n="$REPO" -F p="$PR_NUMBER" 2>/dev/null)"; then
		note_ineligible "Pull request #${PR_NUMBER} was not found in \`${REPOSITORY}\`."
		write_summary "Final Copilot review not requested"
		exit 0
	fi
	echo "$pr_json"
}

has_unresolved_threads() {
	local pr_json="$1"
	local unresolved
	unresolved="$(echo "$pr_json" | jq '[.data.repository.pullRequest.reviewThreads.nodes[]? | select(.isResolved == false)] | length')"
	if [[ "$unresolved" != "0" ]]; then
		return 0
	fi
	if [[ "$(echo "$pr_json" | jq -r '.data.repository.pullRequest.reviewThreads.pageInfo.hasNextPage')" == "true" ]]; then
		note_ineligible "Unresolved review-thread check is inconclusive (more than 100 threads); resolve threads or ask a maintainer to verify manually."
		return 0
	fi
	return 1
}

forbidden_author() {
	local login="$1"
	local entry
	for entry in "${FORBIDDEN_AUTHOR_LOGINS[@]}"; do
		if [[ "$login" == "$entry" ]]; then
			return 0
		fi
	done
	return 1
}

required_checks_ok() {
	local checks_json count name state
	checks_json="$(gh pr checks "$PR_NUMBER" --repo "$REPOSITORY" --required --json name,state 2>/dev/null || echo '[]')"
	count="$(echo "$checks_json" | jq 'length')"
	if [[ "$count" == "0" ]]; then
		note_ineligible "Could not read required status checks for PR #${PR_NUMBER} (token or API limitation)."
		return 1
	fi

	while IFS=$'\t' read -r name state; do
		name="${name//$'\r'/}"
		state="${state//$'\r'/}"
		case "$state" in
		SUCCESS | SKIPPED | NEUTRAL) ;;
		PENDING | QUEUED | IN_PROGRESS)
			note_ineligible "Required check \`${name}\` is still \`${state}\` for the current HEAD."
			;;
		*)
			note_ineligible "Required check \`${name}\` is \`${state}\` (not passing)."
			;;
		esac
	done < <(echo "$checks_json" | jq -r '.[] | "\(.name)\t\(.state)"')

	if ((${#INELIGIBLE_REASONS[@]} > 0)); then
		return 1
	fi
	return 0
}

evaluate_eligibility() {
	local pr_json="$1"
	local pr state is_draft base head_repo author_login review_decision merge_state head_oid

	pr="$(echo "$pr_json" | jq '.data.repository.pullRequest')"
	if [[ "$pr" == "null" ]]; then
		note_ineligible "Pull request #${PR_NUMBER} does not exist in \`${REPOSITORY}\`."
		return 1
	fi

	state="$(echo "$pr" | jq -r '.state')"
	is_draft="$(echo "$pr" | jq -r '.isDraft')"
	base="$(echo "$pr" | jq -r '.baseRefName')"
	head_repo="$(echo "$pr" | jq -r '.headRepository.nameWithOwner // empty')"
	author_login="$(echo "$pr" | jq -r '.author.login // empty')"
	review_decision="$(echo "$pr" | jq -r '.reviewDecision // empty')"
	merge_state="$(echo "$pr" | jq -r '.mergeStateStatus // empty')"
	head_oid="$(echo "$pr" | jq -r '.headRefOid')"

	if [[ "$state" != "OPEN" ]]; then
		note_ineligible "Pull request #${PR_NUMBER} is \`${state}\`, not \`OPEN\`."
	fi
	if [[ "$is_draft" == "true" ]]; then
		note_ineligible "Pull request #${PR_NUMBER} is still a **Draft**; mark it Ready for Review first."
	fi
	if [[ "$base" != "develop" ]]; then
		note_ineligible "Pull request #${PR_NUMBER} targets \`${base}\`; only \`develop\` is eligible."
	fi
	if [[ -n "$head_repo" && "$head_repo" != "$REPOSITORY" ]]; then
		note_ineligible "Pull request #${PR_NUMBER} head \`${head_repo}\` is not this repository (\`${REPOSITORY}\`); fork PRs are out of scope."
	fi
	if forbidden_author "$author_login"; then
		note_ineligible "Pull request #${PR_NUMBER} is authored by \`${author_login}\`; repository policy forbids Copilot self-approval on agent-authored PRs."
	fi
	if [[ "$review_decision" == "CHANGES_REQUESTED" ]]; then
		note_ineligible "Pull request #${PR_NUMBER} has an active \`CHANGES_REQUESTED\` review decision."
	fi
	if has_unresolved_threads "$pr_json"; then
		if [[ "${#INELIGIBLE_REASONS[@]}" -eq 0 ]] || [[ "${INELIGIBLE_REASONS[-1]}" != *"inconclusive"* ]]; then
			note_ineligible "Pull request #${PR_NUMBER} has unresolved review conversation threads."
		fi
	fi
	case "$merge_state" in
	BEHIND)
		note_ineligible "Pull request #${PR_NUMBER} is \`BEHIND\` \`develop\`; update the branch before the final Copilot review."
		;;
	UNSTABLE)
		note_ineligible "Pull request #${PR_NUMBER} merge state is \`UNSTABLE\` (failing or pending checks)."
		;;
	DIRTY)
		note_ineligible "Pull request #${PR_NUMBER} merge state is \`DIRTY\` (conflicts or unresolved merge state)."
		;;
	UNKNOWN)
		note_ineligible "Pull request #${PR_NUMBER} merge state is \`UNKNOWN\`; retry after GitHub finishes computing mergeability."
		;;
	esac

	if ((${#INELIGIBLE_REASONS[@]} == 0)); then
		if ! required_checks_ok; then
			:
		fi
	fi

	if ((${#INELIGIBLE_REASONS[@]} > 0)); then
		return 1
	fi

	ELIGIBLE_HEAD_OID="$head_oid"
	return 0
}

request_copilot_refresh() {
	local pr_node_id="$1"
	local head_oid_before="$2"
	local pr_json head_oid_after

	pr_json="$(fetch_pr_json)"
	head_oid_after="$(echo "$pr_json" | jq -r '.data.repository.pullRequest.headRefOid')"
	if [[ "$head_oid_after" != "$head_oid_before" ]]; then
		note_ineligible "HEAD changed during eligibility (\`${head_oid_before:0:7}\` → \`${head_oid_after:0:7}\`); re-run after the branch is stable."
		write_summary "Final Copilot review not requested"
		exit 0
	fi

	local bot_node snap user_ids team_ids
	bot_node="$(gh api '/users/copilot-pull-request-reviewer%5Bbot%5D' --jq .node_id)"

	snap="$(gh api graphql -f query='query($o:String!,$n:String!,$p:Int!){repository(owner:$o,name:$n){pullRequest(number:$p){reviewRequests(first:20){nodes{requestedReviewer{__typename ... on User{id login} ... on Team{id slug} ... on Bot{id login}}}}}}}' \
		-f o="$OWNER" -f n="$REPO" -F p="$PR_NUMBER")"
	user_ids="$(echo "$snap" | jq -c '[.data.repository.pullRequest.reviewRequests.nodes[] | select(.requestedReviewer.__typename=="User") | .requestedReviewer.id]')"
	team_ids="$(echo "$snap" | jq -c '[.data.repository.pullRequest.reviewRequests.nodes[] | select(.requestedReviewer.__typename=="Team") | .requestedReviewer.id]')"

	gh api graphql --input - <<EOF
{"query":"mutation(\$pr:ID!){requestReviews(input:{pullRequestId:\$pr,botIds:[],userIds:[],teamIds:[],union:false}){clientMutationId}}","variables":{"pr":"$pr_node_id"}}
EOF

	gh api graphql --input - <<EOF
{"query":"mutation(\$pr:ID!,\$bots:[ID!]!,\$users:[ID!]!,\$teams:[ID!]!){requestReviews(input:{pullRequestId:\$pr,botIds:\$bots,userIds:\$users,teamIds:\$teams,union:false}){clientMutationId}}","variables":{"pr":"$pr_node_id","bots":["$bot_node"],"users":$user_ids,"teams":$team_ids}}
EOF

	write_summary "Final Copilot review requested" \
		"" \
		"- PR: #${PR_NUMBER}" \
		"- HEAD: \`${head_oid_before}\`" \
		"- Copilot reviewer: \`${COPILOT_REVIEWER_BOT}\`" \
		"- Preserved human user reviewer IDs: \`${user_ids}\`" \
		"- Preserved team reviewer IDs: \`${team_ids}\`" \
		"" \
		"This workflow only **requests** Copilot Code Review. It does not submit \`APPROVED\`, merge, or change branch protection."
}

main() {
	require_int_pr_number

	local pr_json pr_node head_oid
	pr_json="$(fetch_pr_json)"
	pr_node="$(echo "$pr_json" | jq -r '.data.repository.pullRequest.id // empty')"

	if ! evaluate_eligibility "$pr_json"; then
		write_summary "Final Copilot review not requested"
		exit 0
	fi
	head_oid="$ELIGIBLE_HEAD_OID"

	if [[ -z "$pr_node" || "$pr_node" == "null" ]]; then
		note_ineligible "Could not resolve the pull request node ID."
		write_summary "Final Copilot review not requested"
		exit 0
	fi

	if [[ "${REQUEST_FINAL_COPILOT_DRY_RUN:-}" == "1" ]]; then
		write_summary "Eligible for final Copilot review (dry run)" \
			"" \
			"- PR: #${PR_NUMBER}" \
			"- HEAD: \`${head_oid}\`" \
			"- No Copilot reviewer was requested (\`REQUEST_FINAL_COPILOT_DRY_RUN=1\`)."
		exit 0
	fi

	request_copilot_refresh "$pr_node" "$head_oid"
}

main "$@"
