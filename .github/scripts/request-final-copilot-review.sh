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
	'copilot-swe-agent'
	'github-copilot[bot]'
	'github-copilot'
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
				reviewRequests(first:100){
					nodes{requestedReviewer{__typename ... on Bot{login} ... on User{login}}}
				}
				reviewThreads(first:100){
					totalCount
					nodes{
						isResolved
						isOutdated
						comments(first:100){
							pageInfo{hasNextPage}
							nodes{author{login __typename} commit{oid}}
						}
					}
					pageInfo{hasNextPage endCursor}
				}
			}
		}
	}' -f o="$OWNER" -f n="$REPO" -F p="$PR_NUMBER" 2>/dev/null)"; then
		note_ineligible "Could not load a complete GraphQL snapshot for pull request #${PR_NUMBER}."
		write_summary "Final Copilot review not requested"
		return 1
	fi
	if ! echo "$pr_json" | jq -e 'type=="object" and ((.errors // []) | length == 0) and (.data.repository.pullRequest | type=="object") and (.data.repository.pullRequest | has("reviewThreads"))' >/dev/null 2>&1; then
		note_ineligible "GraphQL snapshot for pull request #${PR_NUMBER} is incomplete or returned errors."
		write_summary "Final Copilot review not requested"
		return 1
	fi
	echo "$pr_json"
}

has_unresolved_threads() {
	local pr_json="$1"
	local head_oid="$2"
	local unresolved
	unresolved="$(echo "$pr_json" | jq '[.data.repository.pullRequest.reviewThreads.nodes[]? | select(.isResolved == false)] | length')"
	if [[ "$unresolved" != "0" ]]; then
		return 0
	fi
	if [[ "$(echo "$pr_json" | jq -r '.data.repository.pullRequest.reviewThreads.pageInfo.hasNextPage')" == "true" ]]; then
		note_ineligible "Unresolved review-thread check is inconclusive (more than 100 threads); resolve threads or ask a maintainer to verify manually."
		return 0
	fi
	if [[ "$(echo "$pr_json" | jq '[.data.repository.pullRequest.reviewThreads.nodes[]? | .comments.pageInfo.hasNextPage == true] | any')" == "true" ]]; then
		note_ineligible "Review-thread disposition check is inconclusive (comment pagination truncated)."
		return 0
	fi
	local untreated
	untreated="$(echo "$pr_json" | jq --arg head "$head_oid" --argjson copilot '["Copilot","copilot-pull-request-reviewer","copilot-pull-request-reviewer[bot]"]' '
		[.data.repository.pullRequest.reviewThreads.nodes[]?
			| select(.isResolved == true)
			| . as $thread
			| select(
				([($thread.comments.nodes[1:] // [])[]
					| select(
						(.author.__typename == "User")
						and ((.author.login // "") | endswith("[bot]") | not)
						and (.author.login as $login | ($copilot | index($login) | not))
						and (
							((.commit.oid // "") == $head)
							or ($thread.isOutdated == true)
						)
					)
				] | length) == 0
			)
		] | length')"
	if [[ "$untreated" != "0" ]]; then
		note_ineligible "Pull request #${PR_NUMBER} has resolved review threads without a current-HEAD disposition reply."
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
	local checks_json count name state checks_rc
	checks_json="$(mktemp)"
	set +e
	python3 scripts/review/required_checks.py --repository "$REPOSITORY" --head "$1" >"$checks_json" 2>/dev/null
	checks_rc=$?
	set -e
	# Policy/API failures cannot certify the exact commit. Missing contexts
	# appear as PENDING receipts in a successful helper response.
	if [[ "$checks_rc" -ne 0 || ! -s "$checks_json" ]] || ! jq -e '.checks | type=="array"' "$checks_json" >/dev/null 2>&1; then
		note_ineligible "Could not read required status checks for PR #${PR_NUMBER} (token or API limitation)."
		rm -f "$checks_json"
		return 1
	fi
	count="$(jq '[.checks[] | select(.name != "Final review gate")] | length' "$checks_json")"
	if [[ "$count" == "0" ]]; then
		note_ineligible "Required checks snapshot has no external contexts for PR #${PR_NUMBER}."
		rm -f "$checks_json"
		return 1
	fi

	while IFS=$'\t' read -r name state; do
		name="${name//$'\r'/}"
		state="${state//$'\r'/}"
		if [[ "$name" == "Final review gate" ]]; then
			continue
		fi
		case "$state" in
		SUCCESS | NEUTRAL | SKIPPED) ;;
		PENDING | QUEUED | IN_PROGRESS)
			note_ineligible "Required check \`${name}\` is still \`${state}\` for the current HEAD."
			;;
		*)
			note_ineligible "Required check \`${name}\` is \`${state}\` (not passing)."
			;;
		esac
	done < <(jq -r '.checks[] | "\(.name)\t\(.state)"' "$checks_json")
	rm -f "$checks_json"

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
	if [[ "$head_repo" != "$REPOSITORY" ]]; then
		note_ineligible "Pull request #${PR_NUMBER} head \`${head_repo:-<missing>}\` is not this repository (\`${REPOSITORY}\`); only same-repo heads are eligible."
	fi
	if forbidden_author "$author_login"; then
		note_ineligible "Pull request #${PR_NUMBER} is authored by \`${author_login}\`; repository policy forbids Copilot self-approval on agent-authored PRs."
	fi
	if [[ "$review_decision" == "CHANGES_REQUESTED" ]]; then
		note_ineligible "Pull request #${PR_NUMBER} has an active \`CHANGES_REQUESTED\` review decision."
	fi
	if has_unresolved_threads "$pr_json" "$head_oid"; then
		last="${INELIGIBLE_REASONS[-1]-}"
		if [[ "$last" != *"inconclusive"* && "$last" != *"disposition"* ]]; then
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
	UNKNOWN | "")
		note_ineligible "Pull request #${PR_NUMBER} merge state is \`${merge_state:-<missing>}\`; retry after GitHub finishes computing mergeability."
		;;
	esac

	if ((${#INELIGIBLE_REASONS[@]} == 0)); then
		if ! required_checks_ok "$head_oid"; then
			:
		fi
	fi

	if ((${#INELIGIBLE_REASONS[@]} > 0)); then
		return 1
	fi

	ELIGIBLE_HEAD_OID="$head_oid"
	return 0
}

graphql_mutation_ok() {
	local response="$1"
	if [[ -z "$response" ]]; then
		echo "::error::Empty GraphQL response from GitHub API." >&2
		return 1
	fi
	if ! echo "$response" | jq -e '
		type == "object" and ((.errors // []) | length == 0)
		and (.data | type == "object")
		and (.data.requestReviews | type == "object")
		and (.data.requestReviews | has("clientMutationId"))
	' >/dev/null 2>&1; then
		echo "::error::GraphQL mutation response is invalid or has no successful requestReviews payload." >&2
		return 1
	fi
	return 0
}

reviewer_sets_unchanged() {
	local users_a="$1"
	local teams_a="$2"
	local users_b="$3"
	local teams_b="$4"
	[[ "$users_a" == "$users_b" && "$teams_a" == "$teams_b" ]]
}

fetch_preserved_reviewer_ids() {
	local user_ids='[]'
	local team_ids='[]'
	local cursor=""
	local has_next="true"

	while [[ "$has_next" == "true" ]]; do
		local snap
		local -a gql_args=(
			api graphql
			-f query='query($o:String!,$n:String!,$p:Int!,$after:String){
			repository(owner:$o,name:$n){
				pullRequest(number:$p){
					reviewRequests(first:100,after:$after){
						nodes{requestedReviewer{__typename ... on User{id login} ... on Team{id slug} ... on Bot{id login}}}
						pageInfo{hasNextPage endCursor}
					}
				}
			}
		}'
			-f o="$OWNER"
			-f n="$REPO"
			-F p="$PR_NUMBER"
		)
		# First page must omit after (null); empty string is an invalid cursor.
		if [[ -n "$cursor" ]]; then
			gql_args+=(-f after="$cursor")
		fi
		if ! snap="$(gh "${gql_args[@]}" 2>/dev/null)"; then
			echo "::error::Failed to list existing review requests for PR #${PR_NUMBER}." >&2
			return 1
		fi
		if echo "$snap" | jq -e '((.errors // []) | length) > 0' >/dev/null; then
			echo "::error::GraphQL reviewRequests query returned errors." >&2
			return 1
		fi
		if ! echo "$snap" | jq -e '.data.repository.pullRequest.reviewRequests.pageInfo.hasNextPage | type == "boolean"' >/dev/null; then
			echo "::error::reviewRequests pagination is missing or invalid." >&2
			return 1
		fi

		user_ids="$(jq -c --argjson users "$user_ids" \
			'($users + [.data.repository.pullRequest.reviewRequests.nodes[] | select(.requestedReviewer.__typename=="User") | .requestedReviewer.id]) | unique' \
			<<<"$snap")"
		team_ids="$(jq -c --argjson teams "$team_ids" \
			'($teams + [.data.repository.pullRequest.reviewRequests.nodes[] | select(.requestedReviewer.__typename=="Team") | .requestedReviewer.id]) | unique' \
			<<<"$snap")"

		has_next="$(echo "$snap" | jq -r '.data.repository.pullRequest.reviewRequests.pageInfo.hasNextPage')"
		cursor="$(echo "$snap" | jq -r '.data.repository.pullRequest.reviewRequests.pageInfo.endCursor // empty')"
		if [[ "$has_next" == "true" && -z "$cursor" ]]; then
			echo "::error::reviewRequests reported hasNextPage without endCursor." >&2
			return 1
		fi
	done

	printf '%s\n%s\n' "$user_ids" "$team_ids"
}

request_copilot_refresh() {
	local pr_node_id="$1"
	local head_oid_before="$2"
	local pr_json head_oid_after
	local max_reviews_per_head=1

	if ! pr_json="$(fetch_pr_json)"; then
		exit 0
	fi
	head_oid_after="$(echo "$pr_json" | jq -r '.data.repository.pullRequest.headRefOid')"
	if [[ "$head_oid_after" != "$head_oid_before" ]]; then
		note_ineligible "HEAD changed during eligibility (\`${head_oid_before:0:7}\` → \`${head_oid_after:0:7}\`); re-run after the branch is stable."
		write_summary "Final Copilot review not requested"
		exit 0
	fi

	# Idempotent / capped: do not clear+re-request when a Copilot review is
	# already in flight or completed for this HEAD, and never exceed three
	# Copilot reviews for the same commit.
	local pending_copilot head_review_count
	pending_copilot="$(echo "$pr_json" | jq -r --arg bot "$COPILOT_REVIEWER_BOT" '
		[.data.repository.pullRequest.reviewRequests.nodes[]?
		 | .requestedReviewer
		 | select((.login // "") == $bot or (.login // "") == "copilot-pull-request-reviewer" or (.login // "") == "Copilot")
		] | length')"
	if [[ "${pending_copilot:-0}" -gt 0 ]]; then
		note_ineligible "Copilot review already requested for PR #${PR_NUMBER}; skipping duplicate clear/re-request."
		write_summary "Final Copilot review not requested"
		exit 0
	fi

	head_review_count="$(
		gh api "repos/${REPOSITORY}/pulls/${PR_NUMBER}/reviews" --paginate \
			| jq -s --arg head "$head_oid_before" --arg bot "$COPILOT_REVIEWER_BOT" \
				'add // [] | [.[] | select((.user.login == $bot or .user.login == "Copilot" or .user.login == "copilot-pull-request-reviewer") and .commit_id == $head)] | length'
	)" || {
		echo "::error::Could not list existing Copilot reviews for PR #${PR_NUMBER}; refusing clear/re-request." >&2
		exit 1
	}
	if [[ -z "$head_review_count" || ! "$head_review_count" =~ ^[0-9]+$ ]]; then
		echo "::error::Could not count existing Copilot reviews for HEAD ${head_oid_before:0:7}." >&2
		exit 1
	fi
	if [[ "$head_review_count" -ge "$max_reviews_per_head" ]]; then
		note_ineligible "Copilot already reviewed HEAD \`${head_oid_before:0:7}\`; one accepted request per SHA."
		write_summary "Final Copilot review not requested"
		exit 0
	fi

	local bot_node user_ids team_ids clear_resp add_resp restore_resp
	if ! bot_node="$(gh api '/users/copilot-pull-request-reviewer%5Bbot%5D' --jq .node_id 2>/dev/null)"; then
		echo "::error::Could not resolve Copilot reviewer bot node ID." >&2
		exit 1
	fi
	if [[ -z "$bot_node" || "$bot_node" == "null" ]]; then
		echo "::error::Copilot reviewer bot node ID was empty." >&2
		exit 1
	fi

	restore_preserved_reviewers() {
		local why="$1"
		echo "::error::${why}" >&2
		if ! restore_resp="$(gh api graphql --input - <<EOF
{"query":"mutation(\$pr:ID!,\$users:[ID!]!,\$teams:[ID!]!){requestReviews(input:{pullRequestId:\$pr,botIds:[],userIds:\$users,teamIds:\$teams,union:false}){clientMutationId}}","variables":{"pr":"$RESTORE_PR_NODE","users":$RESTORE_USER_IDS,"teams":$RESTORE_TEAM_IDS}}
EOF
)"; then
			echo "::error::UNRECOVERABLE: failed to restore preserved human/team reviewers after clear; review requests may be empty." >&2
			return 1
		fi
		if ! graphql_mutation_ok "$restore_resp"; then
			echo "::error::UNRECOVERABLE: restore GraphQL mutation reported errors; review requests may be empty." >&2
			return 1
		fi
		REVIEWERS_CLEARED=0
		return 0
	}

	# Re-run the full eligibility predicate (state, draft, review decision,
	# threads, merge state, required checks) and re-capture the reviewer set
	# immediately before the destructive clear so a change during the run cannot
	# mutate review requests on a now-ineligible PR or drop a newly added reviewer.
	if ! pr_json="$(fetch_pr_json)"; then
		exit 0
	fi
	head_oid_after="$(echo "$pr_json" | jq -r '.data.repository.pullRequest.headRefOid')"
	if [[ "$head_oid_after" != "$head_oid_before" ]]; then
		note_ineligible "HEAD changed before clear/re-request (\`${head_oid_before:0:7}\`  \`${head_oid_after:0:7}\`); re-run after the branch is stable."
		write_summary "Final Copilot review not requested"
		exit 0
	fi
	if ! evaluate_eligibility "$pr_json"; then
		write_summary "Final Copilot review not requested"
		exit 0
	fi
	preserved_raw="$(fetch_preserved_reviewer_ids)" || {
		echo "::error::Failed to fetch preserved reviewer IDs before clear/re-request." >&2
		exit 1
	}
	user_ids="$(printf '%s\n' "$preserved_raw" | sed -n '1p')"
	team_ids="$(printf '%s\n' "$preserved_raw" | sed -n '2p')"
	if [[ -z "$user_ids" || -z "$team_ids" ]]; then
		echo "::error::Preserved reviewer ID payload was incomplete." >&2
		exit 1
	fi
	if ! pr_json="$(fetch_pr_json)"; then
		exit 0
	fi
	head_oid_after="$(echo "$pr_json" | jq -r '.data.repository.pullRequest.headRefOid')"
	if [[ "$head_oid_after" != "$head_oid_before" ]]; then
		note_ineligible "HEAD changed after listing reviewers (\`${head_oid_before:0:7}\` -> \`${head_oid_after:0:7}\`); re-run after the branch is stable."
		write_summary "Final Copilot review not requested"
		exit 0
	fi
	if ! evaluate_eligibility "$pr_json"; then
		write_summary "Final Copilot review not requested"
		exit 0
	fi
	preserved_raw_again="$(fetch_preserved_reviewer_ids)" || {
		echo "::error::Failed to re-read reviewer IDs immediately before clear." >&2
		exit 1
	}
	user_ids_again="$(printf '%s\n' "$preserved_raw_again" | sed -n '1p')"
	team_ids_again="$(printf '%s\n' "$preserved_raw_again" | sed -n '2p')"
	if ! reviewer_sets_unchanged "$user_ids" "$team_ids" "$user_ids_again" "$team_ids_again"; then
		note_ineligible "Human/team reviewer requests changed before clear; aborting so a newly added reviewer is not dropped."
		write_summary "Final Copilot review not requested"
		exit 0
	fi
	user_ids="$user_ids_again"
	team_ids="$team_ids_again"
	RESTORE_PR_NODE="$pr_node_id"
	RESTORE_USER_IDS="$user_ids"
	RESTORE_TEAM_IDS="$team_ids"
	REVIEWERS_CLEARED=0
	# A cancelled or terminated runner after the clear must not leave the PR
	# with no human/team review requests.
	trap 'if [[ "${REVIEWERS_CLEARED}" == "1" ]]; then restore_preserved_reviewers "Interrupted after clearing reviewers; restoring preserved human/team reviewers." || true; fi' EXIT
	trap 'exit 143' TERM INT
	# A transport failure cannot prove the server did not apply the clear.
	REVIEWERS_CLEARED=1
	if ! clear_resp="$(gh api graphql --input - <<EOF
{"query":"mutation(\$pr:ID!){requestReviews(input:{pullRequestId:\$pr,botIds:[],userIds:[],teamIds:[],union:false}){clientMutationId}}","variables":{"pr":"$pr_node_id"}}
EOF
)"; then
		echo "::error::Failed to clear existing review requests before re-requesting Copilot." >&2
		exit 1
	fi
	if ! graphql_mutation_ok "$clear_resp"; then
		exit 1
	fi
	REVIEWERS_CLEARED=1

	if ! add_resp="$(gh api graphql --input - <<EOF
{"query":"mutation(\$pr:ID!,\$bots:[ID!]!,\$users:[ID!]!,\$teams:[ID!]!){requestReviews(input:{pullRequestId:\$pr,botIds:\$bots,userIds:\$users,teamIds:\$teams,union:false}){clientMutationId}}","variables":{"pr":"$pr_node_id","bots":["$bot_node"],"users":$user_ids,"teams":$team_ids}}
EOF
)"; then
		restore_preserved_reviewers "Failed to request Copilot review after clearing reviewers; restoring preserved human/team reviewers." || echo "::error::Restoration failed; EXIT will retry. Maintainer recovery is required if retry fails." >&2
		exit 1
	fi
	if ! graphql_mutation_ok "$add_resp"; then
		restore_preserved_reviewers "Copilot re-request GraphQL mutation failed; restoring preserved human/team reviewers." || echo "::error::Restoration failed; EXIT will retry. Maintainer recovery is required if retry fails." >&2
		exit 1
	fi
	REVIEWERS_CLEARED=0

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
    if ! command -v python3 >/dev/null || [[ ! -f .github/scripts/classify-copilot-review.py || ! -f scripts/review/required_checks.py ]]; then
        echo '::error::Trusted Python helpers are unavailable; refusing a final review request.' >&2
        return 1
    fi
	require_int_pr_number

	local pr_json pr_node head_oid
	if ! pr_json="$(fetch_pr_json)"; then
		exit 0
	fi
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

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	main "$@"
fi
