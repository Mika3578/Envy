#!/usr/bin/env bash
# Review Gate evaluator: staged review/correction/final-approval policy.
#
# Read-only. Never approves, never merges, never pushes. Emits one verdict:
#   PASS (READY_TO_MERGE) or FAIL (reason + HUMAN_REQUIRED when applicable).
#
# Binding invariant: every review signal is valid only for the exact HEAD SHA
# under evaluation. Stale reviews (commit_id != HEAD) are ignored. Cursor
# (cursor[bot]) APPROVED is ALWAYS ignored and can never authorize merge.
# Quota/rate-limit/off-topic bot messages are classified as noise, never as
# reviews or findings, and never posted back to the PR discussion.
#
# Usage (live):
#   PR_NUMBER=123 HEAD_SHA=abc... GITHUB_REPOSITORY=owner/repo bash review-gate.sh
# Usage (fixture, used by the selftest):
#   REVIEW_GATE_FIXTURES=dir/with/{reviews.json,threads.json} PR_NUMBER=.. HEAD_SHA=.. bash review-gate.sh
#
# Env knobs:
#   DOCS_ONLY=true        Low-risk path: Stage A + CI green suffices, no Copilot APPROVED needed.
#   MAX_ITERATIONS=3      Global correction budget per PR (generation supplied by caller).
#   GENERATION=1          Current correction generation (1 = first HEAD).
#   REQUIRE_COPILOT=true  Require Copilot APPROVED on HEAD (default true; false only for docs-only).
set -euo pipefail

PR_NUMBER="${PR_NUMBER:?PR_NUMBER is required}"
HEAD_SHA="${HEAD_SHA:?HEAD_SHA is required}"
REPO="${GITHUB_REPOSITORY:-Mika3578/Envy}"
MAX_ITERATIONS="${MAX_ITERATIONS:-3}"
GENERATION="${GENERATION:-1}"
DOCS_ONLY="${DOCS_ONLY:-false}"
REQUIRE_COPILOT="${REQUIRE_COPILOT:-true}"
FIXTURES="${REVIEW_GATE_FIXTURES:-}"

if [[ "$DOCS_ONLY" == "true" ]]; then
	REQUIRE_COPILOT="false"
fi

fail() {
	echo "REVIEW_GATE_STATE=$1"
	echo "REVIEW_GATE_REASON=$2"
	if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
		{
			echo "## Review Gate: $1"
			echo
			echo "PR #$PR_NUMBER @ \`$HEAD_SHA\` (generation $GENERATION/$MAX_ITERATIONS)"
			echo
			echo "Reason: $2"
		} >>"$GITHUB_STEP_SUMMARY"
	fi
	exit 1
}

pass() {
	echo "REVIEW_GATE_STATE=READY_TO_MERGE"
	echo "REVIEW_GATE_REASON=$1"
	if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
		{
			echo "## Review Gate: READY_TO_MERGE"
			echo
			echo "PR #$PR_NUMBER @ \`$HEAD_SHA\` (generation $GENERATION/$MAX_ITERATIONS)"
			echo
			echo "$1"
		} >>"$GITHUB_STEP_SUMMARY"
	fi
	exit 0
}

# --- Load review + thread evidence (live API or fixtures) --------------------
if [[ -n "$FIXTURES" ]]; then
	REVIEWS_JSON="$(cat "$FIXTURES/reviews.json")"
	THREADS_JSON="$(cat "$FIXTURES/threads.json")"
else
	REVIEWS_JSON="$(gh api --paginate "repos/${REPO}/pulls/${PR_NUMBER}/reviews")"
	THREADS_JSON="$(gh api graphql --paginate -f query='
		query($o:String!,$n:String!,$p:Int!,$c:String) {
			repository(owner:$o,name:$n){ pullRequest(number:$p){
				reviewThreads(first:100,after:$c){ nodes{ isResolved comments(first:1){
					nodes{ author{login} body } } } pageInfo{ hasNextPage endCursor } } } } }' \
		-f o="${REPO%%/*}" -f n="${REPO##*/}" -F p="$PR_NUMBER")"
fi

# Malformed payloads fail closed.
if ! printf '%s' "$REVIEWS_JSON" | jq -e 'if type == "array" then . else error("not-array") end' >/dev/null 2>&1; then
	fail "HUMAN_REQUIRED" "reviews payload is not a valid JSON array (malformed or transient API error)"
fi
if ! printf '%s' "$THREADS_JSON" | jq -e '.data.repository.pullRequest.reviewThreads.nodes | type == "array"' >/dev/null 2>&1; then
	fail "HUMAN_REQUIRED" "review threads payload is malformed or missing pagination data"
fi

# --- Quota/rate-limit spam patterns (noise, never a review signal) -----------
is_noise_body() {
	local body="$1"
	local low
	low="$(printf '%s' "$body" | tr '[:upper:]' '[:lower:]')"
	case "$low" in
		*"review budget"*|*"rate limit"*|*"rate-limit"*|*"upgrade to get a review"*|*"no credit"*|*"quota"*)
			return 0
			;;
	esac
	return 1
}

# --- Iteration budget ---------------------------------------------------------
if [ "$GENERATION" -gt "$MAX_ITERATIONS" ]; then
	fail "HUMAN_REQUIRED" "correction budget exhausted (generation $GENERATION > max $MAX_ITERATIONS); recurring or unbounded findings need a human"
fi

# --- Normalize reviews bound to the exact HEAD --------------------------------
COPILOT_STATE="absent"     # absent|pending|approved|commented-findings|closer-look|changes-requested
CODERABBIT_BLOCKING="false"
UNRESOLVED_BLOCKING="0"

# Copilot: latest review on HEAD wins; stale reviews ignored.
COPILOT_STATE="$(printf '%s' "$REVIEWS_JSON" | jq -r --arg head "$HEAD_SHA" '
	[ .[] | select(.user.login == "copilot-pull-request-reviewer[bot]" and .commit_id == $head) ]
	| sort_by(.submitted_at // .id) | last | . as $r
	| if $r == null then "absent"
	  elif $r.state == "APPROVED" then "approved"
	  elif $r.state == "CHANGES_REQUESTED" then "changes-requested"
	  elif (($r.body // "") | test("(?i)needs a closer look")) then "closer-look"
	  elif (($r.body // "") | test("(?i)finding")) then "commented-findings"
	  else "pending" end')"

# CodeRabbit: CHANGES_REQUESTED on HEAD blocks; COMMENTED with unresolved
# threads blocks (checked below); APPROVED or clean COMMENTED is fine.
CODERABBIT_BLOCKING="$(printf '%s' "$REVIEWS_JSON" | jq -r --arg head "$HEAD_SHA" '
	[ .[] | select(.user.login == "coderabbitai[bot]" and .commit_id == $head and .state == "CHANGES_REQUESTED") ]
	| if length > 0 then "true" else "false" end')"

# cursor[bot] APPROVED is deliberately never read: no binding, no authority.
# (Bugbot cleanliness is derived from unresolved threads below, not review state.)

# --- Unresolved threads (bot-authored actionable findings block) --------------
UNRESOLVED_BLOCKING="$(printf '%s' "$THREADS_JSON" | jq -r '
	[.data.repository.pullRequest.reviewThreads.nodes[]?
		| select(.isResolved != true)
		| .comments.nodes[0] // empty
		| select(.author.login != null)
		| .body // "" as $b
		| select(($b | ascii_downcase | test("review budget|rate limit|rate-limit|upgrade to get a review|no credit|quota")) | not)
	] | length')"

if [[ "$UNRESOLVED_BLOCKING" == "null" || -z "$UNRESOLVED_BLOCKING" ]]; then
	fail "HUMAN_REQUIRED" "review threads evaluation failed (fail closed)"
fi

# --- Policy evaluation (fail closed) ------------------------------------------
if [[ "$CODERABBIT_BLOCKING" == "true" ]]; then
	fail "FIX_REQUIRED" "CodeRabbit CHANGES_REQUESTED on current HEAD"
fi

if ((UNRESOLVED_BLOCKING > 0)); then
	fail "FIX_REQUIRED" "$UNRESOLVED_BLOCKING unresolved actionable review thread(s) on current HEAD"
fi

if [[ "$REQUIRE_COPILOT" == "true" ]]; then
	case "$COPILOT_STATE" in
		approved)
			pass "Copilot APPROVED recorded for exact HEAD $HEAD_SHA; Stage A clean; no unresolved threads."
			;;
		absent)
			fail "COPILOT_PENDING" "no Copilot review for current HEAD (never treat absence as success)"
			;;
		pending)
			fail "COPILOT_PENDING" "Copilot review for current HEAD not yet completed"
			;;
		commented-findings)
			fail "COPILOT_FIX_REQUIRED" "Copilot COMMENTED with findings on current HEAD; correct, push, re-run Stage A, request a new final review"
			;;
		closer-look)
			fail "HUMAN_REQUIRED" "Copilot 'Needs a closer look' on current HEAD: final human review required (never reinterpret as approval)"
			;;
		changes-requested)
			fail "COPILOT_FIX_REQUIRED" "Copilot CHANGES_REQUESTED on current HEAD"
			;;
		*)
			fail "HUMAN_REQUIRED" "unknown Copilot state '$COPILOT_STATE' (fail closed)"
			;;
	esac
else
	pass "Docs-only/low-risk path: Stage A clean for HEAD $HEAD_SHA; no unresolved threads; Copilot final not required."
fi
