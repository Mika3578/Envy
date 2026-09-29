#!/usr/bin/env bash
# Acquire a PR review snapshot for evaluate-pr-review-gate.py.
# Read-only. Writes snapshot JSON to stdout. Never mutates the PR.
set -euo pipefail

OWNER="${REPOSITORY%%/*}"
REPO="${REPOSITORY#*/}"
PR_NUMBER="${PR_NUMBER:?PR_NUMBER is required}"
COPILOT_REVIEWER_BOT='copilot-pull-request-reviewer[bot]'
REQUEST_MARKER='<!-- envy-final-copilot-request:v1 -->'
OUTCOME_MARKER='<!-- envy-copilot-review-outcome:v1 -->'

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

cat >"$WORKDIR/required_contexts.json" <<'EOF'
[
  "Build x64 Release",
  "Build Win32 Release",
  "Lint build files",
  "Vcpkg manifest sanity",
  "Format Check",
  "secret-scan",
  "Analyze (c-cpp)",
  "SonarCloud Code Analysis"
]
EOF

gh api graphql -f query='query($o:String!,$n:String!,$p:Int!){
  repository(owner:$o,name:$n){
    pullRequest(number:$p){
      number
      headRefOid
      changedFiles
      isDraft
      reviewRequests(first:20){
        nodes{requestedReviewer{__typename ... on Bot{login} ... on User{login}}}
      }
      reviews(last:100){
        nodes{
          databaseId
          state
          commit{oid}
          author{login}
          submittedAt
          body
        }
      }
      reviewThreads(first:100){
        nodes{
          isResolved
          comments(first:20){
            nodes{author{login} body}
          }
        }
        pageInfo{hasNextPage}
      }
    }
  }
}' -f o="$OWNER" -f n="$REPO" -F p="$PR_NUMBER" >"$WORKDIR/pr.json"

head_sha="$(jq -r '.data.repository.pullRequest.headRefOid' "$WORKDIR/pr.json")"
changed_files="$(jq -r '.data.repository.pullRequest.changedFiles' "$WORKDIR/pr.json")"
printf '%s' "$head_sha" >"$WORKDIR/head_sha.txt"
printf '%s' "$changed_files" >"$WORKDIR/changed_files.txt"

gh pr checks "$PR_NUMBER" --repo "$REPOSITORY" --json name,state >"$WORKDIR/checks.json" 2>/dev/null || echo '[]' >"$WORKDIR/checks.json"

gh api "repos/${OWNER}/${REPO}/issues/${PR_NUMBER}/comments" --paginate >"$WORKDIR/comments.json" 2>/dev/null || echo '[]' >"$WORKDIR/comments.json"

jq --arg marker "$OUTCOME_MARKER" --arg head "$head_sha" '
  [.[]
    | select(.user.login == "github-actions[bot]")
    | select(.body | contains($marker))
    | .body
    | capture("(?s)<!-- envy-copilot-review-outcome:v1 -->[\\s\\S]*?```json\\n(?<json>[\\s\\S]*?)\\n```")?
    | .json
    | fromjson?
    | select(. != null)
    | select(.head_sha == $head)
  ]
  | sort_by(.submitted_at // "")
  | reverse
  | .[0] // {}
' "$WORKDIR/comments.json" >"$WORKDIR/outcome.json"

jq --arg marker "$REQUEST_MARKER" --arg head "$head_sha" '
  [.[]
    | select(.user.login == "github-actions[bot]")
    | select(.body | contains($marker))
    | select(.body | contains($head))
  ] | length > 0
' "$WORKDIR/comments.json" >"$WORKDIR/request_marker.json"

jq '
  [.data.repository.pullRequest.reviewRequests.nodes[]?
    | .requestedReviewer
    | select((.login // "") | . == "copilot-pull-request-reviewer[bot]" or . == "copilot-pull-request-reviewer" or . == "Copilot")
  ] | length > 0
' "$WORKDIR/pr.json" >"$WORKDIR/copilot_requested.json"

jq --arg marker "$REQUEST_MARKER" '
  [.[]
    | select(.user.login == "github-actions[bot]")
    | select(.body | contains($marker))
    | (.body | capture("HEAD `(?<sha>[0-9a-f]{7,40})`")? | .sha // empty)
  ]
  | map(select(length > 0))
  | unique
  | length
' "$WORKDIR/comments.json" >"$WORKDIR/generation_count.json"

jq '
  [.data.repository.pullRequest.reviews.nodes[]? | {
    id: (.databaseId // 0),
    state,
    commit_id: (.commit.oid // ""),
    submitted_at: (.submittedAt // null),
    body: (.body // ""),
    user: {login: (.author.login // "")}
  }]
' "$WORKDIR/pr.json" >"$WORKDIR/reviews.json"

jq '
  [.data.repository.pullRequest.reviewThreads.nodes[]? | {
    isResolved,
    comments: [
      .comments.nodes[]? | {
        user: {login: (.author.login // "")},
        body: (.body // "")
      }
    ]
  }]
' "$WORKDIR/pr.json" >"$WORKDIR/threads.json"

jq -n \
	--rawfile head_sha "$WORKDIR/head_sha.txt" \
	--rawfile changed_files "$WORKDIR/changed_files.txt" \
	--slurpfile reviews "$WORKDIR/reviews.json" \
	--slurpfile threads "$WORKDIR/threads.json" \
	--slurpfile checks "$WORKDIR/checks.json" \
	--slurpfile required_contexts "$WORKDIR/required_contexts.json" \
	--slurpfile copilot_outcome "$WORKDIR/outcome.json" \
	--slurpfile copilot_review_requested "$WORKDIR/copilot_requested.json" \
	--slurpfile request_marker_for_head "$WORKDIR/request_marker.json" \
	--slurpfile copilot_generation_count "$WORKDIR/generation_count.json" \
	'{
		head_sha: $head_sha,
		changed_files: ($changed_files | tonumber),
		reviews: $reviews[0],
		threads: $threads[0],
		checks: $checks[0],
		required_contexts: $required_contexts[0],
		copilot_outcome: $copilot_outcome[0],
		copilot_review_requested: $copilot_review_requested[0],
		request_marker_for_head: $request_marker_for_head[0],
		copilot_generation_count: $copilot_generation_count[0],
		head_stable: true,
		diff_too_large: false
	}'
