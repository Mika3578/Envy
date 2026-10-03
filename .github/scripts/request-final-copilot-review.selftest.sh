#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
export REPOSITORY=Mika3578/Envy PR_NUMBER=397
export GITHUB_STEP_SUMMARY
GITHUB_STEP_SUMMARY=$(mktemp)
trap 'rm -f "$GITHUB_STEP_SUMMARY"' EXIT
source .github/scripts/request-final-copilot-review.sh

for response in '' 'invalid json' '{}' '{"data":null}' \
 '{"data":{"requestReviews":{}}}' \
 '{"errors":[{"message":"failed"}],"data":{"requestReviews":{"clientMutationId":null}}}'; do
 if graphql_mutation_ok "$response" 2>/dev/null; then
  echo 'FAIL malformed mutation response accepted' >&2
  exit 1
 fi
done
graphql_mutation_ok '{"data":{"requestReviews":{"clientMutationId":null}}}'

if ! reviewer_sets_unchanged '["U1"]' '["T1"]' '["U1"]' '["T1"]'; then
 echo 'FAIL unchanged reviewer sets rejected' >&2
 exit 1
fi
if reviewer_sets_unchanged '["U1"]' '[]' '["U1","U2"]' '[]'; then
 echo 'FAIL reviewer-request race accepted' >&2
 exit 1
fi
if grep -q 'local max_reviews_per_head=2' .github/scripts/request-final-copilot-review.sh; then
 echo 'FAIL same-SHA Copilot retry still allowed' >&2
 exit 1
fi
grep -q 'local max_reviews_per_head=1' .github/scripts/request-final-copilot-review.sh
grep -q 'reviewer_sets_unchanged' .github/scripts/request-final-copilot-review.sh

# A failed lookup captured by command substitution must propagate failure.
gh() { return 1; }
if payload=$(fetch_pr_json); then
 echo 'FAIL failed lookup accepted' >&2
 exit 1
fi
[[ -z "$payload" ]]
grep -q 'Final Copilot review not requested' "$GITHUB_STEP_SUMMARY"
echo 'Requester mutation and lookup regression tests passed'
