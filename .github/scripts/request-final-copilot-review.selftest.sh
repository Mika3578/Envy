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

# A failed lookup captured by command substitution must propagate failure.
gh() { return 1; }
if payload=$(fetch_pr_json); then
 echo 'FAIL failed lookup accepted' >&2
 exit 1
fi
[[ -z "$payload" ]]
grep -q 'Final Copilot review not requested' "$GITHUB_STEP_SUMMARY"
echo 'Requester mutation and lookup regression tests passed'
