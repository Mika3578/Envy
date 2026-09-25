#!/usr/bin/env bash
# Deterministic selftest for review-gate.sh (fixture mode, no live API).
# Pattern follows pr-gate-conclusions.selftest.sh: expect helper + fail accumulator.
set -euo pipefail
cd "$(dirname "$0")"

fail=0
HEAD_A="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
HEAD_B="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

empty_threads='{"data":{"repository":{"pullRequest":{"reviewThreads":{"nodes":[]}}}}}'

# run_case <name> <want_state> <reviews.json> <threads.json> [extra env k=v ...]
run_case() {
	local name="$1" want="$2" reviews="$3" threads="$4"
	shift 4
	local dir
	dir="$(mktemp -d)"
	printf '%s' "$reviews" >"$dir/reviews.json"
	printf '%s' "$threads" >"$dir/threads.json"
	local got rc
	set +e
	# NOTE: assignments from "$@" must go through `env`: bash does not
	# recognize VAR=value words produced by "$@" expansion as env prefixes.
	got="$(env PR_NUMBER=1 HEAD_SHA="$HEAD_A" REVIEW_GATE_FIXTURES="$dir" "$@" bash ./review-gate.sh 2>/dev/null | grep -m1 '^REVIEW_GATE_STATE=' | cut -d= -f2)"
	rc=$?
	set -e
	rm -rf "$dir"
	if [[ "$got" != "$want" ]]; then
		echo "FAIL $name: got='${got:-<empty>}' want='$want'"
		fail=1
	else
		echo "OK   $name ($got)"
	fi
}

R() { printf '%s' "$1"; }

# 1. no reviews
run_case "01-no-reviews" "COPILOT_PENDING" '[]' "$empty_threads"
# 2. Stage A pending (unresolved actionable thread, no Copilot yet)
run_case "02-stagea-pending" "FIX_REQUIRED" '[]' \
	'{"data":{"repository":{"pullRequest":{"reviewThreads":{"nodes":[{"isResolved":false,"comments":{"nodes":[{"author":{"login":"coderabbitai[bot]"},"body":"Potential null deref in Envy/Foo.cpp"}]}}]}}}}}'
# 3. Stage A clean, Copilot not yet run
run_case "03-stagea-clean" "COPILOT_PENDING" '[]' "$empty_threads"
# 4. Stage A finding (CodeRabbit CHANGES_REQUESTED on HEAD)
run_case "04-stagea-finding" "FIX_REQUIRED" \
	"$(R "[{\"user\":{\"login\":\"coderabbitai[bot]\"},\"state\":\"CHANGES_REQUESTED\",\"commit_id\":\"$HEAD_A\",\"submitted_at\":\"2026-09-25T10:00:00Z\",\"id\":1,\"body\":\"Blocking issue\"}]")" \
	"$empty_threads"
# 5. correction creates new HEAD: old reviews stale, Copilot APPROVED on new HEAD
run_case "05-new-head-approved" "READY_TO_MERGE" \
	"$(R "[{\"user\":{\"login\":\"coderabbitai[bot]\"},\"state\":\"CHANGES_REQUESTED\",\"commit_id\":\"old\",\"submitted_at\":\"t\",\"id\":1,\"body\":\"x\"},{\"user\":{\"login\":\"copilot-pull-request-reviewer[bot]\"},\"state\":\"APPROVED\",\"commit_id\":\"$HEAD_A\",\"submitted_at\":\"t\",\"id\":2,\"body\":\"Looks good\"}]")" \
	"$empty_threads"
# 6. old Stage A result ignored (approval only on stale HEAD)
run_case "06-stale-result-ignored" "COPILOT_PENDING" \
	"$(R "[{\"user\":{\"login\":\"copilot-pull-request-reviewer[bot]\"},\"state\":\"APPROVED\",\"commit_id\":\"old\",\"submitted_at\":\"t\",\"id\":1,\"body\":\"Looks good\"}]")" \
	"$empty_threads"
# 7. all Stage A clean then final candidate awaits Copilot
run_case "07-final-candidate-waits" "COPILOT_PENDING" \
	"$(R "[{\"user\":{\"login\":\"coderabbitai[bot]\"},\"state\":\"COMMENTED\",\"commit_id\":\"$HEAD_A\",\"submitted_at\":\"t\",\"id\":1,\"body\":\"All good\"}]")" \
	"$empty_threads"
# 8. Copilot absent
run_case "08-copilot-absent" "COPILOT_PENDING" \
	"$(R "[{\"user\":{\"login\":\"cursor[bot]\"},\"state\":\"COMMENTED\",\"commit_id\":\"$HEAD_A\",\"submitted_at\":\"t\",\"id\":1,\"body\":\"Bugbot clean\"}]")" \
	"$empty_threads"
# 9. Copilot pending (in-progress COMMENTED, no findings keywords)
run_case "09-copilot-pending" "COPILOT_PENDING" \
	"$(R "[{\"user\":{\"login\":\"copilot-pull-request-reviewer[bot]\"},\"state\":\"COMMENTED\",\"commit_id\":\"$HEAD_A\",\"submitted_at\":\"t\",\"id\":1,\"body\":\"Review in progress\"}]")" \
	"$empty_threads"
# 10. Cursor APPROVED while Copilot pending
run_case "10-cursor-approved-copilot-pending" "COPILOT_PENDING" \
	"$(R "[{\"user\":{\"login\":\"cursor[bot]\"},\"state\":\"APPROVED\",\"commit_id\":\"$HEAD_A\",\"submitted_at\":\"t\",\"id\":1,\"body\":\"Approved: Bugbot clean\"},{\"user\":{\"login\":\"copilot-pull-request-reviewer[bot]\"},\"state\":\"COMMENTED\",\"commit_id\":\"$HEAD_A\",\"submitted_at\":\"t\",\"id\":2,\"body\":\"Review in progress\"}]")" \
	"$empty_threads"
# 11. Cursor APPROVED while Copilot absent
run_case "11-cursor-approved-copilot-absent" "COPILOT_PENDING" \
	"$(R "[{\"user\":{\"login\":\"cursor[bot]\"},\"state\":\"APPROVED\",\"commit_id\":\"$HEAD_A\",\"submitted_at\":\"t\",\"id\":1,\"body\":\"Approved: Bugbot clean\"}]")" \
	"$empty_threads"
# 12. Copilot COMMENTED with findings
run_case "12-copilot-findings" "COPILOT_FIX_REQUIRED" \
	"$(R "[{\"user\":{\"login\":\"copilot-pull-request-reviewer[bot]\"},\"state\":\"COMMENTED\",\"commit_id\":\"$HEAD_A\",\"submitted_at\":\"t\",\"id\":1,\"body\":\"## Copilot review overview Findings: buffer may overflow\"}]")" \
	"$empty_threads"
# 13. Copilot Needs a closer look
run_case "13-closer-look" "HUMAN_REQUIRED" \
	"$(R "[{\"user\":{\"login\":\"copilot-pull-request-reviewer[bot]\"},\"state\":\"COMMENTED\",\"commit_id\":\"$HEAD_A\",\"submitted_at\":\"t\",\"id\":1,\"body\":\"Needs a closer look. Findings: None. Final human review required.\"}]")" \
	"$empty_threads"
# 14. Copilot CHANGES_REQUESTED
run_case "14-copilot-changes-requested" "COPILOT_FIX_REQUIRED" \
	"$(R "[{\"user\":{\"login\":\"copilot-pull-request-reviewer[bot]\"},\"state\":\"CHANGES_REQUESTED\",\"commit_id\":\"$HEAD_A\",\"submitted_at\":\"t\",\"id\":1,\"body\":\"Please fix\"}]")" \
	"$empty_threads"
# 15. Copilot APPROVED current HEAD
run_case "15-copilot-approved-head" "READY_TO_MERGE" \
	"$(R "[{\"user\":{\"login\":\"copilot-pull-request-reviewer[bot]\"},\"state\":\"APPROVED\",\"commit_id\":\"$HEAD_A\",\"submitted_at\":\"t\",\"id\":1,\"body\":\"Ready to approve\"}]")" \
	"$empty_threads"
# 16. Copilot APPROVED stale HEAD
run_case "16-copilot-approved-stale" "COPILOT_PENDING" \
	"$(R "[{\"user\":{\"login\":\"copilot-pull-request-reviewer[bot]\"},\"state\":\"APPROVED\",\"commit_id\":\"$HEAD_B\",\"submitted_at\":\"t\",\"id\":1,\"body\":\"Ready\"}]")" \
	"$empty_threads"
# 17. new commit after Copilot approval (same as stale, child commit evaluated)
run_case "17-commit-after-approval" "COPILOT_PENDING" \
	"$(R "[{\"user\":{\"login\":\"copilot-pull-request-reviewer[bot]\"},\"state\":\"APPROVED\",\"commit_id\":\"parent-sha\",\"submitted_at\":\"t\",\"id\":1,\"body\":\"Ready\"},{\"user\":{\"login\":\"cursor[bot]\"},\"state\":\"APPROVED\",\"commit_id\":\"$HEAD_A\",\"submitted_at\":\"t\",\"id\":2,\"body\":\"Approved\"}]")" \
	"$empty_threads"
# 18. unresolved review thread blocks
run_case "18-unresolved-thread" "FIX_REQUIRED" \
	"$(R "[{\"user\":{\"login\":\"copilot-pull-request-reviewer[bot]\"},\"state\":\"APPROVED\",\"commit_id\":\"$HEAD_A\",\"submitted_at\":\"t\",\"id\":1,\"body\":\"Ready\"}]")" \
	'{"data":{"repository":{"pullRequest":{"reviewThreads":{"nodes":[{"isResolved":false,"comments":{"nodes":[{"author":{"login":"coderabbitai[bot]"},"body":"Fix this leak"}]}}]}}}}}'
# 19. duplicate reviewer events are harmless (dup Cursor APPROVED + Copilot APPROVED)
run_case "19-duplicate-events" "READY_TO_MERGE" \
	"$(R "[{\"user\":{\"login\":\"cursor[bot]\"},\"state\":\"APPROVED\",\"commit_id\":\"$HEAD_A\",\"submitted_at\":\"t\",\"id\":1,\"body\":\"Approved\"},{\"user\":{\"login\":\"cursor[bot]\"},\"state\":\"APPROVED\",\"commit_id\":\"$HEAD_A\",\"submitted_at\":\"t\",\"id\":2,\"body\":\"Approved\"},{\"user\":{\"login\":\"copilot-pull-request-reviewer[bot]\"},\"state\":\"APPROVED\",\"commit_id\":\"$HEAD_A\",\"submitted_at\":\"t\",\"id\":3,\"body\":\"Ready\"}]")" \
	"$empty_threads"
# 20. duplicate finding (two identical unresolved threads) still blocks once
run_case "20-duplicate-finding" "FIX_REQUIRED" '[]' \
	'{"data":{"repository":{"pullRequest":{"reviewThreads":{"nodes":[{"isResolved":false,"comments":{"nodes":[{"author":{"login":"coderabbitai[bot]"},"body":"Same nit"}]}},{"isResolved":false,"comments":{"nodes":[{"author":{"login":"coderabbitai[bot]"},"body":"Same nit"}]}}]}}}}}'
# 21. pagination metadata present does not break evaluation
run_case "21-pagination" "COPILOT_PENDING" '[]' \
	'{"data":{"repository":{"pullRequest":{"reviewThreads":{"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}}}'
# 22. malformed API payload fails closed
run_case "22-malformed-payload" "HUMAN_REQUIRED" 'not-json{{{' "$empty_threads"
# 23. transient API error object (not an array) fails closed
run_case "23-transient-error" "HUMAN_REQUIRED" '{"message":"API rate limit exceeded"}' "$empty_threads"
# 24. cancelled/superseded generation over budget
run_case "24-generation-over-budget" "HUMAN_REQUIRED" '[]' "$empty_threads" GENERATION=4 MAX_ITERATIONS=3
# 25. max iteration reached exactly at boundary still evaluates
run_case "25-generation-at-boundary" "COPILOT_PENDING" '[]' "$empty_threads" GENERATION=3 MAX_ITERATIONS=3
# 26. oscillating finding across generations ends at HUMAN_REQUIRED via budget
run_case "26-oscillation-budget" "HUMAN_REQUIRED" '[]' \
	'{"data":{"repository":{"pullRequest":{"reviewThreads":{"nodes":[{"isResolved":false,"comments":{"nodes":[{"author":{"login":"coderabbitai[bot]"},"body":"Restore A"}]}}]}}}}} GENERATION=5 MAX_ITERATIONS=3'
# 27. PR #298 regression: Cursor APPROVED + Copilot closer-look + Sourcery quota spam
THREADS27='{"data":{"repository":{"pullRequest":{"reviewThreads":{"nodes":[{"isResolved":false,"comments":{"nodes":[{"author":{"login":"sourcery-ai[bot]"},"body":"Sorry, you have used your review budget"}]}}]}}}}}'
run_case "27-pr298-regression" "HUMAN_REQUIRED" \
	"$(R "[{\"user\":{\"login\":\"sourcery-ai[bot]\"},\"state\":\"COMMENTED\",\"commit_id\":\"$HEAD_A\",\"submitted_at\":\"2026-09-25T11:51:38Z\",\"id\":1,\"body\":\"you have used your review budget\"},{\"user\":{\"login\":\"cursor[bot]\"},\"state\":\"APPROVED\",\"commit_id\":\"$HEAD_A\",\"submitted_at\":\"2026-09-25T11:53:31Z\",\"id\":2,\"body\":\"Approved: Bugbot clean\"},{\"user\":{\"login\":\"copilot-pull-request-reviewer[bot]\"},\"state\":\"COMMENTED\",\"commit_id\":\"$HEAD_A\",\"submitted_at\":\"2026-09-25T11:54:16Z\",\"id\":3,\"body\":\"Needs a closer look. Findings: None. Final human review required.\"}]")" \
	"$THREADS27"
# 28. fully clean happy path
run_case "28-happy-path" "READY_TO_MERGE" \
	"$(R "[{\"user\":{\"login\":\"coderabbitai[bot]\"},\"state\":\"COMMENTED\",\"commit_id\":\"$HEAD_A\",\"submitted_at\":\"t\",\"id\":1,\"body\":\"Clean\"},{\"user\":{\"login\":\"copilot-pull-request-reviewer[bot]\"},\"state\":\"APPROVED\",\"commit_id\":\"$HEAD_A\",\"submitted_at\":\"t\",\"id\":2,\"body\":\"Ready to approve\"}]")" \
	"$empty_threads"

if ((fail != 0)); then
	echo "review-gate selftest: FAILURES present"
	exit 1
fi
echo "review-gate selftest: all cases pass"
