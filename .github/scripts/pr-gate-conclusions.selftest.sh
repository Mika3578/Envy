#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=pr-gate-conclusions.sh
source ./pr-gate-conclusions.sh
fail=0

expect() {
	local name="$1"
	local fn="$2"
	local arg="$3"
	local want_rc="$4"
	set +e
	"$fn" "$arg"
	local got=$?
	set -e
	if [[ "$got" -ne "$want_rc" ]]; then
		echo "FAIL $name: $fn($arg) rc=$got want=$want_rc"
		fail=1
	else
		echo "OK   $name"
	fi
}

expect_out() {
	local name="$1"
	local want="$2"
	shift 2
	local got
	got="$("$@")"
	if [[ "$got" != "$want" ]]; then
		echo "FAIL $name: got='$got' want='$want'"
		fail=1
	else
		echo "OK   $name"
	fi
}

expect bad-failure is_bad_conclusion failure 0
expect bad-cancelled is_bad_conclusion cancelled 0
expect bad-timed-out is_bad_conclusion timed_out 0
expect bad-action-required is_bad_conclusion action_required 0
expect bad-startup-failure is_bad_conclusion startup_failure 0
expect bad-stale is_bad_conclusion stale 0
expect bad-unknown is_bad_conclusion other 1
expect bad-empty is_bad_conclusion "" 1
expect bad-success is_bad_conclusion success 1
expect bad-neutral is_bad_conclusion neutral 1
expect bad-skipped is_bad_conclusion skipped 1

expect failfast-failure is_fail_fast_conclusion failure 0
expect failfast-timed-out is_fail_fast_conclusion timed_out 0
expect failfast-action-required is_fail_fast_conclusion action_required 0
expect failfast-startup-failure is_fail_fast_conclusion startup_failure 0
expect failfast-stale is_fail_fast_conclusion stale 0
expect failfast-cancelled-not is_fail_fast_conclusion cancelled 1
expect failfast-success-not is_fail_fast_conclusion success 1

expect supersede-cancelled is_supersedable_conclusion cancelled 0
expect supersede-failure-not is_supersedable_conclusion failure 1
expect supersede-success-not is_supersedable_conclusion success 1

expect must-success is_ok_must_pass success 0
expect must-skip is_ok_must_pass skipped 1
expect must-neutral is_ok_must_pass neutral 1
expect must-unknown is_ok_must_pass other 1
expect must-empty is_ok_must_pass "" 1

expect skip-success is_ok_may_skip success 0
expect skip-skipped is_ok_may_skip skipped 0
expect skip-neutral is_ok_may_skip neutral 1
expect skip-unknown is_ok_may_skip other 1
expect skip-empty is_ok_may_skip "" 1

# 1–7: classify_gate_outcome
expect_out classify-success ok classify_gate_outcome completed success false
expect_out classify-failure failed classify_gate_outcome completed failure false
expect_out classify-timed-out failed classify_gate_outcome completed timed_out false
expect_out classify-action-required failed classify_gate_outcome completed action_required false
expect_out classify-startup-failure failed classify_gate_outcome completed startup_failure false
expect_out classify-stale failed classify_gate_outcome completed stale false
expect_out classify-cancelled-pending pending classify_gate_outcome completed cancelled false
expect_out classify-cancelled-never-ok pending classify_gate_outcome completed cancelled true
expect_out classify-in-progress pending classify_gate_outcome in_progress "" false
expect_out classify-queued pending classify_gate_outcome queued "" false
expect_out classify-missing pending classify_gate_outcome "" "" false
expect_out classify-neutral-must failed classify_gate_outcome completed neutral false
expect_out classify-skip-may ok classify_gate_outcome completed skipped true
expect_out classify-skip-must failed classify_gate_outcome completed skipped false

# 10: cancelled without replacement stays pending (timeout path, never success)
timeout_sec=1
elapsed=1
cancelled_state="$(classify_gate_outcome completed cancelled false)"
if [[ "$cancelled_state" == "pending" && "$elapsed" -ge "$timeout_sec" && "$cancelled_state" != "ok" ]]; then
	echo "OK   cancelled-alone-times-out-without-pass"
else
	echo "FAIL cancelled-alone-times-out-without-pass state=$cancelled_state"
	fail=1
fi

check_json() {
	"${PYTHON:-python3}" -c 'import json,sys; print(json.dumps({"check_runs": json.loads(sys.argv[1])}))' "$1"
}

select_conc() {
	local head="$1"
	local json="$2"
	local name="$3"
	local merge="${4:-}"
	printf '%s\n' "$json" | pr_gate_latest_check_rows "$head" "$merge" | awk -F '\t' -v n="$name" '$1==n { print $2 "\t" $3 "\t" $4 }'
}

HEAD_A="bd3761a52a8d9d7fc0d36fdc3a3fac22ee2ba01b"
HEAD_B="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
MERGE_A="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
MERGE_OLD="cccccccccccccccccccccccccccccccccccccccc"

# 8 / 11: cancelled then success same HEAD
json_t3="$(check_json '[
  {"id":1,"name":"Format Check","status":"completed","conclusion":"cancelled","head_sha":"'"$HEAD_A"'"},
  {"id":2,"name":"Format Check","status":"completed","conclusion":"success","head_sha":"'"$HEAD_A"'"}
]')"
got="$(select_conc "$HEAD_A" "$json_t3" "Format Check")"
expect_out select-cancelled-then-success $'completed\tsuccess\t'"$HEAD_A" printf '%s' "$got"
expect_out classify-after-replacement-success ok classify_gate_outcome completed success false

# old failure -> new success
json_old_fail_new_success="$(check_json '[
  {"id":1,"name":"secret-scan","status":"completed","conclusion":"failure","head_sha":"'"$HEAD_A"'","started_at":"2026-09-21T18:00:00Z"},
  {"id":2,"name":"secret-scan","status":"completed","conclusion":"success","head_sha":"'"$HEAD_A"'","started_at":"2026-09-21T18:05:00Z"}
]')"
got="$(select_conc "$HEAD_A" "$json_old_fail_new_success" "secret-scan")"
expect_out select-old-failure-new-success $'completed\tsuccess\t'"$HEAD_A" printf '%s' "$got"

# 9: cancelled then in_progress
json_t2="$(check_json '[
  {"id":1,"name":"Format Check","status":"completed","conclusion":"cancelled","head_sha":"'"$HEAD_A"'"},
  {"id":2,"name":"Format Check","status":"in_progress","conclusion":null,"head_sha":"'"$HEAD_A"'"}
]')"
got="$(select_conc "$HEAD_A" "$json_t2" "Format Check")"
expect_out select-cancelled-then-in-progress $'in_progress\t\t'"$HEAD_A" printf '%s' "$got"
st="${got%%$'\t'*}"
rest="${got#*$'\t'}"
conc="${rest%%$'\t'*}"
expect_out classify-after-replacement-in-progress pending classify_gate_outcome "$st" "$conc" false

# old success -> new queued / in_progress
json_old_success_new_queued="$(check_json '[
  {"id":1,"name":"gitleaks","status":"completed","conclusion":"success","head_sha":"'"$HEAD_A"'","started_at":"2026-09-21T18:00:00Z"},
  {"id":2,"name":"gitleaks","status":"queued","conclusion":null,"head_sha":"'"$HEAD_A"'","started_at":"2026-09-21T18:05:00Z"}
]')"
got="$(select_conc "$HEAD_A" "$json_old_success_new_queued" "gitleaks")"
expect_out select-old-success-new-queued $'queued\t\t'"$HEAD_A" printf '%s' "$got"
expect_out classify-old-success-new-queued pending classify_gate_outcome queued "" false

json_old_success_new_progress="$(check_json '[
  {"id":1,"name":"gitleaks","status":"completed","conclusion":"success","head_sha":"'"$HEAD_A"'","started_at":"2026-09-21T18:00:00Z"},
  {"id":2,"name":"gitleaks","status":"in_progress","conclusion":null,"head_sha":"'"$HEAD_A"'","started_at":"2026-09-21T18:05:00Z"}
]')"
got="$(select_conc "$HEAD_A" "$json_old_success_new_progress" "gitleaks")"
expect_out select-old-success-new-in-progress $'in_progress\t\t'"$HEAD_A" printf '%s' "$got"
expect_out classify-old-success-new-in-progress pending classify_gate_outcome in_progress "" false

# 12: old cancelled + new failure same HEAD
json_fail="$(check_json '[
  {"id":10,"name":"Format Check","status":"completed","conclusion":"cancelled","head_sha":"'"$HEAD_A"'"},
  {"id":20,"name":"Format Check","status":"completed","conclusion":"failure","head_sha":"'"$HEAD_A"'"}
]')"
got="$(select_conc "$HEAD_A" "$json_fail" "Format Check")"
expect_out select-cancelled-then-failure $'completed\tfailure\t'"$HEAD_A" printf '%s' "$got"
expect_out classify-after-replacement-failure failed classify_gate_outcome completed failure false

# 13: never select older success to mask newer failure
json_mask="$(check_json '[
  {"id":1,"name":"Format Check","status":"completed","conclusion":"success","head_sha":"'"$HEAD_A"'"},
  {"id":99,"name":"Format Check","status":"completed","conclusion":"failure","head_sha":"'"$HEAD_A"'"}
]')"
got="$(select_conc "$HEAD_A" "$json_mask" "Format Check")"
expect_out select-latest-failure-not-old-success $'completed\tfailure\t'"$HEAD_A" printf '%s' "$got"
expect_out classify-old-success-new-failure failed classify_gate_outcome completed failure false

# old success -> new cancelled is pending/fail-closed until timeout
json_old_success_new_cancelled="$(check_json '[
  {"id":1,"name":"Documentation Check","status":"completed","conclusion":"success","head_sha":"'"$HEAD_A"'","started_at":"2026-09-21T18:00:00Z"},
  {"id":2,"name":"Documentation Check","status":"completed","conclusion":"cancelled","head_sha":"'"$HEAD_A"'","started_at":"2026-09-21T18:05:00Z"}
]')"
got="$(select_conc "$HEAD_A" "$json_old_success_new_cancelled" "Documentation Check")"
expect_out select-old-success-new-cancelled $'completed\tcancelled\t'"$HEAD_A" printf '%s' "$got"
expect_out classify-old-success-new-cancelled pending classify_gate_outcome completed cancelled false

# 14: several generations → latest by id
json_gen="$(check_json '[
  {"id":1,"name":"Lint build files","status":"completed","conclusion":"cancelled","head_sha":"'"$HEAD_A"'"},
  {"id":5,"name":"Lint build files","status":"completed","conclusion":"cancelled","head_sha":"'"$HEAD_A"'"},
  {"id":9,"name":"Lint build files","status":"completed","conclusion":"success","head_sha":"'"$HEAD_A"'"}
]')"
got="$(select_conc "$HEAD_A" "$json_gen" "Lint build files")"
expect_out select-latest-generation $'completed\tsuccess\t'"$HEAD_A" printf '%s' "$got"

# timestamps identical -> id tie-breaker is deterministic
json_same_time="$(check_json '[
  {"id":1,"name":"Vcpkg manifest sanity","status":"completed","conclusion":"failure","head_sha":"'"$HEAD_A"'","started_at":"2026-09-21T18:00:00Z"},
  {"id":2,"name":"Vcpkg manifest sanity","status":"completed","conclusion":"success","head_sha":"'"$HEAD_A"'","started_at":"2026-09-21T18:00:00Z"}
]')"
got="$(select_conc "$HEAD_A" "$json_same_time" "Vcpkg manifest sanity")"
expected_same_time="$(printf 'completed\tsuccess\t%s' "$HEAD_A")"
expect_out select-same-timestamp-id-tiebreak "$expected_same_time" printf '%s' "$got"

# Regression: generation order follows check-run ID, not runner start time.
# An older queued run may start after its newer replacement.
json_old_starts_late="$(check_json '[
  {"id":100,"name":"Format Check","status":"completed","conclusion":"success","head_sha":"'"$HEAD_A"'","started_at":"2026-09-21T18:10:00Z"},
  {"id":200,"name":"Format Check","status":"completed","conclusion":"failure","head_sha":"'"$HEAD_A"'","started_at":"2026-09-21T18:05:00Z"}
]')"
got="$(select_conc "$HEAD_A" "$json_old_starts_late" "Format Check")"
expected_newer_failure="$(printf 'completed\tfailure\t%s' "$HEAD_A")"
expect_out select-newer-id-even-if-older-starts-later "$expected_newer_failure" printf '%s' "$got"
expect_out classify-newer-failure-not-masked failed classify_gate_outcome completed failure false

# Pagination: a newer generation on a later API page must replace an older
# generation from an earlier page for the same required check.
json_page_1="$(check_json '[
  {"id":300,"name":"Documentation Check","status":"completed","conclusion":"success","head_sha":"'"$HEAD_A"'"}
]')"
json_page_2="$(check_json '[
  {"id":400,"name":"Documentation Check","status":"completed","conclusion":"failure","head_sha":"'"$HEAD_A"'"}
]')"
json_two_pages="$(printf '%s\n%s\n' "$json_page_1" "$json_page_2")"
got="$(select_conc "$HEAD_A" "$json_two_pages" "Documentation Check")"
expected_paged_failure="$(printf 'completed\tfailure\t%s' "$HEAD_A")"
expect_out select-newer-generation-across-pages "$expected_paged_failure" printf '%s' "$got"
expect_out classify-newer-paged-failure failed classify_gate_outcome completed failure false

# 15: different HEAD must not mix generations
json_heads="$(check_json '[
  {"id":50,"name":"Format Check","status":"completed","conclusion":"success","head_sha":"'"$HEAD_B"'"},
  {"id":10,"name":"Format Check","status":"completed","conclusion":"failure","head_sha":"'"$HEAD_A"'"}
]')"
got="$(select_conc "$HEAD_A" "$json_heads" "Format Check")"
expect_out select-head-not-other-sha $'completed\tfailure\t'"$HEAD_A" printf '%s' "$got"
got_b="$(select_conc "$HEAD_B" "$json_heads" "Format Check")"
expect_out select-other-head-isolated $'completed\tsuccess\t'"$HEAD_B" printf '%s' "$got_b"

# A missing current-HEAD check is absent, not satisfied by another SHA.
json_missing_head="$(check_json '[
  {"id":50,"name":"Analyze (c-cpp)","status":"completed","conclusion":"success","head_sha":"'"$HEAD_B"'"}
]')"
got="$(select_conc "$HEAD_A" "$json_missing_head" "Analyze (c-cpp)")"
expect_out select-missing-current-head-empty "" printf '%s' "$got"

# Current merge-SHA checks are valid for pull_request workflows that publish
# against GitHub's merge ref; stale merge generations remain isolated.
json_merge_sha="$(check_json '[
  {"id":50,"name":"Build x64 Release","status":"completed","conclusion":"success","head_sha":"'"$MERGE_A"'"},
  {"id":60,"name":"Build x64 Release","status":"completed","conclusion":"failure","head_sha":"'"$MERGE_OLD"'"}
]')"
got="$(select_conc "$HEAD_A" "$json_merge_sha" "Build x64 Release" "$MERGE_A")"
expect_out select-current-merge-sha $'completed\tsuccess\t'"$MERGE_A" printf '%s' "$got"
got="$(select_conc "$HEAD_A" "$json_merge_sha" "Build x64 Release")"
expect_out select-merge-sha-requires-allowlist "" printf '%s' "$got"

json_old_merge_only="$(check_json '[
  {"id":60,"name":"Build Win32 Release","status":"completed","conclusion":"success","head_sha":"'"$MERGE_OLD"'"}
]')"
got="$(select_conc "$HEAD_A" "$json_old_merge_only" "Build Win32 Release" "$MERGE_A")"
expect_out select-stale-merge-sha-empty "" printf '%s' "$got"

json_head_and_merge="$(check_json '[
  {"id":70,"name":"Documentation Check","status":"completed","conclusion":"failure","head_sha":"'"$HEAD_A"'","started_at":"2026-09-21T18:00:00Z"},
  {"id":80,"name":"Documentation Check","status":"completed","conclusion":"success","head_sha":"'"$MERGE_A"'","started_at":"2026-09-21T18:05:00Z"}
]')"
got="$(select_conc "$HEAD_A" "$json_head_and_merge" "Documentation Check" "$MERGE_A")"
expect_out select-latest-across-current-head-and-merge $'completed\tsuccess\t'"$MERGE_A" printf '%s' "$got"

# API error-shaped payload fails explicitly.
set +e
printf '%s\n' '{"message":"bad credentials"}' | pr_gate_latest_check_rows "$HEAD_A" >/dev/null
api_rc=$?
set -e
if [[ "$api_rc" -eq 0 ]]; then
	echo "FAIL api-error-payload-fails"
	fail=1
else
	echo "OK   api-error-payload-fails"
fi

set +e
printf '%s\n' 'not-json' | pr_gate_latest_check_rows "$HEAD_A" "$MERGE_A" >/dev/null
malformed_rc=$?
set -e
if [[ "$malformed_rc" -eq 0 ]]; then
	echo "FAIL malformed-json-fails"
	fail=1
else
	echo "OK   malformed-json-fails"
fi

# A malformed newer record must not be ignored in favor of an older success.
json_malformed_run="$(check_json '[
  {"id":1,"name":"Format Check","status":"completed","conclusion":"success","head_sha":"'"$HEAD_A"'"},
  {"id":null,"name":"Format Check","status":"completed","conclusion":"failure","head_sha":"'"$HEAD_A"'"}
]')"
set +e
printf '%s\n' "$json_malformed_run" | pr_gate_latest_check_rows "$HEAD_A" >/dev/null
malformed_run_rc=$?
set -e
if [[ "$malformed_run_rc" -eq 0 ]]; then
	echo "FAIL malformed-check-run-fails-closed"
	fail=1
else
	echo "OK   malformed-check-run-fails-closed"
fi

# Serialized TSV fields must reject control characters so a malformed value
# cannot shift Bash read fields and synthesize a passing required check.
for control_case in name status conclusion head_sha; do
	case "$control_case" in
	name)
		json_control_char="$(check_json '[
  {"id":1,"name":"Format Check\tspoof","status":"completed","conclusion":"success","head_sha":"'"$HEAD_A"'"}
]')"
		;;
	status)
		json_control_char="$(check_json '[
  {"id":1,"name":"Format Check","status":"completed\nspoof","conclusion":"success","head_sha":"'"$HEAD_A"'"}
]')"
		;;
	conclusion)
		json_control_char="$(check_json '[
  {"id":1,"name":"Format Check","status":"completed","conclusion":"success\rspoof","head_sha":"'"$HEAD_A"'"}
]')"
		;;
	head_sha)
		json_control_char="$(check_json '[
  {"id":1,"name":"Format Check","status":"completed","conclusion":"success","head_sha":"'"$HEAD_A"'\tspoof"}
]')"
		;;
	esac
	set +e
	printf '%s\n' "$json_control_char" | pr_gate_latest_check_rows "$HEAD_A" >/dev/null
	control_char_rc=$?
	set -e
	if [[ "$control_char_rc" -eq 0 ]]; then
		echo "FAIL control-char-$control_case-fails-closed"
		fail=1
	else
		echo "OK   control-char-$control_case-fails-closed"
	fi
done

# Regression: #304 canary race (run 35594164751)
# t0/t1: old Format Check cancelled, replacement not yet reported → pending
json_t0="$(check_json '[
  {"id":106315013598,"name":"Format Check","status":"completed","conclusion":"cancelled","head_sha":"'"$HEAD_A"'"}
]')"
got="$(select_conc "$HEAD_A" "$json_t0" "Format Check")"
expect_out regression-t0-select-cancelled $'completed\tcancelled\t'"$HEAD_A" printf '%s' "$got"
expect_out regression-t1-wait-replacement pending classify_gate_outcome completed cancelled false
if [[ "$(classify_gate_outcome completed cancelled false)" == "ok" ]]; then
	echo "FAIL regression-t1-never-pass-on-cancelled"
	fail=1
else
	echo "OK   regression-t1-never-pass-on-cancelled"
fi

# t2: replacement in_progress
json_t2b="$(check_json '[
  {"id":106315013598,"name":"Format Check","status":"completed","conclusion":"cancelled","head_sha":"'"$HEAD_A"'"},
  {"id":106315368299,"name":"Format Check","status":"in_progress","conclusion":null,"head_sha":"'"$HEAD_A"'"}
]')"
got="$(select_conc "$HEAD_A" "$json_t2b" "Format Check")"
expect_out regression-t2-select-in-progress $'in_progress\t\t'"$HEAD_A" printf '%s' "$got"
expect_out regression-t2-pending pending classify_gate_outcome in_progress "" false

# t3: replacement success (observed 11:29:00 on #304)
json_t3b="$(check_json '[
  {"id":106315013598,"name":"Format Check","status":"completed","conclusion":"cancelled","head_sha":"'"$HEAD_A"'"},
  {"id":106315368299,"name":"Format Check","status":"completed","conclusion":"success","head_sha":"'"$HEAD_A"'"}
]')"
got="$(select_conc "$HEAD_A" "$json_t3b" "Format Check")"
expect_out regression-t3-select-success $'completed\tsuccess\t'"$HEAD_A" printf '%s' "$got"
expect_out regression-t3-ok ok classify_gate_outcome completed success false

# Process-substitution false-green demonstration + checked capture helper.
capture_checked() {
	# Captures stdout of a command; propagates non-zero exit (unlike mapfile < <()).
	local out
	out="$("$@")" || return $?
	printf '%s' "$out"
}

set +e
out="$(capture_checked false)"
rc=$?
set -e
if [[ "$rc" -eq 0 ]]; then
	echo "FAIL capture_checked did not fail on false"
	fail=1
else
	echo "OK   capture_checked fails closed (rc=$rc)"
fi

set +e
# Demonstrate mapfile process-substitution does NOT fail the script under set -e.
(
	set -euo pipefail
	mapfile -t a < <(false)
	exit 0
)
map_rc=$?
set -e
if [[ "$map_rc" -eq 0 ]]; then
	echo "OK   mapfile process-sub does not propagate failure (known pitfall)"
else
	echo "NOTE mapfile unexpectedly failed (rc=$map_rc)"
fi

# End-to-end timeout regression: every expected check except one is terminal
# and acceptable. The cancelled required check must remain pending until the
# real pr-gate.sh polling loop reaches TIMEOUT_SEC and exits non-zero.
timeout_stub_dir="$(mktemp -d)"
cat >"$timeout_stub_dir/gh" <<'EOF_GH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" != "api" ]]; then
	echo "unexpected gh invocation: $*" >&2
	exit 2
fi
cat <<EOF_JSON
{"check_runs":[
  {"id":100,"name":"Lint build files","status":"completed","conclusion":"cancelled","head_sha":"${STUB_HEAD_SHA}"},
  {"id":101,"name":"secret-scan","status":"completed","conclusion":"success","head_sha":"${STUB_HEAD_SHA}"},
  {"id":102,"name":"Vcpkg manifest sanity","status":"completed","conclusion":"success","head_sha":"${STUB_HEAD_SHA}"},
  {"id":103,"name":"Analyze (c-cpp)","status":"completed","conclusion":"success","head_sha":"${STUB_HEAD_SHA}"},
  {"id":104,"name":"Analyze (javascript-typescript)","status":"completed","conclusion":"success","head_sha":"${STUB_HEAD_SHA}"},
  {"id":105,"name":"Analyze (csharp)","status":"completed","conclusion":"success","head_sha":"${STUB_HEAD_SHA}"},
  {"id":106,"name":"Format Check","status":"completed","conclusion":"success","head_sha":"${STUB_HEAD_SHA}"},
  {"id":107,"name":"Documentation Check","status":"completed","conclusion":"success","head_sha":"${STUB_HEAD_SHA}"},
  {"id":108,"name":"Build x64 Release","status":"completed","conclusion":"skipped","head_sha":"${STUB_HEAD_SHA}"},
  {"id":109,"name":"Build Win32 Release","status":"completed","conclusion":"skipped","head_sha":"${STUB_HEAD_SHA}"}
]}
EOF_JSON
EOF_GH
chmod +x "$timeout_stub_dir/gh"

set +e
timeout_output="$(PATH="$timeout_stub_dir:$PATH" \
	STUB_HEAD_SHA="$HEAD_A" \
	GITHUB_REPOSITORY="Mika3578/Envy" \
	HEAD_SHA="$HEAD_A" \
	MERGE_SHA="$HEAD_A" \
	RUN_WINDOWS_BUILD=false \
	RUN_REMOTE_JS=false \
	RUN_DEP_REVIEW=false \
	TIMEOUT_SEC=1 \
	POLL_SEC=0.1 \
	bash ./pr-gate.sh 2>&1)"
timeout_rc=$?
set -e
rm -rf "$timeout_stub_dir"

if [[ "$timeout_rc" -eq 0 ]]; then
	echo "FAIL cancelled-check-e2e-timeout: gate unexpectedly succeeded"
	fail=1
elif [[ "$timeout_output" != *"Timed out after 1s waiting for required checks."* ]]; then
	echo "FAIL cancelled-check-e2e-timeout: timeout message missing"
	printf '%s\n' "$timeout_output"
	fail=1
elif [[ "$timeout_output" != *"Lint build files: cancelled (waiting for replacement)"* ]]; then
	echo "FAIL cancelled-check-e2e-timeout: cancelled check was not kept pending"
	printf '%s\n' "$timeout_output"
	fail=1
elif [[ "$timeout_output" == *"All expected checks completed successfully."* ]]; then
	echo "FAIL cancelled-check-e2e-timeout: cancelled check was accepted as success"
	fail=1
else
	echo "OK   cancelled-check-e2e-timeout"
fi

exit "$fail"
