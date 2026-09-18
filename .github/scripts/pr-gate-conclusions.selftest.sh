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

exit "$fail"
