#!/usr/bin/env bash
# Shared conclusion helpers for PR Gate (sourced by pr-gate.sh and selftests).
# shellcheck shell=bash

is_bad_conclusion() {
	local conclusion="$1"
	case "$conclusion" in
	failure | cancelled | timed_out | action_required | startup_failure | stale)
		return 0
		;;
	*)
		return 1
		;;
	esac
}

# PR Gate concurrency can cancel a run before its replacement check exists.
# A cancelled generation must remain pending; it must never green-light the
# gate, but it must not fail the replacement generation either.
is_fail_fast_conclusion() {
	local conclusion="$1"
	case "$conclusion" in
	failure | timed_out | action_required | startup_failure | stale)
		return 0
		;;
	*)
		return 1
		;;
	esac
}

classify_gate_outcome() {
	local status="${1:-}"
	local conclusion="${2:-}"
	local allow_skip="${3:-false}"

	if [[ "$status" != "completed" ]]; then
		printf '%s\n' pending
		return
	fi
	if [[ "$conclusion" == "cancelled" ]]; then
		printf '%s\n' pending
		return
	fi
	if is_fail_fast_conclusion "$conclusion"; then
		printf '%s\n' failed
		return
	fi
	if [[ "$allow_skip" == "true" ]]; then
		if is_ok_may_skip "$conclusion"; then
			printf '%s\n' ok
			return
		fi
	else
		if is_ok_must_pass "$conclusion"; then
			printf '%s\n' ok
			return
		fi
	fi
	printf '%s\n' failed
}

# must_pass: only success is OK (skipped/neutral/empty fail).
is_ok_must_pass() {
	local conclusion="$1"
	if [[ "$conclusion" == "success" ]]; then
		return 0
	fi
	return 1
}

# may_skip: success or skipped OK; neutral/empty fail.
is_ok_may_skip() {
	local conclusion="$1"
	case "$conclusion" in
	success | skipped)
		return 0
		;;
	*)
		return 1
		;;
	esac
}
