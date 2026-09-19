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
