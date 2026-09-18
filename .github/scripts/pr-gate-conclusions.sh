#!/usr/bin/env bash
# Shared conclusion helpers for PR Gate (sourced by pr-gate.sh and selftests).
# shellcheck shell=bash

is_bad_conclusion() {
	case "$1" in
	failure | cancelled | timed_out | action_required | startup_failure | stale)
		return 0
		;;
	*)
		return 1
		;;
	esac
}

# must_pass: only success is OK (skipped/neutral fail).
is_ok_must_pass() {
	[[ "$1" == "success" ]]
}

# may_skip: success or skipped OK; neutral fails.
is_ok_may_skip() {
	case "$1" in
	success | skipped)
		return 0
		;;
	*)
		return 1
		;;
	esac
}
