#!/usr/bin/env bash
# Expected check names for phase regression tests.

ci_phase_policy() {
	case "${CI_PHASE:-full}" in
	draft | live-test | ready | full) ;;
	*) echo "::error::Invalid CI_PHASE" >&2; return 1 ;;
	esac
	add_must "Lint build files"
	add_must "secret-scan"
	add_must "Vcpkg manifest sanity"
	add_must "Analyze (c-cpp)"
	add_must "Analyze (javascript-typescript)"
	add_must "Format Check"
	add_must "Documentation Check"
	if [[ "${CI_PHASE:-full}" != draft ]]; then
		add_must "Analyze (csharp)"
		add_must "Build x64 Release"
		add_must "Build Win32 Release"
	fi
	if [[ "${RUN_REMOTE_JS:-false}" == true ]]; then
		add_must "Remote JS Security Tests"
	fi
	if [[ "${RUN_DEP_REVIEW:-false}" == true ]]; then
		add_must "Dependency review"
	fi
}
