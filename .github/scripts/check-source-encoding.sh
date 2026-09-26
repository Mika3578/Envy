#!/usr/bin/env bash
# Fail when a PR introduces new encoding corruption in first-party sources.
# Historical debt on the merge base is tolerated (base -> head). See #350.
set -euo pipefail

if [[ -n "${CHECK_ENCODING_ROOT:-}" ]]; then
	ROOT="$CHECK_ENCODING_ROOT"
else
	ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
fi
cd "$ROOT"

resolve_base_head() {
	BASE_SHA="${BASE_SHA:-}"
	HEAD_SHA="${HEAD_SHA:-HEAD}"

	if [[ -n "$BASE_SHA" ]]; then
		return 0
	fi

	if [[ "${GITHUB_EVENT_NAME:-}" == "pull_request" ]]; then
		BASE_SHA="${GITHUB_BASE_SHA:-}"
		HEAD_SHA="${GITHUB_HEAD_SHA:-HEAD}"
	fi

	if [[ -z "$BASE_SHA" && -n "${GITHUB_EVENT_BEFORE:-}" && "${GITHUB_EVENT_BEFORE}" != "0000000000000000000000000000000000000000" ]]; then
		BASE_SHA="$GITHUB_EVENT_BEFORE"
	fi

	if [[ -z "$BASE_SHA" ]]; then
		return 1
	fi
}

if ! resolve_base_head; then
	echo "check-source-encoding: no base SHA; skipping diff (OK)."
	exit 0
fi

if ! git rev-parse --verify "${HEAD_SHA}^{commit}" >/dev/null 2>&1; then
	echo "::error::Invalid HEAD_SHA: ${HEAD_SHA}" >&2
	exit 1
fi

if ! git rev-parse --verify "${BASE_SHA}^{commit}" >/dev/null 2>&1; then
	echo "::error::Invalid BASE_SHA: ${BASE_SHA}" >&2
	exit 1
fi

echo "check-source-encoding: base=${BASE_SHA} head=${HEAD_SHA}"

export CHECK_ENCODING_ROOT="$ROOT"
LIB="${CHECK_ENCODING_LIB:-$ROOT/.github/scripts/check_source_encoding_lib.py}"
if [[ ! -f "$LIB" ]]; then
	echo "::error::Missing check_source_encoding_lib.py (expected at ${LIB})" >&2
	exit 1
fi
python3 "$LIB" "$BASE_SHA" "$HEAD_SHA"
