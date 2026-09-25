#!/usr/bin/env bash
# Fail when a PR introduces new UTF-8 replacement bytes (EF BF BD / U+FFFD) in
# first-party C/C++ sources. Historical debt on develop is not rewritten here;
# we compare counts against the merge base per file.
set -euo pipefail

SCRIPT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ROOT="${CHECK_ENCODING_ROOT:-$SCRIPT_ROOT}"
cd "$ROOT"

FIRST_PARTY_PREFIXES=(
	Envy/
	HashLib/
	TorrentEnvy/
	Unpacker/
	SkinBuilder/
)

count_fffd_blob() {
	python3 -c 'import sys; print(sys.stdin.buffer.read().count(b"\xef\xbf\xbd"))'
}

is_first_party() {
	local f="$1"
	local p
	for p in "${FIRST_PARTY_PREFIXES[@]}"; do
		if [[ "$f" == "$p"* ]]; then
			return 0
		fi
	done
	return 1
}

is_source_file() {
	case "$1" in
		*.cpp | *.cxx | *.cc | *.c | *.h | *.hpp | *.hxx | *.inl) return 0 ;;
		*) return 1 ;;
	esac
}

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
		# Nothing to diff (e.g. workflow_dispatch without SHAs).
		return 1
	fi
}

failed=0

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

while IFS= read -r -d '' f; do
	is_first_party "$f" || continue
	is_source_file "$f" || continue

	base_count=0
	if git cat-file -e "${BASE_SHA}:${f}" 2>/dev/null; then
		base_count="$(git show "${BASE_SHA}:${f}" | count_fffd_blob)"
	fi
	head_count="$(git show "${HEAD_SHA}:${f}" | count_fffd_blob)"

	if ((head_count > base_count)); then
		echo "::error file=${f}::New UTF-8 replacement character (U+FFFD, bytes EF BF BD): base=${base_count} head=${head_count}. Edit/save with a UTF-8-forcing editor can cause this. See docs/10_dev/development-environment.md and issue #350." >&2
		failed=1
	fi
done < <(git diff --name-only -z --diff-filter=ACMR "${BASE_SHA}" "${HEAD_SHA}")

if ((failed != 0)); then
	exit 1
fi

echo "check-source-encoding: no new U+FFFD in changed first-party sources."
exit 0
