#!/usr/bin/env bash
# Diff-aware Format Check for first-party C/C++ (Envy/TorrentEnvy/HashLib).
#
# Uses LLVM clang-format-diff against base...head so only changed hunks are
# checked (legacy off-diff lines do not fail the job).
#
# Required env:
#   BASE_SHA  PR base commit
#   HEAD_SHA  PR head commit
# Optional:
#   CLANG_FORMAT_MAJOR   default 18
#   CLANG_FORMAT_DIFF    override binary (default clang-format-diff-$MAJOR)
#   CLANG_FORMAT_BIN     override formatter (default clang-format-$MAJOR)
set -euo pipefail

BASE_SHA="${BASE_SHA:?BASE_SHA is required}"
HEAD_SHA="${HEAD_SHA:?HEAD_SHA is required}"
CLANG_FORMAT_MAJOR="${CLANG_FORMAT_MAJOR:-18}"
CLANG_FORMAT_DIFF="${CLANG_FORMAT_DIFF:-clang-format-diff-${CLANG_FORMAT_MAJOR}}"
CLANG_FORMAT_BIN="${CLANG_FORMAT_BIN:-clang-format-${CLANG_FORMAT_MAJOR}}"

if ! git rev-parse --verify "${BASE_SHA}^{commit}" >/dev/null 2>&1; then
	echo "::error::BASE_SHA is not a valid commit: ${BASE_SHA}" >&2
	exit 1
fi
if ! git rev-parse --verify "${HEAD_SHA}^{commit}" >/dev/null 2>&1; then
	echo "::error::HEAD_SHA is not a valid commit: ${HEAD_SHA}" >&2
	exit 1
fi

if ! command -v "$CLANG_FORMAT_DIFF" >/dev/null 2>&1; then
	echo "::error::Missing ${CLANG_FORMAT_DIFF}. Install clang-format-${CLANG_FORMAT_MAJOR}." >&2
	exit 1
fi
if ! command -v "$CLANG_FORMAT_BIN" >/dev/null 2>&1; then
	echo "::error::Missing ${CLANG_FORMAT_BIN}." >&2
	exit 1
fi

# clang-format-diff reads the working tree at hunk line numbers. PR checkouts
# default to the merge ref; pin the tree to HEAD_SHA so hunks match the PR tip.
if [[ "$(git rev-parse HEAD)" != "$(git rev-parse "${HEAD_SHA}^{commit}")" ]]; then
	git checkout --detach --quiet "$HEAD_SHA"
fi

# git diff exits 1 when a diff exists — that is not a failure for our purposes.
set +e
diff_raw="$(
	git diff -U0 --no-color "${BASE_SHA}...${HEAD_SHA}" -- \
		Envy/ TorrentEnvy/ HashLib/ \
		':(exclude)Services/' \
		':(exclude)Plugins/PluginWizard/' \
		':(exclude)Plugins/RatDVDPlugin/' \
		':(exclude)Plugins/SWFPlugin/' \
		':(exclude)HashLib/HashLib/'
)"
diff_rc=$?
set -e
if ((diff_rc > 1)); then
	echo "::error::git diff failed (exit ${diff_rc})" >&2
	exit 1
fi

# Keep only C/C++ file hunks (include .c — used in first-party trees).
filtered="$(
	printf '%s\n' "$diff_raw" | awk '
		BEGIN { keep=0 }
		/^diff --git / {
			keep=0
			if ($0 ~ /\.(c|cpp|h|cxx|hpp)( |$)/) keep=1
		}
		keep { print }
	'
)"

if [[ -z "${filtered//[$'\t\r\n ']/}" ]]; then
	echo "No first-party C/C++ hunks changed under Envy/TorrentEnvy/HashLib."
	"$CLANG_FORMAT_BIN" --version
	exit 0
fi

echo "Checking clang-format on changed hunks with ${CLANG_FORMAT_DIFF} -binary ${CLANG_FORMAT_BIN}"
"$CLANG_FORMAT_BIN" --version

# Bind clang-format-diff to the pinned major (do not rely on unversioned clang-format).
# Non-empty stdout means a reformatting patch is required. Exit codes vary by
# LLVM version (18 often exits 0 with a patch; newer may exit 1), so treat
# output as authoritative and non-zero-with-empty-output as a tool failure.
set +e
format_out="$(
	printf '%s\n' "$filtered" |
		"$CLANG_FORMAT_DIFF" -p1 -style=file -binary "$CLANG_FORMAT_BIN" 2>&1
)"
format_rc=$?
set -e

if [[ -n "${format_out}" ]]; then
	echo "::error::Changed C/C++ hunks are not clang-format clean. Format the modified lines only (do not bulk-reformat)." >&2
	printf '%s\n' "$format_out" >&2
	exit 1
fi

if ((format_rc != 0)); then
	echo "::error::${CLANG_FORMAT_DIFF} failed (exit ${format_rc})" >&2
	exit 1
fi

echo "clang-format-diff clean on changed hunks."
