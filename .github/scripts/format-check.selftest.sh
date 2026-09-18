#!/usr/bin/env bash
# Self-test for diff-aware format-check.sh (changed hunks only).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
fail=0

if ! command -v clang-format-diff-18 >/dev/null 2>&1 && ! command -v clang-format-diff >/dev/null 2>&1; then
	echo "SKIP format-check.selftest: clang-format-diff not installed locally"
	exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

git init -q "$TMP/repo"
cd "$TMP/repo"
git config user.email "ci@example.com"
git config user.name "CI"
printf 'BasedOnStyle: LLVM\nIndentWidth: 4\nColumnLimit: 80\n' >.clang-format
mkdir -p Envy

# Base: intentionally messy middle line (legacy debt outside later hunks).
cat >Envy/Foo.cpp <<'EOF'
int main() {
int x = 1;
    return x;
}
EOF
git add Envy/Foo.cpp .clang-format
git commit -q -m base
BASE=$(git rev-parse HEAD)

export CLANG_FORMAT_MAJOR=18
if command -v clang-format-diff-18 >/dev/null 2>&1; then
	export CLANG_FORMAT_DIFF=clang-format-diff-18
	export CLANG_FORMAT_BIN=clang-format-18
else
	export CLANG_FORMAT_DIFF=clang-format-diff
	if command -v clang-format-18 >/dev/null 2>&1; then
		export CLANG_FORMAT_BIN=clang-format-18
	else
		mkdir -p "$TMP/bin"
		ln -sf "$(command -v clang-format)" "$TMP/bin/clang-format-18"
		export PATH="$TMP/bin:$PATH"
		export CLANG_FORMAT_BIN=clang-format-18
		export CLANG_FORMAT_MAJOR=18
	fi
fi

# Head A: comment-only touch on an already-indented return line so the changed
# hunk is clang-format clean; legacy `int x = 1;` stays off-hunk with -U0.
cat >Envy/Foo.cpp <<'EOF'
int main() {
int x = 1;
    return x; // keep
}
EOF
git add Envy/Foo.cpp
git commit -q -m 'clean hunk change'
HEAD_CLEAN=$(git rev-parse HEAD)

# format-check.sh may detach HEAD to HEAD_SHA; restore tip after each call.
run_format_check() {
	local tip rc
	tip=$(git rev-parse HEAD)
	set +e
	bash "$ROOT/.github/scripts/format-check.sh"
	rc=$?
	set -e
	git checkout --detach --quiet "$tip"
	return "$rc"
}

set +e
BASE_SHA=$BASE HEAD_SHA=$HEAD_CLEAN run_format_check
rc=$?
set -e
if [[ "$rc" -ne 0 ]]; then
	echo "FAIL legacy off-hunk / clean changed hunk should SUCCESS (rc=$rc)"
	fail=1
else
	echo "OK   legacy off-hunk + clean changed hunk → SUCCESS"
fi

# Head B: clearly bad new formatting on the changed line.
cat >Envy/Foo.cpp <<'EOF'
int main() {
int x = 1;
return x+1+2+3+4+5+6+7+8+9+10+11+12+13+14+15+16+17+18+19+20;
}
EOF
git add Envy/Foo.cpp
git commit -q -m 'bad hunk'
HEAD_BAD=$(git rev-parse HEAD)

set +e
BASE_SHA=$BASE HEAD_SHA=$HEAD_BAD run_format_check
rc=$?
set -e
if [[ "$rc" -eq 0 ]]; then
	echo "FAIL expected FAILURE on badly formatted changed hunk"
	fail=1
else
	echo "OK   bad changed hunk → FAILURE"
fi

# Docs-only commit: no C++ hunks.
mkdir -p docs
echo note >docs/a.md
git add docs/a.md
git commit -q -m docs
HEAD_DOCS=$(git rev-parse HEAD)
BASE_SHA=$HEAD_BAD HEAD_SHA=$HEAD_DOCS run_format_check
echo "OK   no C++ hunks → SUCCESS"

# Invalid BASE must fail closed.
set +e
BASE_SHA=deadbeef HEAD_SHA=$HEAD_DOCS run_format_check
rc=$?
set -e
if [[ "$rc" -eq 0 ]]; then
	echo "FAIL expected FAILURE on invalid BASE_SHA"
	fail=1
else
	echo "OK   invalid BASE_SHA → FAILURE (fail-closed)"
fi

# Missing tool must fail closed.
set +e
BASE_SHA=$BASE HEAD_SHA=$HEAD_CLEAN CLANG_FORMAT_DIFF=clang-format-diff-missing-xyz \
	run_format_check
rc=$?
set -e
if [[ "$rc" -eq 0 ]]; then
	echo "FAIL expected FAILURE when clang-format-diff is missing"
	fail=1
else
	echo "OK   missing clang-format-diff → FAILURE (fail-closed)"
fi

exit "$fail"
