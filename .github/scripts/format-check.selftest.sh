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
printf 'BasedOnStyle: LLVM\nIndentWidth: 4\nColumnLimit: 80\nAllowShortFunctionsOnASingleLine: None\n' >.clang-format
mkdir -p Envy

# Base: legacy debt lives in a separate function so a clean change in main()
# is not poisoned by neighboring mis-indented lines (clang-format-diff formats
# changed lines using surrounding AST/indent context).
cat >Envy/Foo.cpp <<'EOF'
void legacy() {
int debt = 1;
}

int main() {
    return 0;
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

# format-check.sh may detach HEAD to HEAD_SHA; restore tip after each call.
# Stores exit code in LAST_FORMAT_RC (avoids set -e pitfalls with return).
LAST_FORMAT_RC=0
run_format_check() {
	local tip
	tip=$(git rev-parse HEAD)
	set +e
	bash "$ROOT/.github/scripts/format-check.sh"
	LAST_FORMAT_RC=$?
	git checkout --detach --quiet "$tip" 2>/dev/null || true
	set -e
}

# Head A: change only a clean line in main(); legacy() stays off-hunk with -U0.
cat >Envy/Foo.cpp <<'EOF'
void legacy() {
int debt = 1;
}

int main() {
    return 1;
}
EOF
git add Envy/Foo.cpp
git commit -q -m 'clean hunk change'
HEAD_CLEAN=$(git rev-parse HEAD)

BASE_SHA=$BASE HEAD_SHA=$HEAD_CLEAN run_format_check
if [[ "$LAST_FORMAT_RC" -ne 0 ]]; then
	echo "FAIL legacy off-hunk / clean changed hunk should SUCCESS (rc=$LAST_FORMAT_RC)"
	fail=1
else
	echo "OK   legacy off-hunk + clean changed hunk → SUCCESS"
fi

# Head B: badly formatted changed line in main().
cat >Envy/Foo.cpp <<'EOF'
void legacy() {
int debt = 1;
}

int main() {
return 1+2+3+4+5+6+7+8+9+10+11+12+13+14+15+16+17+18+19+20;
}
EOF
git add Envy/Foo.cpp
git commit -q -m 'bad hunk'
HEAD_BAD=$(git rev-parse HEAD)

BASE_SHA=$BASE HEAD_SHA=$HEAD_BAD run_format_check
if [[ "$LAST_FORMAT_RC" -eq 0 ]]; then
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
if [[ "$LAST_FORMAT_RC" -ne 0 ]]; then
	echo "FAIL expected SUCCESS on docs-only / no C++ hunks (rc=$LAST_FORMAT_RC)"
	fail=1
else
	echo "OK   no C++ hunks → SUCCESS"
fi

# Invalid BASE must fail closed.
BASE_SHA=deadbeef HEAD_SHA=$HEAD_DOCS run_format_check
if [[ "$LAST_FORMAT_RC" -eq 0 ]]; then
	echo "FAIL expected FAILURE on invalid BASE_SHA"
	fail=1
else
	echo "OK   invalid BASE_SHA → FAILURE (fail-closed)"
fi

# Missing tool must fail closed.
BASE_SHA=$BASE HEAD_SHA=$HEAD_CLEAN CLANG_FORMAT_DIFF=clang-format-diff-missing-xyz \
	run_format_check
if [[ "$LAST_FORMAT_RC" -eq 0 ]]; then
	echo "FAIL expected FAILURE when clang-format-diff is missing"
	fail=1
else
	echo "OK   missing clang-format-diff → FAILURE (fail-closed)"
fi

exit "$fail"
