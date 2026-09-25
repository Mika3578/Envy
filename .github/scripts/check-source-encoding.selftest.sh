#!/usr/bin/env bash
# Self-test for check-source-encoding.sh (diff-aware U+FFFD guard).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/.github/scripts/check-source-encoding.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cd "$TMP"
git init -q
git config user.email "selftest@example.com"
git config user.name "selftest"

mkdir -p Envy
printf '// header\r\nvoid ok();\r\n' >Envy/Clean.cpp
git add Envy/Clean.cpp
git commit -q -m "base clean"
BASE="$(git rev-parse HEAD)"

printf '// \xef\xbf\xbd legacy\r\n' >Envy/Legacy.cpp
git add Envy/Legacy.cpp
git commit -q -m "legacy fffd on branch"
LEGACY_HEAD="$(git rev-parse HEAD)"

printf '// \xef\xbf\xbd legacy\r\nvoid f();\r\n' >Envy/Legacy.cpp
git add Envy/Legacy.cpp
git commit -q -m "touch legacy"
HEAD_TOUCH="$(git rev-parse HEAD)"

CHECK_ENCODING_ROOT="$TMP" BASE_SHA="$LEGACY_HEAD" HEAD_SHA="$HEAD_TOUCH" bash "$SCRIPT"

git checkout -q -B bad-test "$BASE"
printf '// \xef\xbf\xbd new\r\n' >Envy/Clean.cpp
git add Envy/Clean.cpp
git commit -q -m "introduce fffd"
HEAD_BAD="$(git rev-parse HEAD)"

set +e
CHECK_ENCODING_ROOT="$TMP" BASE_SHA="$BASE" HEAD_SHA="$HEAD_BAD" bash "$SCRIPT"
rc=$?
set -e
if [[ "$rc" -eq 0 ]]; then
	echo "FAIL expected non-zero when new FFFD introduced"
	exit 1
fi

git checkout -q -B fix-test "$HEAD_BAD"
printf '// header\r\nvoid ok();\r\n' >Envy/Clean.cpp
git add Envy/Clean.cpp
git commit -q -m "revert fffd"
HEAD_FIX="$(git rev-parse HEAD)"

CHECK_ENCODING_ROOT="$TMP" BASE_SHA="$HEAD_BAD" HEAD_SHA="$HEAD_FIX" bash "$SCRIPT"

echo "OK   check-source-encoding.selftest"
