#!/usr/bin/env bash
# Self-test for check-source-encoding (diff-aware base -> head guard).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/.github/scripts/check-source-encoding.sh"
LIB="$ROOT/.github/scripts/check_source_encoding_lib.py"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cd "$TMP"
git init -q
git config user.email "selftest@example.com"
git config user.name "selftest"

mkdir -p Envy Installer/Scripts

run_check() {
	local base="$1"
	local head="$2"
	CHECK_ENCODING_ROOT="$TMP" CHECK_ENCODING_LIB="$LIB" BASE_SHA="$base" HEAD_SHA="$head" bash "$SCRIPT"
}

run_check_expect_fail() {
	set +e
	run_check "$@"
	local rc=$?
	set -e
	if [[ "$rc" -eq 0 ]]; then
		echo "FAIL expected non-zero for: $*"
		exit 1
	fi
}

# PASS: ASCII-only functional edit
printf '// header\r\nvoid ok();\r\n' >Envy/Clean.cpp
git add Envy/Clean.cpp
git commit -q -m "base clean"
BASE="$(git rev-parse HEAD)"
printf '// header\r\nvoid ok();\r\nint x;\r\n' >Envy/Clean.cpp
git add Envy/Clean.cpp
git commit -q -m "ascii functional"
HEAD_ASCII="$(git rev-parse HEAD)"
run_check "$BASE" "$HEAD_ASCII"

# PASS: historical U+FFFD unchanged
printf '// \xef\xbf\xbd legacy\r\n' >Envy/Legacy.cpp
git add Envy/Legacy.cpp
git commit -q -m "legacy fffd"
LEGACY_BASE="$(git rev-parse HEAD)"
printf '// \xef\xbf\xbd legacy\r\nvoid f();\r\n' >Envy/Legacy.cpp
git add Envy/Legacy.cpp
git commit -q -m "touch legacy"
run_check "$LEGACY_BASE" "$(git rev-parse HEAD)"

# FAIL: new U+FFFD
git checkout -q -B fffd-test "$BASE"
printf '// \xef\xbf\xbd new\r\n' >Envy/Clean.cpp
git add Envy/Clean.cpp
git commit -q -m "introduce fffd"
run_check_expect_fail "$BASE" "$(git rev-parse HEAD)"

# FAIL: rejects_copyright_c2a9_to_c29d_corruption (UTF-8 © -> U+009D)
git checkout -q -B utf8-corrupt "$BASE"
printf '// This file is part of Envy (getenvy.com) \xc2\xa9 2016-2018\r\nvoid f();\r\n' >Envy/Corrupt.cpp
git add Envy/Corrupt.cpp
git commit -q -m "utf8 copyright base"
CORRUPT_BASE="$(git rev-parse HEAD)"
printf '// This file is part of Envy (getenvy.com) \xc2\x9d 2016-2018\r\nvoid f();\r\nint y;\r\n' >Envy/Corrupt.cpp
git add Envy/Corrupt.cpp
git commit -q -m "utf8 copyright corrupt"
run_check_expect_fail "$CORRUPT_BASE" "$(git rev-parse HEAD)"

# FAIL: real #357 legacy single-byte 0xA9 -> 0x9D in ENVY header
git checkout -q -B pr357-regression "$BASE"
printf '// This file is part of Envy (getenvy.com) \xa9 2016-2018\r\nvoid g();\r\n' >Envy/Datagrams.cpp
git add Envy/Datagrams.cpp
git commit -q -m "legacy copyright base"
PR357_BASE="$(git rev-parse HEAD)"
printf '// This file is part of Envy (getenvy.com) \x9d 2016-2018\r\nvoid g();\r\nint z;\r\n' >Envy/Datagrams.cpp
git add Envy/Datagrams.cpp
git commit -q -m "legacy copyright corrupt"
run_check_expect_fail "$PR357_BASE" "$(git rev-parse HEAD)"

# FAIL: mojibake Â© introduced
git checkout -q -B mojibake-test "$BASE"
printf '// This file is part of Envy (getenvy.com) \xa9 2016\r\n' >Envy/Moji.cpp
git add Envy/Moji.cpp
git commit -q -m "moji base"
MOJI_BASE="$(git rev-parse HEAD)"
printf '// This file is part of Envy (getenvy.com) \xc3\x82\xc2\xa9 2016\r\n' >Envy/Moji.cpp
git add Envy/Moji.cpp
git commit -q -m "mojibake"
run_check_expect_fail "$MOJI_BASE" "$(git rev-parse HEAD)"

# FAIL: installer AppCopyright © -> ?
git checkout -q -B iss-test "$BASE"
printf 'AppCopyright=Envy \xa9 2020\r\n' >Installer/Scripts/Main.iss
git add Installer/Scripts/Main.iss
git commit -q -m "iss base"
ISS_BASE="$(git rev-parse HEAD)"
printf 'AppCopyright=Envy ? 2020\r\n' >Installer/Scripts/Main.iss
git add Installer/Scripts/Main.iss
git commit -q -m "iss corrupt"
run_check_expect_fail "$ISS_BASE" "$(git rev-parse HEAD)"

# PASS: removing historical anomaly
git checkout -q -B fix-legacy "$LEGACY_BASE"
printf '// header\r\nvoid ok();\r\n' >Envy/Legacy.cpp
git add Envy/Legacy.cpp
git commit -q -m "remove fffd"
run_check "$LEGACY_BASE" "$(git rev-parse HEAD)"

echo "OK   check-source-encoding.selftest"
