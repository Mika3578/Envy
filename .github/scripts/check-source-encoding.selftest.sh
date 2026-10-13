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
	# Clear ambient CI event payload so fixture repos never inherit real PR labels.
	GITHUB_EVENT_PATH="" CHECK_ENCODING_ROOT="$TMP" CHECK_ENCODING_LIB="$LIB" BASE_SHA="$base" HEAD_SHA="$head" bash "$SCRIPT"
}

run_check_with_event() {
	local base="$1"
	local head="$2"
	local event="$3"
	GITHUB_EVENT_PATH="$event" CHECK_ENCODING_ROOT="$TMP" CHECK_ENCODING_LIB="$LIB" BASE_SHA="$base" HEAD_SHA="$head" bash "$SCRIPT"
}

run_check_expect_fail_with_event() {
	local base="$1"
	local head="$2"
	local event="$3"
	set +e
	run_check_with_event "$base" "$head" "$event"
	local rc=$?
	set -e
	if [[ "$rc" -eq 0 ]]; then
		echo "FAIL expected non-zero for: $*"
		exit 1
	fi
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

# FAIL: changed source lines beginning with ++/-- still participate in the diff
# hunk scanner; their diff prefixes must not be mistaken for file headers.
git checkout -q -B diff-prefix-lines "$BASE"
printf 'int value = 0;\r\n++value; // clean\r\n--value; // clean\r\n' >Envy/Prefix.cpp
git add Envy/Prefix.cpp
git commit -q -m "diff prefix base"
PREFIX_BASE="$(git rev-parse HEAD)"
printf 'int value = 0;\r\n++value; // \xef\xbf\xbd\r\n--value; // \xef\xbf\xbd\r\n' >Envy/Prefix.cpp
git add Envy/Prefix.cpp
git commit -q -m "diff prefix corruption"
run_check_expect_fail "$PREFIX_BASE" "$(git rev-parse HEAD)"

# PASS: new file with standard Envy header (no baseline header lines)
git checkout -q -B new-file-pass "$BASE"
printf '// This file is part of Envy (getenvy.com) \xc2\xa9 2020\r\nvoid nf();\r\n' >Envy/NewFile.cpp
git add Envy/NewFile.cpp
git commit -q -m "add new file with header"
run_check "$BASE" "$(git rev-parse HEAD)"

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

# FAIL: new U+0080 (C2 80) in valid UTF-8 on a non-header line
git checkout -q -B c1-control "$BASE"
printf '// body\r\nvoid c1();\r\n' >Envy/C1.cpp
git add Envy/C1.cpp
git commit -q -m "c1 base"
C1_BASE="$(git rev-parse HEAD)"
printf '// body\r\n// marker \xc2\x80\r\nvoid c1();\r\n' >Envy/C1.cpp
git add Envy/C1.cpp
git commit -q -m "c1 introduce"
run_check_expect_fail "$C1_BASE" "$(git rev-parse HEAD)"

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

# FAIL: UTF-8 BOM must not hide copyright header from sensitive-line matching
# (#350): BOM + © -> BOM + ? would otherwise bypass startswith(prefix).
git checkout -q -B bom-copyright "$BASE"
printf '\xef\xbb\xbf// This file is part of Envy (getenvy.com) \xc2\xa9 2016-2018\r\nvoid bom();\r\n' >Envy/BomHeader.cpp
git add Envy/BomHeader.cpp
git commit -q -m "bom copyright base"
BOM_BASE="$(git rev-parse HEAD)"
printf '\xef\xbb\xbf// This file is part of Envy (getenvy.com) ? 2016-2018\r\nvoid bom();\r\nint n;\r\n' >Envy/BomHeader.cpp
git add Envy/BomHeader.cpp
git commit -q -m "bom copyright corrupt"
run_check_expect_fail "$BOM_BASE" "$(git rev-parse HEAD)"

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

# FAIL: mojibake Â© introduced on a non-header line
git checkout -q -B mojibake-test "$BASE"
printf '// body\r\nvoid m();\r\n' >Envy/Moji.cpp
git add Envy/Moji.cpp
git commit -q -m "moji base"
MOJI_BASE="$(git rev-parse HEAD)"
printf '// body\r\n// note \xc3\x82\xc2\xa9\r\nvoid m();\r\n' >Envy/Moji.cpp
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

# PASS: valid UTF-8 punctuation (en dash) is not mojibake
git checkout -q -B utf8-punct "$BASE"
printf '// body\r\nvoid p();\r\n' >Envy/Punct.cpp
git add Envy/Punct.cpp
git commit -q -m "punct base"
PUNCT_BASE="$(git rev-parse HEAD)"
printf '// body\r\n// range \xe2\x80\x93 ok\r\nvoid p();\r\n' >Envy/Punct.cpp
git add Envy/Punct.cpp
git commit -q -m "utf8 en dash"
run_check "$PUNCT_BASE" "$(git rev-parse HEAD)"

# PASS: insert line above historical debt does not flag unchanged debt line (hunk diff)
git checkout -q -B hunk-align "$LEGACY_BASE"
printf '// \xef\xbf\xbd legacy\r\nvoid f();\r\n' >Envy/Legacy.cpp
git add Envy/Legacy.cpp
git commit -q -m "legacy with func"
HUNK_BASE="$(git rev-parse HEAD)"
printf '// inserted\r\n// \xef\xbf\xbd legacy\r\nvoid f();\r\n' >Envy/Legacy.cpp
git add Envy/Legacy.cpp
git commit -q -m "insert above legacy"
run_check "$HUNK_BASE" "$(git rev-parse HEAD)"

# FAIL: new file with single-byte corrupted copyright marker
git checkout -q -B new-bad-copyright "$BASE"
printf '// This file is part of Envy (getenvy.com) \x9d 2016\r\nvoid bad();\r\n' >Envy/BadNew.cpp
git add Envy/BadNew.cpp
git commit -q -m "new corrupt header"
run_check_expect_fail "$BASE" "$(git rev-parse HEAD)"

# PASS: rename-aware diff (base blob at old path, head at new path)
git checkout -q -B rename-aware "$BASE"
printf '// This file is part of Envy (getenvy.com) \xa9 2020\r\nvoid r();\r\n' >Envy/RenameMe.cpp
git add Envy/RenameMe.cpp
git commit -q -m "rename base"
REN_BASE="$(git rev-parse HEAD)"
git mv Envy/RenameMe.cpp Envy/Renamed.cpp
printf '// This file is part of Envy (getenvy.com) \xa9 2020\r\nvoid r();\r\nint n;\r\n' > Envy/Renamed.cpp
git add Envy/Renamed.cpp
git commit -q -m "rename with ascii functional edit"
run_check "$REN_BASE" "$(git rev-parse HEAD)"

# FAIL: header-byte preservation change without encoding-migration label
git checkout -q -B mig-no-label "$BASE"
printf '// This file is part of Envy (getenvy.com) \xa9 2020\r\nvoid m();\r\n' >Envy/MigLabel.cpp
git add Envy/MigLabel.cpp
git commit -q -m "mig base"
MIG_BASE="$(git rev-parse HEAD)"
printf '// This file is part of Envy (getenvy.com) (C) 2020\r\nvoid m();\r\n' >Envy/MigLabel.cpp
git add Envy/MigLabel.cpp
git commit -q -m "mig header form"
run_check_expect_fail "$MIG_BASE" "$(git rev-parse HEAD)"

# PASS: same change is warn-only when PR carries encoding-migration label
EVENT="$TMP/encoding-migration-event.json"
printf '%s\n' '{"pull_request":{"labels":[{"name":"encoding-migration"}]}}' >"$EVENT"
run_check_with_event "$MIG_BASE" "$(git rev-parse HEAD)" "$EVENT"

# FAIL: encoding-migration label does not downgrade new U+FFFD corruption
git checkout -q -B mig-fffd "$MIG_BASE"
printf '// This file is part of Envy (getenvy.com) \xa9 2020\r\n// \xef\xbf\xbd bad\r\nvoid m();\r\n' >Envy/MigLabel.cpp
git add Envy/MigLabel.cpp
git commit -q -m "mig fffd"
run_check_expect_fail_with_event "$MIG_BASE" "$(git rev-parse HEAD)" "$EVENT"

# FAIL: rename non-scanned path with FFFD into Envy/ is not tolerated
git checkout -q -B rename-into-envy "$BASE"
mkdir -p docs
printf '\xef\xbf\xbd legacy doc\r\n' >docs/Corrupt.txt
git add docs/Corrupt.txt
git commit -q -m "doc with fffd"
REN_BASE="$(git rev-parse HEAD)"
git mv docs/Corrupt.txt Envy/RenamedCorrupt.cpp
git commit -q -m "rename corrupt into envy"
run_check_expect_fail "$REN_BASE" "$(git rev-parse HEAD)"

# FAIL: valid UTF-8 file becomes invalid (lone continuation byte on a source line)
git checkout -q -B utf8-invalid "$BASE"
printf '// ascii only\r\nvoid u();\r\n' >Envy/Utf8Valid.cpp
git add Envy/Utf8Valid.cpp
git commit -q -m "utf8 valid base"
UTF8_BASE="$(git rev-parse HEAD)"
printf '// ascii only\r\nvoid u();\r\n// \x9d lone\r\n' >Envy/Utf8Valid.cpp
git add Envy/Utf8Valid.cpp
git commit -q -m "utf8 break"
run_check_expect_fail "$UTF8_BASE" "$(git rev-parse HEAD)"

# FAIL: already-invalid legacy file gains a new invalid line (0x9D). Whole-blob
# validity stays invalid→invalid with no FFFD/C1/mojibake metric increase.
git checkout -q -B legacy-invalid-new-line "$BASE"
printf '// legacy \xa9 debt\r\nvoid legacy();\r\n' >Envy/LegacyInvalid.cpp
git add Envy/LegacyInvalid.cpp
git commit -q -m "legacy invalid utf8 base"
LEGACY_INVALID_BASE="$(git rev-parse HEAD)"
printf '// legacy \xa9 debt\r\nvoid legacy();\r\n// \x9d new debt\r\n' >Envy/LegacyInvalid.cpp
git add Envy/LegacyInvalid.cpp
git commit -q -m "add invalid line to legacy invalid file"
run_check_expect_fail "$LEGACY_INVALID_BASE" "$(git rev-parse HEAD)"

# PASS: already-invalid legacy file with ASCII-only functional edit
git checkout -q -B legacy-invalid-ascii "$LEGACY_INVALID_BASE"
printf '// legacy \xa9 debt\r\nvoid legacy();\r\nint y;\r\n' >Envy/LegacyInvalid.cpp
git add Envy/LegacyInvalid.cpp
git commit -q -m "ascii edit on legacy invalid"
run_check "$LEGACY_INVALID_BASE" "$(git rev-parse HEAD)"

# FAIL: mutate an already-invalid line by appending a new raw invalid byte (0x9D).
# Both base and head lines stay invalid UTF-8; error-byte delta must still fail.
git checkout -q -B legacy-invalid-mutate-line "$LEGACY_INVALID_BASE"
printf '// legacy \xa9\x9d debt\r\nvoid legacy();\r\n' >Envy/LegacyInvalid.cpp
git add Envy/LegacyInvalid.cpp
git commit -q -m "append invalid byte on legacy invalid line"
run_check_expect_fail "$LEGACY_INVALID_BASE" "$(git rev-parse HEAD)"

# FAIL: already-invalid legacy line gains a UTF-8 C1 control (C2 80). Whole-blob
# validity stays invalid; C1 sequence counting must still fail.
git checkout -q -B legacy-invalid-c1 "$LEGACY_INVALID_BASE"
printf '// legacy \xa9 debt \xc2\x80\r\nvoid legacy();\r\n' >Envy/LegacyInvalid.cpp
git add Envy/LegacyInvalid.cpp
git commit -q -m "add utf8 c1 on legacy invalid line"
run_check_expect_fail "$LEGACY_INVALID_BASE" "$(git rev-parse HEAD)"

# FAIL: uppercase Windows source suffix must still be scanned on Linux CI
git checkout -q -B upper-suffix "$BASE"
printf '// header\r\nvoid u();\r\n' >Envy/Upper.CPP
git add Envy/Upper.CPP
git commit -q -m "upper cpp base"
UPPER_BASE="$(git rev-parse HEAD)"
printf '// header\r\nvoid u();\r\n// \xef\xbf\xbd\r\n' >Envy/Upper.CPP
git add Envy/Upper.CPP
git commit -q -m "upper cpp fffd"
run_check_expect_fail "$UPPER_BASE" "$(git rev-parse HEAD)"

# FAIL: non-ASCII filename must not be skipped by core.quotepath quoting
git checkout -q -B nonascii-name "$BASE"
printf '// header\r\nvoid n();\r\n' >"Envy/é.cpp"
git add "Envy/é.cpp"
git commit -q -m "nonascii name base"
NONASCII_BASE="$(git rev-parse HEAD)"
printf '// header\r\nvoid n();\r\n// \xef\xbf\xbd\r\n' >"Envy/é.cpp"
git add "Envy/é.cpp"
git commit -q -m "nonascii name fffd"
run_check_expect_fail "$NONASCII_BASE" "$(git rev-parse HEAD)"

echo "OK   check-source-encoding.selftest"
