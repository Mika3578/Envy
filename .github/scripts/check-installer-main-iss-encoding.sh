#!/usr/bin/env bash
# Contractual UTF-8 validation for Installer/Scripts/Main.iss (issue #350 / PR #354).
set -euo pipefail

MAIN_ISS="${INSTALLER_MAIN_ISS:-Installer/Scripts/Main.iss}"

if [[ ! -f "$MAIN_ISS" ]]; then
	echo "::error::Missing ${MAIN_ISS}" >&2
	exit 1
fi

python3 - "$MAIN_ISS" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = path.read_bytes()

if data.startswith(b"\xef\xbb\xbf"):
	print(f"::warning file={path}::UTF-8 BOM present (allowed but not required for Inno 6.3+).")

try:
	text = data.decode("utf-8")
except UnicodeDecodeError as exc:
	print(f"::error file={path}::Not valid UTF-8: {exc}", file=sys.stderr)
	sys.exit(1)

if b"\xef\xbf\xbd" in data:
	print(f"::error file={path}::Contains UTF-8 replacement character (U+FFFD).", file=sys.stderr)
	sys.exit(1)

m = re.search(r'^#define\s+copyright\s+"([^"]*)"', text, re.MULTILINE)
if not m:
	print(f"::error file={path}::Missing #define copyright macro.", file=sys.stderr)
	sys.exit(1)

value = m.group(1)
expected_year = "2016-2020 Envy Development Team"
if expected_year not in value:
	print(f"::error file={path}::Unexpected copyright suffix: {value!r}", file=sys.stderr)
	sys.exit(1)

if "\u00a9" not in value:
	print(
		f"::error file={path}::Copyright define must contain U+00A9 (©), not ASCII fallback or corruption. Got: {value!r}",
		file=sys.stderr,
	)
	sys.exit(1)

if value.startswith("? ") or "? 2016" in value:
	print(f"::error file={path}::Corrupted '?' copyright substitution detected.", file=sys.stderr)
	sys.exit(1)

if "(C)" in value:
	print(f"::error file={path}::ASCII (C) fallback is not the contractual copyright spelling.", file=sys.stderr)
	sys.exit(1)

print(f"check-installer-main-iss-encoding: OK ({path})")
PY
