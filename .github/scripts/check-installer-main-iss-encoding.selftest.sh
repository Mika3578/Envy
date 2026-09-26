#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
SCRIPT=".github/scripts/check-installer-main-iss-encoding.sh"

bash "$SCRIPT"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
cp Installer/Scripts/Main.iss "$tmpdir/Main.iss"
python3 - "$tmpdir/Main.iss" <<'PY'
import sys
from pathlib import Path
p = Path(sys.argv[1])
t = p.read_text(encoding="utf-8")
t = t.replace("\u00a9", "?")
p.write_text(t, encoding="utf-8")
PY

if INSTALLER_MAIN_ISS="$tmpdir/Main.iss" bash "$SCRIPT"; then
	echo "FAIL: corrupted copyright should fail"
	exit 1
fi

echo "OK   check-installer-main-iss-encoding selftest"
