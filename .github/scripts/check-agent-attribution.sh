#!/usr/bin/env bash
# Thin wrapper so existing workflow/selftest invocations keep working.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd -P)"
if command -v cygpath >/dev/null 2>&1; then
	ROOT="$(cygpath -u "$ROOT")"
fi
exec "${PYTHON:-python3}" "$ROOT/check-agent-attribution.py" "$@"
