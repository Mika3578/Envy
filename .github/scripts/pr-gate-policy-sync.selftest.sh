#!/usr/bin/env bash
# Fail closed when PR Gate polling omits a Protect develop required context.
# Compares declarative .github/settings.yml (documented mirror of ruleset
# 16457466) to add_must/add_skip names in pr-gate.sh. PR Gate excludes itself.
set -euo pipefail
cd "$(dirname "$0")"
repo_root="$(cd ../.. && pwd)"
settings="${repo_root}/.github/settings.yml"
gate="${repo_root}/.github/scripts/pr-gate.sh"

if [[ ! -f "$settings" || ! -f "$gate" ]]; then
	echo "FAIL pr-gate-policy-sync: missing settings or pr-gate.sh" >&2
	exit 1
fi

mapfile -t contexts < <("${PYTHON:-python3}" - "$settings" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(encoding="utf-8")
block = re.search(
    r"name:\s*develop\b.*?required_status_checks:\s*\n\s*strict:.*?contexts:\s*\n((?:\s+- \"[^\"]+\"\n)+)",
    text,
    re.S,
)
if not block:
    raise SystemExit("could not parse develop required_status_checks contexts")
for line in block.group(1).splitlines():
    m = re.match(r'\s+- "([^"]+)"\s*$', line)
    if m:
        print(m.group(1))
PY
)

mapfile -t gate_names < <(grep -E 'add_(must|skip) "' "$gate" | sed -E 's/.*"(.*)".*/\1/' | sort -u)

declare -A gate_set=()
for name in "${gate_names[@]}"; do
	gate_set["$name"]=1
done

fail=0
for ctx in "${contexts[@]}"; do
	if [[ "$ctx" == "PR Gate" ]]; then
		continue
	fi
	if [[ -z "${gate_set[$ctx]:-}" ]]; then
		echo "FAIL pr-gate-policy-sync: Protect develop context not referenced in pr-gate.sh: $ctx" >&2
		fail=1
	fi
done

if [[ "$fail" -ne 0 ]]; then
	exit 1
fi

if ! grep -q 'filter=all' "$gate"; then
	echo "FAIL pr-gate-policy-sync: pr-gate.sh must request check-runs with filter=all" >&2
	exit 1
fi

echo "OK   pr-gate-policy-sync (${#contexts[@]} ruleset contexts, ${#gate_names[@]} gate names)"
