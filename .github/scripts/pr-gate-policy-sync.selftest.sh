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

extract_required_contexts() {
	"${PYTHON:-python3}" - "$1" <<'PY'
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
}

extract_gate_names() {
	grep -E 'add_(must|skip) "' "$1" | sed -E 's/.*"(.*)".*/\1/' | sort -u
}

contexts_text="$(extract_required_contexts "$settings")" || {
	echo "FAIL pr-gate-policy-sync: could not parse required contexts from settings.yml" >&2
	exit 1
}
if [[ -z "${contexts_text//[$'\t\n\r ']/}" ]]; then
	echo "FAIL pr-gate-policy-sync: parsed zero required contexts (fail closed)" >&2
	exit 1
fi
mapfile -t contexts <<<"$contexts_text"

gate_names_text="$(extract_gate_names "$gate")" || {
	echo "FAIL pr-gate-policy-sync: could not read add_must/add_skip from pr-gate.sh" >&2
	exit 1
}
if [[ -z "${gate_names_text//[$'\t\n\r ']/}" ]]; then
	echo "FAIL pr-gate-policy-sync: pr-gate.sh has no add_must/add_skip names" >&2
	exit 1
fi
mapfile -t gate_names <<<"$gate_names_text"

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

# Negative fixtures: parser and gate extraction must fail closed.
neg_fail=0
neg_tmp="$(mktemp -d)"
trap 'rm -rf "$neg_tmp"' EXIT

cat >"$neg_tmp/bad-settings.yml" <<'EOF'
name: develop
required_status_checks:
  strict: true
  contexts:
EOF

set +e
bad_out="$(extract_required_contexts "$neg_tmp/bad-settings.yml" 2>&1)"
bad_rc=$?
set -e
if [[ "$bad_rc" -eq 0 ]]; then
	echo "FAIL pr-gate-policy-sync negative: invalid settings must not parse" >&2
	neg_fail=1
else
	echo "OK   pr-gate-policy-sync negative: invalid settings rejected"
fi

cat >"$neg_tmp/empty-contexts.yml" <<'EOF'
branch_protection_rules:
  - pattern: develop
    name: develop
    required_status_checks:
      strict: true
      contexts:
EOF

set +e
empty_out="$(extract_required_contexts "$neg_tmp/empty-contexts.yml" 2>/dev/null)"
empty_rc=$?
set -e
if [[ "$empty_rc" -ne 0 ]]; then
	echo "OK   pr-gate-policy-sync negative: empty contexts block rejected at parse"
elif [[ -z "${empty_out//[$'\t\n\r ']/}" ]]; then
	echo "OK   pr-gate-policy-sync negative: empty contexts output guarded"
else
	echo "FAIL pr-gate-policy-sync negative: empty contexts must not yield names" >&2
	neg_fail=1
fi

cat >"$neg_tmp/no-add-must.sh" <<'EOF'
#!/usr/bin/env bash
# gate stub without add_must/add_skip
filter=all
EOF
chmod +x "$neg_tmp/no-add-must.sh"

set +e
no_names="$(extract_gate_names "$neg_tmp/no-add-must.sh" 2>/dev/null)"
no_names_rc=$?
set -e
if [[ -z "${no_names//[$'\t\n\r ']/}" ]]; then
	echo "OK   pr-gate-policy-sync negative: gate without add_must/add_skip is empty"
else
	echo "FAIL pr-gate-policy-sync negative: gate without add_must/add_skip must be empty" >&2
	neg_fail=1
fi

if [[ "$neg_fail" -ne 0 ]]; then
	exit 1
fi

echo "OK   pr-gate-policy-sync (${#contexts[@]} ruleset contexts, ${#gate_names[@]} gate names)"
