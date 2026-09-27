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
develop = re.search(
    r"(?ms)^\s*-\s*name:\s*develop\s*$.*?(?=^\s*-\s*name:\s|\Z)",
    text,
)
if not develop:
    raise SystemExit("could not locate develop branch protection block")
block = develop.group(0)
ctx_match = re.search(r"(?m)^(\s*)contexts:\s*$", block)
if not ctx_match:
    raise SystemExit("could not parse develop required_status_checks contexts")
list_indent = len(ctx_match.group(1)) + 2
contexts = []
for line in block[ctx_match.end() :].splitlines():
    if not line.strip():
        continue
    indent = len(line) - len(line.lstrip(" "))
    if indent < list_indent:
        break
    stripped = line.strip()
    if stripped.startswith("#"):
        continue
    if not stripped.startswith("- "):
        raise SystemExit(f"unexpected line in contexts list: {line!r}")
    value = stripped[2:].strip()
    if not value:
        raise SystemExit("empty context entry in contexts list")
    if value[0] == '"' and value[-1] == '"' and len(value) >= 2:
        value = value[1:-1]
    elif value[0] in "\"'":
        raise SystemExit(f"malformed quoted context entry: {line!r}")
    contexts.append(value)
if not contexts:
    raise SystemExit("develop contexts list was empty")
for name in contexts:
    print(name)
PY
}

extract_gate_names() {
	# Match executable add_must/add_skip only (not commented-out examples).
	grep -E '^[[:space:]]*add_(must|skip) "' "$1" | sed -E 's/.*"(.*)".*/\1/' | sort -u
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

cat >"$neg_tmp/mixed-contexts.yml" <<'EOF'
branches:
  - name: develop
    protection:
      required_status_checks:
        strict: true
        contexts:
          - "Quoted First"
          # inline comment must not truncate the list
          - Unquoted Second
          - "Quoted Third"
EOF

set +e
mixed_out="$(extract_required_contexts "$neg_tmp/mixed-contexts.yml" 2>/dev/null)"
mixed_rc=$?
set -e
if [[ "$mixed_rc" -eq 0 && "$mixed_out" == $'Quoted First\nUnquoted Second\nQuoted Third' ]]; then
	echo "OK   pr-gate-policy-sync negative: mixed contexts list parses completely"
else
	echo "FAIL pr-gate-policy-sync negative: mixed contexts must parse all entries (rc=$mixed_rc)" >&2
	neg_fail=1
fi

cat >"$neg_tmp/comment-only-add-must.sh" <<'EOF'
#!/usr/bin/env bash
# add_must "Ghost Check"
filter=all
add_must "Real Check"
EOF
chmod +x "$neg_tmp/comment-only-add-must.sh"

comment_names="$(extract_gate_names "$neg_tmp/comment-only-add-must.sh" 2>/dev/null || true)"
if [[ "$comment_names" == "Real Check" ]]; then
	echo "OK   pr-gate-policy-sync negative: commented add_must is ignored"
elif [[ "$comment_names" == *"Ghost Check"* ]]; then
	echo "FAIL pr-gate-policy-sync negative: commented add_must must not count as coverage" >&2
	neg_fail=1
else
	echo "FAIL pr-gate-policy-sync negative: unexpected gate name extraction: $comment_names" >&2
	neg_fail=1
fi

if [[ "$neg_fail" -ne 0 ]]; then
	exit 1
fi

echo "OK   pr-gate-policy-sync (${#contexts[@]} ruleset contexts, ${#gate_names[@]} gate names)"
