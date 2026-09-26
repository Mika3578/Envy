#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd -P)"
if command -v cygpath >/dev/null 2>&1; then
	ROOT="$(cygpath -u "$ROOT")"
fi
SCANNER="$ROOT/.github/scripts/check-agent-attribution.py"
run_scan() { "${PYTHON:-python3}" "$SCANNER" "$@"; }
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fx() { printf '%s@%s.%s' "$1" "$2" "$3"; }

git init -q "$TMP/repo"
cd "$TMP/repo"
git config user.email "ci@users.noreply.github.com"
git config user.name "CI"
git config commit.gpgsign false

echo one >file.txt
git add file.txt
git commit -q -m "feat: initial"
BASE=$(git rev-parse HEAD)

echo two >file.txt
git add file.txt
git commit -q -m "fix: technical subject"
HEAD=$(git rev-parse HEAD)

if ! run_scan --from "$BASE" --to "$HEAD"; then
	echo "FAIL: clean commits must pass"
	exit 1
fi

# Allowed: GitHub noreply author
git config user.email "58137747+tester@users.noreply.github.com"
echo noreply >file.txt
git add file.txt
git commit -q -m "fix: noreply author"
NOREPLY=$(git rev-parse HEAD)
if ! run_scan --from "$HEAD" --to "$NOREPLY"; then
	echo "FAIL: GitHub noreply author must pass"
	exit 1
fi

# Cursor Cloud Agent default identity is not an allowed git author.
git config user.email "cursoragent@cursor.com"
git config user.name "Cursor Agent"
echo agent >file.txt
git add file.txt
git commit -q -m "fix: agent author without trailer"
AGENT=$(git rev-parse HEAD)
if run_scan --from "$NOREPLY" --to "$AGENT"; then
	echo "FAIL: Cursor Agent author must be rejected"
	exit 1
fi

git config user.email "ci@users.noreply.github.com"
git config user.name "CI"

echo three >file.txt
git add file.txt
git commit -q -m "$(cat <<'EOF'
fix: bad trailer

Co-authored-by: Cursor Agent <cursoragent@cursor.com>
EOF
)"
BAD=$(git rev-parse HEAD)
if run_scan --from "$AGENT" --to "$BAD"; then
	echo "FAIL: Cursor Co-authored-by must be rejected"
	exit 1
fi

# Other AI-tool Co-authored-by trailers must be rejected even when the address
# is an allowlisted noreply mailbox.
echo ai-names >file.txt
git add file.txt
git commit -q -m "$(cat <<'EOF'
fix: other ai trailers

Co-authored-by: Gemini <58137747+tester@users.noreply.github.com>
Co-authored-by: Grok <58137747+tester@users.noreply.github.com>
Co-authored-by: Cubic <58137747+tester@users.noreply.github.com>
Co-authored-by: Sourcery <58137747+tester@users.noreply.github.com>
Co-authored-by: Amazon Q <123+tool@users.noreply.github.com>
Co-authored-by: Amazon Q Developer <123+tool@users.noreply.github.com>
Co-authored-by: amazon q <123+tool@users.noreply.github.com>
EOF
)"
AINAMES=$(git rev-parse HEAD)
if run_scan --from "$BAD" --to "$AINAMES"; then
	echo "FAIL: AI-tool Co-authored-by names must be rejected"
	exit 1
fi

# Personal Gmail in commit message
echo gmailmsg >file.txt
git add file.txt
git commit -q -m "fix: contact $(fx alice.test gmail com)"
GMAIL_MSG=$(git rev-parse HEAD)
if run_scan --from "$AINAMES" --to "$GMAIL_MSG"; then
	echo "FAIL: gmail in commit message must be rejected"
	exit 1
fi

# Hotmail / Outlook / Proton in Signed-off-by
echo sob >file.txt
git add file.txt
git commit -q -m "$(cat <<EOF
fix: signed off personal

Signed-off-by: Test User <$(fx bob.test hotmail com)>
EOF
)"
SOB=$(git rev-parse HEAD)
if run_scan --from "$GMAIL_MSG" --to "$SOB"; then
	echo "FAIL: hotmail Signed-off-by must be rejected"
	exit 1
fi

echo outlook >file.txt
git add file.txt
git commit -q -m "$(cat <<EOF
fix: reviewed personal

Reviewed-by: Test User <$(fx carol.test outlook com)>
EOF
)"
REV=$(git rev-parse HEAD)
if run_scan --from "$SOB" --to "$REV"; then
	echo "FAIL: outlook Reviewed-by must be rejected"
	exit 1
fi

echo proton >file.txt
git add file.txt
git commit -q -m "fix: proton $(fx dave.test proton me)"
PROTON=$(git rev-parse HEAD)
if run_scan --from "$REV" --to "$PROTON"; then
	echo "FAIL: proton address in message must be rejected"
	exit 1
fi

# Personal Gmail as author
git -c user.email="$(fx eve.test gmail com)" -c user.name="Eve" commit --allow-empty -q -m "fix: gmail author"
GMAIL_AUTH=$(git rev-parse HEAD)
if run_scan --from "$PROTON" --to "$GMAIL_AUTH"; then
	echo "FAIL: gmail author must be rejected"
	exit 1
fi

# Personal Hotmail as committer
git -c user.email="ci@users.noreply.github.com" -c user.name="CI" \
	-c committer.email="$(fx frank.test hotmail fr)" -c committer.name="Frank" \
	commit --allow-empty -q -m "fix: hotmail committer"
HOT_COMMITTER=$(git rev-parse HEAD)
if run_scan --from "$GMAIL_AUTH" --to "$HOT_COMMITTER"; then
	echo "FAIL: hotmail committer must be rejected"
	exit 1
fi

mkdir -p Envy docs
printf '// Reject truncated frames before reading the payload length.\nvoid f() {}\n' >Envy/a.cpp
git add Envy/a.cpp
git commit -q -m "fix: add technical comment"
GOODCPP=$(git rev-parse HEAD)
if ! run_scan --from "$HOT_COMMITTER" --to "$GOODCPP" --diff; then
	echo "FAIL: technical C++ comment must pass"
	exit 1
fi

printf 'void inc() {\n\t++counter;\n\t+++value;\n}\n' >Envy/inc.cpp
git add Envy/inc.cpp
git commit -q -m "fix: add prefix operators"
GOODPLUS=$(git rev-parse HEAD)
if ! run_scan --from "$GOODCPP" --to "$GOODPLUS" --diff; then
	echo "FAIL: real C++ lines beginning with ++ or +++ must pass"
	exit 1
fi

printf 'void inc_bad() {\n\t++counter; // Generated with Cursor\n}\n' >Envy/inc_bad.cpp
git add Envy/inc_bad.cpp
git commit -q -m "fix: generated signature after prefix operator"
BADPLUS=$(git rev-parse HEAD)
if run_scan --from "$GOODPLUS" --to "$BADPLUS" --diff; then
	echo "FAIL: signature on added line beginning with ++ must be rejected"
	exit 1
fi

printf '// Requested by Copilot review.\nvoid g() {}\n' >Envy/b.cpp
git add Envy/b.cpp
git commit -q -m "fix: process comment"
BADCPP=$(git rev-parse HEAD)
if run_scan --from "$BADPLUS" --to "$BADCPP" --diff; then
	echo "FAIL: process C++ comment must be rejected"
	exit 1
fi

printf '// Reject frames shorter than the fixed protocol header (see issue #298).\nvoid ok_ref() {}\n' >Envy/ref.cpp
git add Envy/ref.cpp
git commit -q -m "fix: technical comment with issue reference"
OKREF=$(git rev-parse HEAD)
if ! run_scan --from "$BADCPP" --to "$OKREF" --diff; then
	echo "FAIL: technical comment with issue reference must pass"
	exit 1
fi

printf 'const char* k = "%s";\n' "$(fx alice.test gmail com)" >Envy/mail.cpp
git add Envy/mail.cpp
git commit -q -m "fix: email in cpp"
CPPMAIL=$(git rev-parse HEAD)
if run_scan --from "$OKREF" --to "$CPPMAIL" --diff; then
	echo "FAIL: personal email in C++ line must be rejected"
	exit 1
fi

printf 'Contact %s\n' "$(fx alice.test gmail com)" >docs/note.md
git add docs/note.md
git commit -q -m "docs: email in markdown"
DOCMAIL=$(git rev-parse HEAD)
if run_scan --from "$OKREF" --to "$DOCMAIL" --diff; then
	echo "FAIL: personal email in documentation must be rejected"
	exit 1
fi

printf '// Generated with Cursor\nvoid h() {}\n' >Envy/gen.cpp
git add Envy/gen.cpp
git commit -q -m "fix: generated signature in cpp"
GENCPP=$(git rev-parse HEAD)
if run_scan --from "$DOCMAIL" --to "$GENCPP" --diff; then
	echo "FAIL: Generated with Cursor in added C++ must be rejected"
	exit 1
fi

printf 'Co-authored-by: Cursor Agent <58137747+tester@users.noreply.github.com>\n' >Envy/trailer.cpp
git add Envy/trailer.cpp
git commit -q -m "fix: ai trailer in diff"
AITRAILER=$(git rev-parse HEAD)
if run_scan --from "$GENCPP" --to "$AITRAILER" --diff; then
	echo "FAIL: AI Co-authored-by in added diff must be rejected"
	exit 1
fi

mkdir -p docs
printf 'Co-authored-by: Cursor Agent <58137747+tester@users.noreply.github.com>\n' >docs/check-agent-attribution.py
git add docs/check-agent-attribution.py
git commit -q -m "docs: scanner filename outside canonical path"
FAKECHECKER=$(git rev-parse HEAD)
if run_scan --from "$AITRAILER" --to "$FAKECHECKER" --diff; then
	echo "FAIL: scanner filename outside canonical path must not get exemptions"
	exit 1
fi

printf 'Fixes #123\nRelated to #99\nSee git@github.com:Mika3578/Envy.git\nmention @user without mail\n' >"$TMP/pr.md"
if ! run_scan --pr-body "$TMP/pr.md"; then
	echo "FAIL: issue refs, scp remotes, and @mentions must pass"
	exit 1
fi

printf 'Rejects AI-tool trailers and names the forbidden Generated with Cursor phrase in prose.\n' >"$TMP/pr-prose.md"
if ! run_scan --pr-body "$TMP/pr-prose.md"; then
	echo "FAIL: naming the forbidden phrase in policy prose must pass"
	exit 1
fi

printf 'Generated with Cursor\n' >"$TMP/pr-bad.md"
if run_scan --pr-body "$TMP/pr-bad.md"; then
	echo "FAIL: Generated with Cursor in PR body must be rejected"
	exit 1
fi

printf 'Generated with CodeRabbit\n' >"$TMP/pr-coderabbit.md"
if run_scan --pr-body "$TMP/pr-coderabbit.md"; then
	echo "FAIL: Generated with CodeRabbit in PR body must be rejected"
	exit 1
fi

printf '<!-- CURSOR_AGENT_PR_BODY_BEGIN -->\n' >"$TMP/pr-cursor-marker.md"
if run_scan --pr-body "$TMP/pr-cursor-marker.md"; then
	echo "FAIL: Cursor PR marker must be rejected"
	exit 1
fi

printf 'Generated with Cursor\n' >"$TMP/pr-agent-body.md"
if run_scan --pr-body "$TMP/pr-agent-body.md"; then
	echo "FAIL: agent-authored Generated with Cursor in PR body must be rejected"
	exit 1
fi

printf 'Contact %s about the bug\n' "$(fx me hotmail com)" >"$TMP/pr-mail.md"
if run_scan --pr-body "$TMP/pr-mail.md"; then
	echo "FAIL: personal email in PR body must be rejected"
	exit 1
fi

printf 'clone from https://%s/path.git\n' "$(fx alice.test gmail com)" >"$TMP/pr-url.md"
if ! run_scan --pr-body "$TMP/pr-url.md"; then
	echo "FAIL: URL userinfo must not be treated as email"
	exit 1
fi

printf 'just an @ symbol in a log line\n' >"$TMP/pr-at.md"
if ! run_scan --pr-body "$TMP/pr-at.md"; then
	echo "FAIL: lone @ must pass"
	exit 1
fi

printf 'ci(authorship): enforce repository privacy hygiene\n' >"$TMP/pr-title-good.md"
if ! run_scan --pr-title "$TMP/pr-title-good.md"; then
	echo "FAIL: technical PR title must pass"
	exit 1
fi

printf 'Contact alice@example.com for the upstream notice.\n' >"$TMP/pr-example.md"
if ! run_scan --pr-body "$TMP/pr-example.md"; then
	echo "FAIL: example.com address in PR body must pass"
	exit 1
fi

cat >"$TMP/pr-cubic-block.md" <<'EOF'
## Problem
Agent-assisted changes can accidentally expose personal data.

## Changes
- add authorship scanner

<!-- This is an auto-generated description by cubic. -->
## Summary by cubic
Automated summary text that mentions Cubic and https://cubic.dev/pr/example
<!-- End of auto-generated description by cubic. -->
EOF
if ! run_scan --pr-body "$TMP/pr-cubic-block.md"; then
	echo "FAIL: contributor PR body with Cubic auto-generated block must pass"
	exit 1
fi

"${PYTHON:-python3}" - "$ROOT/.github/scripts/check-agent-attribution.py" <<'PY'
import importlib.util
import sys
from pathlib import Path
path = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("authscan", path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
pages = '[{"body":"a"},{"body":"b"}][{"body":"c"}]'
items = mod.parse_paginated_json(pages, "test")
assert len(items) == 3, items
try:
    mod.parse_paginated_json('{"message":"bad credentials"}', "test")
except RuntimeError:
    pass
else:
    raise AssertionError("object page must fail closed")
print("parse_paginated_json ok")
PY

echo "check-agent-attribution.selftest passed"
