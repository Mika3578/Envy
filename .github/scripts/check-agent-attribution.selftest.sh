#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd -P)"
if command -v cygpath >/dev/null 2>&1; then
	ROOT="$(cygpath -u "$ROOT")"
fi
SCANNER="$ROOT/.github/scripts/check-agent-attribution.py"
run_scan() { "${PYTHON:-python3}" "$SCANNER" "$@"; }
# Capture stderr; exit 0 with WARN lines counts as warn-only.
run_scan_capture() {
	local ec=0
	set +e
	SCAN_OUT="$(run_scan "$@" 2>&1)"
	ec=$?
	set -e
	return "$ec"
}
expect_pass() {
	local label="$1"
	shift
	if ! run_scan_capture "$@"; then
		echo "FAIL: $label (expected PASS)"
		echo "$SCAN_OUT"
		exit 1
	fi
	if printf '%s\n' "$SCAN_OUT" | grep -q '^FAIL:'; then
		echo "FAIL: $label unexpectedly reported FAIL findings"
		echo "$SCAN_OUT"
		exit 1
	fi
	if printf '%s\n' "$SCAN_OUT" | grep -q '^WARN:'; then
		echo "FAIL: $label unexpectedly reported WARN findings"
		echo "$SCAN_OUT"
		exit 1
	fi
}
expect_warn() {
	local label="$1"
	shift
	if ! run_scan_capture "$@"; then
		echo "FAIL: $label (expected WARN-only, got FAIL exit)"
		echo "$SCAN_OUT"
		exit 1
	fi
	if ! printf '%s\n' "$SCAN_OUT" | grep -q '^WARN:'; then
		echo "FAIL: $label expected WARN findings"
		echo "$SCAN_OUT"
		exit 1
	fi
	if printf '%s\n' "$SCAN_OUT" | grep -q '^FAIL:'; then
		echo "FAIL: $label unexpectedly reported FAIL findings"
		echo "$SCAN_OUT"
		exit 1
	fi
}
expect_fail() {
	local label="$1"
	shift
	if run_scan_capture "$@"; then
		echo "FAIL: $label (expected FAIL exit)"
		echo "$SCAN_OUT"
		exit 1
	fi
	if ! printf '%s\n' "$SCAN_OUT" | grep -q '^FAIL:'; then
		echo "FAIL: $label expected FAIL findings"
		echo "$SCAN_OUT"
		exit 1
	fi
}
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fx() { printf '%s@%s.%s' "$1" "$2" "$3"; }

git init -q "$TMP/repo"
cd "$TMP/repo"
git config user.email "ci@users.noreply.github.com"
git config user.name "CI"
git config commit.gpgsign false
git config core.autocrlf false

echo one >file.txt
git add file.txt
git commit -q -m "feat: initial"
BASE=$(git rev-parse HEAD)

echo two >file.txt
git add file.txt
git commit -q -m "fix: technical subject"
HEAD=$(git rev-parse HEAD)

expect_pass "clean commits" --from "$BASE" --to "$HEAD"

# Allowed: GitHub noreply author
git config user.email "58137747+tester@users.noreply.github.com"
echo noreply >file.txt
git add file.txt
git commit -q -m "fix: noreply author"
NOREPLY=$(git rev-parse HEAD)
expect_pass "GitHub noreply author" --from "$HEAD" --to "$NOREPLY"

# Cursor runner without GitHub verification meta → WARN (not FAIL).
git config user.email "cursoragent@cursor.com"
git config user.name "Cursor Agent"
echo agent >file.txt
git add file.txt
git commit -q -m "fix: agent author without trailer"
AGENT=$(git rev-parse HEAD)
expect_warn "Cursor Agent without provenance" --from "$NOREPLY" --to "$AGENT"

# Same identity with verified GitHub meta → PASS.
printf '{"%s":{"author_login":"cursoragent","author_type":"User","verified":true,"reason":"valid"}}\n' "$AGENT" >"$TMP/agent-verified.json"
expect_pass "verified Cursor Agent" --from "$NOREPLY" --to "$AGENT" --commit-meta "$TMP/agent-verified.json"

git config user.email "ci@users.noreply.github.com"
git config user.name "CI"

# Trusted GitHub App bot noreply (PR #351 / CodeRabbit shape) → PASS.
git -c user.name="coderabbitai[bot]" \
	-c user.email="136622811+coderabbitai[bot]@users.noreply.github.com" \
	commit --allow-empty -q -m "fix: coderabbit automation"
CODERABBIT=$(git rev-parse HEAD)
expect_pass "trusted CodeRabbit bot noreply" --from "$AGENT" --to "$CODERABBIT"
printf '{"%s":{"author_login":"coderabbitai[bot]","author_type":"Bot","verified":false,"reason":"unsigned"}}\n' "$CODERABBIT" >"$TMP/cr-unsigned.json"
expect_warn "unsigned CodeRabbit with GitHub meta" --from "$AGENT" --to "$CODERABBIT" \
	--commit-meta "$TMP/cr-unsigned.json"

# Impersonation: bot display name with mismatched noreply login → FAIL.
git -c user.name="coderabbitai[bot]" \
	-c user.email="999999+evil-bot[bot]@users.noreply.github.com" \
	commit --allow-empty -q -m "fix: spoofed bot"
SPOOF_BOT=$(git rev-parse HEAD)
expect_fail "spoofed bot noreply mismatch" --from "$CODERABBIT" --to "$SPOOF_BOT"

# Impersonation: bot name on a human noreply → FAIL.
git -c user.name="coderabbitai[bot]" \
	-c user.email="58137747+tester@users.noreply.github.com" \
	commit --allow-empty -q -m "fix: bot name on human noreply"
SPOOF_HUMAN=$(git rev-parse HEAD)
expect_fail "bot name on human noreply" --from "$SPOOF_BOT" --to "$SPOOF_HUMAN"

echo three >file.txt
git add file.txt
git commit -q -m "$(cat <<'EOF'
fix: bad trailer

Co-authored-by: Cursor Agent <cursoragent@cursor.com>
EOF
)"
BAD=$(git rev-parse HEAD)
expect_warn "Cursor Co-authored-by trailer" --from "$SPOOF_HUMAN" --to "$BAD"

# Other AI-tool Co-authored-by trailers are editorial WARN.
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
expect_warn "AI-tool Co-authored-by names" --from "$BAD" --to "$AINAMES"

# Personal Gmail in commit message
echo gmailmsg >file.txt
git add file.txt
git commit -q -m "fix: contact $(fx alice.test gmail com)"
GMAIL_MSG=$(git rev-parse HEAD)
expect_fail "gmail in commit message" --from "$AINAMES" --to "$GMAIL_MSG"

# Hotmail / Outlook / Proton in Signed-off-by
echo sob >file.txt
git add file.txt
git commit -q -m "$(cat <<EOF
fix: signed off personal

Signed-off-by: Test User <$(fx bob.test hotmail com)>
EOF
)"
SOB=$(git rev-parse HEAD)
expect_fail "hotmail Signed-off-by" --from "$GMAIL_MSG" --to "$SOB"

echo outlook >file.txt
git add file.txt
git commit -q -m "$(cat <<EOF
fix: reviewed personal

Reviewed-by: Test User <$(fx carol.test outlook com)>
EOF
)"
REV=$(git rev-parse HEAD)
expect_fail "outlook Reviewed-by" --from "$SOB" --to "$REV"

echo proton >file.txt
git add file.txt
git commit -q -m "fix: proton $(fx dave.test proton me)"
PROTON=$(git rev-parse HEAD)
expect_fail "proton address in message" --from "$REV" --to "$PROTON"

# Personal Gmail as author
git -c user.email="$(fx eve.test gmail com)" -c user.name="Eve" commit --allow-empty -q -m "fix: gmail author"
GMAIL_AUTH=$(git rev-parse HEAD)
expect_fail "gmail author" --from "$PROTON" --to "$GMAIL_AUTH"

# Personal Hotmail as committer
git -c user.email="ci@users.noreply.github.com" -c user.name="CI" \
	-c committer.email="$(fx frank.test hotmail fr)" -c committer.name="Frank" \
	commit --allow-empty -q -m "fix: hotmail committer"
HOT_COMMITTER=$(git rev-parse HEAD)
expect_fail "hotmail committer" --from "$GMAIL_AUTH" --to "$HOT_COMMITTER"

mkdir -p Envy docs
printf '// Reject truncated frames before reading the payload length.\nvoid f() {}\n' >Envy/a.cpp
git add Envy/a.cpp
git commit -q -m "fix: add technical comment"
GOODCPP=$(git rev-parse HEAD)
expect_pass "technical C++ comment" --from "$HOT_COMMITTER" --to "$GOODCPP" --diff

printf 'void inc() {\n\t++counter;\n\t+++value;\n}\n' >Envy/inc.cpp
git add Envy/inc.cpp
git commit -q -m "fix: add prefix operators"
GOODPLUS=$(git rev-parse HEAD)
expect_pass "C++ lines beginning with ++ or +++" --from "$GOODCPP" --to "$GOODPLUS" --diff

printf 'void inc_bad() {\n\t++counter; // Generated with Cursor\n}\n' >Envy/inc_bad.cpp
git add Envy/inc_bad.cpp
git commit -q -m "fix: generated signature after prefix operator"
BADPLUS=$(git rev-parse HEAD)
expect_warn "signature on added line beginning with ++" --from "$GOODPLUS" --to "$BADPLUS" --diff

printf '// Requested by Copilot review.\nvoid g() {}\n' >Envy/b.cpp
git add Envy/b.cpp
git commit -q -m "fix: process comment"
BADCPP=$(git rev-parse HEAD)
expect_warn "process C++ comment" --from "$BADPLUS" --to "$BADCPP" --diff

printf '// Reject frames shorter than the fixed protocol header (see issue #298).\nvoid ok_ref() {}\n' >Envy/ref.cpp
git add Envy/ref.cpp
git commit -q -m "fix: technical comment with issue reference"
OKREF=$(git rev-parse HEAD)
expect_pass "technical comment with issue reference" --from "$BADCPP" --to "$OKREF" --diff

printf 'const char* k = "%s";\n' "$(fx alice.test gmail com)" >Envy/mail.cpp
git add Envy/mail.cpp
git commit -q -m "fix: email in cpp"
CPPMAIL=$(git rev-parse HEAD)
expect_fail "personal email in C++ line" --from "$OKREF" --to "$CPPMAIL" --diff

printf 'Contact %s\n' "$(fx alice.test gmail com)" >docs/note.md
git add docs/note.md
git commit -q -m "docs: email in markdown"
DOCMAIL=$(git rev-parse HEAD)
expect_fail "personal email in documentation" --from "$CPPMAIL" --to "$DOCMAIL" --diff

printf '// Generated with Cursor\nvoid h() {}\n' >Envy/gen.cpp
git add Envy/gen.cpp
git commit -q -m "fix: generated signature in cpp"
GENCPP=$(git rev-parse HEAD)
expect_warn "Generated with Cursor in added C++" --from "$DOCMAIL" --to "$GENCPP" --diff

printf 'Co-authored-by: Cursor Agent <58137747+tester@users.noreply.github.com>\n' >Envy/trailer.cpp
git add Envy/trailer.cpp
git commit -q -m "fix: ai trailer in diff"
AITRAILER=$(git rev-parse HEAD)
expect_warn "AI Co-authored-by in added diff" --from "$GENCPP" --to "$AITRAILER" --diff

mkdir -p docs
printf 'Co-authored-by: Cursor Agent <58137747+tester@users.noreply.github.com>\n' >docs/check-agent-attribution.py
git add docs/check-agent-attribution.py
git commit -q -m "docs: scanner filename outside canonical path"
FAKECHECKER=$(git rev-parse HEAD)
expect_warn "scanner filename outside canonical path still warns" --from "$AITRAILER" --to "$FAKECHECKER" --diff

printf 'Fixes #123\nRelated to #99\nSee git@github.com:Mika3578/Envy.git\nmention @user without mail\n' >"$TMP/pr.md"
expect_pass "issue refs, scp remotes, and @mentions" --pr-body "$TMP/pr.md"

printf 'Docs may describe Cursor, Copilot, CodeRabbit, and Codex review tooling.\n' >"$TMP/pr-docs-tools.md"
expect_pass "technical tool names in documentation prose" --pr-body "$TMP/pr-docs-tools.md"

printf 'Rejects AI-tool trailers and names the forbidden Generated with Cursor phrase in prose.\n' >"$TMP/pr-prose.md"
expect_pass "naming the forbidden phrase in policy prose" --pr-body "$TMP/pr-prose.md"

printf 'Generated with Cursor\n' >"$TMP/pr-bad.md"
expect_warn "Generated with Cursor in PR body" --pr-body "$TMP/pr-bad.md"

printf 'Generated with CodeRabbit\n' >"$TMP/pr-coderabbit.md"
expect_warn "Generated with CodeRabbit in PR body" --pr-body "$TMP/pr-coderabbit.md"

printf '<!-- CURSOR_AGENT_PR_BODY_BEGIN -->\n' >"$TMP/pr-cursor-marker.md"
expect_warn "Cursor PR marker" --pr-body "$TMP/pr-cursor-marker.md"

printf 'Contact %s about the bug\n' "$(fx me hotmail com)" >"$TMP/pr-mail.md"
expect_fail "personal email in PR body" --pr-body "$TMP/pr-mail.md"

printf 'clone from https://%s/path.git\n' "$(fx alice.test gmail com)" >"$TMP/pr-url.md"
expect_pass "URL userinfo must not be treated as email" --pr-body "$TMP/pr-url.md"

printf 'just an @ symbol in a log line\n' >"$TMP/pr-at.md"
expect_pass "lone @" --pr-body "$TMP/pr-at.md"

printf 'ci(authorship): enforce repository privacy hygiene\n' >"$TMP/pr-title-good.md"
expect_pass "technical PR title" --pr-title "$TMP/pr-title-good.md"

printf 'fix(ci): correct Copilot review classification\n' >"$TMP/pr-title-copilot.md"
expect_pass "technical Copilot mention in PR title" --pr-title "$TMP/pr-title-copilot.md"

printf 'feat: Cursor Agent update\n' >"$TMP/pr-title-tool.md"
expect_pass "tool name alone in PR title" --pr-title "$TMP/pr-title-tool.md"

printf 'Generated with Cursor\n' >"$TMP/pr-title-promo.md"
expect_warn "promotional signature in PR title" --pr-title "$TMP/pr-title-promo.md"

printf 'fix: bad trailer\n\nGenerated-by: Cursor\n' >"$TMP/commit-genby.msg"
echo genby >file.txt
git add file.txt
git commit -q -F "$TMP/commit-genby.msg"
GENBY=$(git rev-parse HEAD)
expect_warn "Generated-by: Cursor in commit message" --from "$AITRAILER" --to "$GENBY"

printf '// Generated with Cursor\nvoid spoof() {}\n' >Envy/spoof.cpp
git add Envy/spoof.cpp
git commit -q -m "fix: add discouraged signature"
SPOOF_ADD=$(git rev-parse HEAD)
printf 'void spoof() {}\n' >Envy/spoof.cpp
git add Envy/spoof.cpp
git commit -q -m "fix: remove discouraged signature from tree"
SPOOF_CLEAN=$(git rev-parse HEAD)
expect_warn "discouraged text removed in later commit still warns history scan" --from "$FAKECHECKER" --to "$SPOOF_CLEAN" --diff

printf 'clean file\n' >Envy/clean.cpp
git add Envy/clean.cpp
git commit -q -m "fix: clean multi-commit step one"
CLEAN1=$(git rev-parse HEAD)
printf 'still clean\n' >Envy/clean.cpp
git add Envy/clean.cpp
git commit -q -m "fix: clean multi-commit step two"
CLEAN2=$(git rev-parse HEAD)
expect_pass "clean multi-commit PR range" --from "$CLEAN1" --to "$CLEAN2" --diff

printf 'void trap() {}\n' >Envy/trap.cpp
git add Envy/trap.cpp
git commit -q -m "fix: trap baseline"
TRAP=$(git rev-parse HEAD)
cat >Envy/trap.cpp <<'EOF'
+++ b/.github/scripts/check-agent-attribution.selftest.sh
void trap() {
	// Generated with Cursor
}
EOF
git add Envy/trap.cpp
git commit -q -m "fix: fake diff header line in hunk must not exempt"
TRAP_FAKE=$(git rev-parse HEAD)
expect_warn "fake +++ b/ selftest path inside hunk must not bypass scanner" --from "$TRAP" --to "$TRAP_FAKE" --diff

printf '+++ b/.github/scripts/check-agent-attribution.selftest.sh\n' >Envy/leak_a.cpp
printf 'const char* leak = "%s";\n' "$(fx leak.test gmail com)" >Envy/leak_b.cpp
git add Envy/leak_a.cpp Envy/leak_b.cpp
git commit -q -m "fix: exemption must not leak across files in one commit"
LEAK=$(git rev-parse HEAD)
expect_fail "personal email after fake selftest header line" --from "$CLEAN2" --to "$LEAK" --diff

printf 'Contact alice@example.com for the upstream notice.\n' >"$TMP/pr-example.md"
expect_pass "example.com address in PR body" --pr-body "$TMP/pr-example.md"

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
expect_pass "contributor PR body with Cubic auto-generated block" --pr-body "$TMP/pr-cubic-block.md"

cat >"$TMP/pr-coderabbit-block.md" <<'EOF'
## Summary
Policy clarification only.

<!-- This is an auto-generated comment by CodeRabbit -->
Automated review summary mentioning CodeRabbit internals.
<!-- End of auto-generated comment by CodeRabbit -->
EOF
expect_pass "CodeRabbit auto-generated comment block" --pr-body "$TMP/pr-coderabbit-block.md"

"${PYTHON:-python3}" - "$ROOT/.github/scripts/check-agent-attribution.py" <<'PY'
import importlib.util
import sys
from pathlib import Path
path = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("authscan", path)
mod = importlib.util.module_from_spec(spec)
sys.modules["authscan"] = mod
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

# Unit classification regressions from historical PR failures.
assert mod.classify_identity(
    "coderabbitai[bot]",
    "136622811+coderabbitai[bot]@users.noreply.github.com",
) == []
assert any(s == mod.SEVERITY_WARN for s, _ in mod.classify_identity(
    "Cursor Agent",
    "cursoragent@cursor.com",
))
assert mod.classify_identity(
    "Cursor Agent",
    "cursoragent@cursor.com",
    meta=mod.CommitGithubMeta(author_login="cursoragent", author_type="User", verified=True, reason="valid"),
) == []
assert any(s == mod.SEVERITY_FAIL for s, _ in mod.classify_identity(
    "coderabbitai[bot]",
    "58137747+tester@users.noreply.github.com",
))
assert mod.classify_signature(mod.CommitGithubMeta(verified=True, reason="valid")) is None
assert mod.classify_signature(mod.CommitGithubMeta(verified=False, reason="unsigned"))[0] == mod.SEVERITY_WARN
print("classification helpers ok")
PY

# Injection regressions: malformed git refs and paths must fail closed.
expect_fail "shell metacharacters in --to" --from "$BASE" --to "HEAD;echo pwned"
expect_fail "traversal in --from" --from "../../../etc/passwd" --to "$HEAD"
echo 'ok' >"$TMP/safe-body.md"
mkdir -p "$TMP/nested"
expect_pass "temp PR body path" --pr-body "$TMP/safe-body.md"
expect_fail ".. in pr-body path" --pr-body "$TMP/nested/../safe-body.md"

"${PYTHON:-python3}" - "$ROOT/.github/scripts/check-agent-attribution.py" <<'PY'
import importlib.util
import sys
from pathlib import Path
path = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("authscan2", path)
mod = importlib.util.module_from_spec(spec)
sys.modules["authscan2"] = mod
spec.loader.exec_module(mod)
try:
    mod.gh_api_list("repos/evil/owner;rm -rf/pulls/1/comments")
except ValueError:
    pass
else:
    raise AssertionError("malformed gh api path must be rejected")
try:
    mod.gh_api_json("repos/evil/x/commits/not-a-sha")
except ValueError:
    pass
else:
    raise AssertionError("malformed commit api path must be rejected")
print("gh_api validation ok")
PY

echo "check-agent-attribution.selftest passed"
