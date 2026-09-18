#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
fail=0
check() {
	local name="$1"
	local files="$2"
	local key="$3"
	local expect="$4"
	local got
	got=$(GITHUB_OUTPUT= CLASSIFY_EVENT=pull_request CLASSIFY_FILES="$files" bash .github/scripts/classify-changes.sh | awk -F= -v k="$key" '$1==k {v=$2} END {print v}')
	if [ "$got" != "$expect" ]; then
		echo "FAIL $name: $key got='$got' want='$expect'"
		CLASSIFY_EVENT=pull_request CLASSIFY_FILES="$files" bash .github/scripts/classify-changes.sh
		fail=1
	else
		echo "OK   $name ($key=$got)"
	fi
}

readonly F_DOCS=$'docs/foo.md\nREADME.md'
readonly F_CPP='Envy/EDClient.cpp'
readonly F_REMOTE='Remote/script.js'
readonly F_CSHARP='Languages/Tools/SkinUpdater/Program.cs'
readonly F_WORKFLOW='.github/workflows/build.yml'
readonly F_VCPKG='vcpkg.json'

# Docs-only: path-aware skips Windows/Remote/deps. CodeQL/Format are not gated here.
check docs-only "$F_DOCS" docs_only true
check docs-only-win "$F_DOCS" run_windows_build false
check docs-only-remote "$F_DOCS" run_remote_js false
check docs-only-docs "$F_DOCS" run_docs_check true

check cpp "$F_CPP" run_windows_build true
check remote "$F_REMOTE" run_remote_js true
check remote-win "$F_REMOTE" run_windows_build false
check csharp-win "$F_CSHARP" run_windows_build false
check workflow-win "$F_WORKFLOW" run_windows_build true
check deps "$F_VCPKG" run_dep_review true
check deps-win "$F_VCPKG" run_windows_build true

# Dead CodeQL/Format classifier flags must be gone.
absent() {
	local name="$1"
	local files="$2"
	local key="$3"
	if GITHUB_OUTPUT= CLASSIFY_EVENT=pull_request CLASSIFY_FILES="$files" bash .github/scripts/classify-changes.sh | grep -q "^${key}="; then
		echo "FAIL $name: unexpected output key $key"
		fail=1
	else
		echo "OK   $name (no $key)"
	fi
}
absent no-ql-cpp "$F_CPP" run_codeql_cpp
absent no-ql-js "$F_CPP" run_codeql_js
absent no-ql-cs "$F_CPP" run_codeql_csharp
absent no-format "$F_CPP" run_format

got=$(GITHUB_OUTPUT= CLASSIFY_EVENT=push bash .github/scripts/classify-changes.sh | awk -F= '$1=="run_windows_build"{v=$2} END{print v}')
if [ "$got" != "true" ]; then echo "FAIL push run_windows_build=$got"; fail=1; else echo "OK   push-full"; fi
exit "$fail"
