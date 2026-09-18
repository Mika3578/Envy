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

# Fixture paths as constants (Sonar shelldre:S1192 — duplicated string literals).
readonly F_DOCS=$'docs/foo.md\nREADME.md'
readonly F_CPP='Envy/EDClient.cpp'
readonly F_REMOTE='Remote/script.js'
readonly F_CSHARP='Languages/Tools/SkinUpdater/Program.cs'
readonly F_WORKFLOW='.github/workflows/build.yml'
readonly F_VCPKG='vcpkg.json'

# Docs-only: skip Windows/Remote/deps, but always emit CodeQL x3 + Format.
check docs-only "$F_DOCS" docs_only true
check docs-only-win "$F_DOCS" run_windows_build false
check docs-only-cpp "$F_DOCS" run_codeql_cpp true
check docs-only-js "$F_DOCS" run_codeql_js true
check docs-only-cs "$F_DOCS" run_codeql_csharp true
check docs-only-format "$F_DOCS" run_format true
check docs-only-remote "$F_DOCS" run_remote_js false

# C++ PR: Windows + Format + CodeQL x3 (no Remote unless Remote/ changes).
check cpp "$F_CPP" run_windows_build true
check cpp-ql "$F_CPP" run_codeql_cpp true
check cpp-cs "$F_CPP" run_codeql_csharp true
check cpp-js "$F_CPP" run_codeql_js true
check cpp-format "$F_CPP" run_format true

# JS/Remote PR: Remote tests + CodeQL x3; no Windows build.
check remote "$F_REMOTE" run_remote_js true
check remote-win "$F_REMOTE" run_windows_build false
check remote-ql-cpp "$F_REMOTE" run_codeql_cpp true
check remote-ql-js "$F_REMOTE" run_codeql_js true
check remote-ql-cs "$F_REMOTE" run_codeql_csharp true

# C# PR: CodeQL x3 including csharp; no Windows Envy build.
check csharp "$F_CSHARP" run_codeql_csharp true
check csharp-win "$F_CSHARP" run_windows_build false
check csharp-ql-cpp "$F_CSHARP" run_codeql_cpp true
check csharp-ql-js "$F_CSHARP" run_codeql_js true

# Workflow-only PR: CodeQL x3 always.
check workflow "$F_WORKFLOW" run_codeql_cpp true
check workflow-js "$F_WORKFLOW" run_codeql_js true
check workflow-cs "$F_WORKFLOW" run_codeql_csharp true
check workflow-format "$F_WORKFLOW" run_format true

check deps "$F_VCPKG" run_dep_review true
check deps-win "$F_VCPKG" run_windows_build true

got=$(GITHUB_OUTPUT= CLASSIFY_EVENT=push bash .github/scripts/classify-changes.sh | awk -F= '$1=="run_windows_build"{v=$2} END{print v}')
if [ "$got" != "true" ]; then echo "FAIL push run_windows_build=$got"; fail=1; else echo "OK   push-full"; fi
exit "$fail"
