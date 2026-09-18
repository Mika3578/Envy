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

# Docs-only: skip Windows/Remote/deps, but always emit CodeQL x3 + Format.
check docs-only $'docs/foo.md\nREADME.md' docs_only true
check docs-only-win $'docs/foo.md\nREADME.md' run_windows_build false
check docs-only-cpp $'docs/foo.md\nREADME.md' run_codeql_cpp true
check docs-only-js $'docs/foo.md\nREADME.md' run_codeql_js true
check docs-only-cs $'docs/foo.md\nREADME.md' run_codeql_csharp true
check docs-only-format $'docs/foo.md\nREADME.md' run_format true
check docs-only-remote $'docs/foo.md\nREADME.md' run_remote_js false

# C++ PR: Windows + Format + CodeQL x3 (no Remote unless Remote/ changes).
check cpp $'Envy/EDClient.cpp' run_windows_build true
check cpp-ql $'Envy/EDClient.cpp' run_codeql_cpp true
check cpp-cs $'Envy/EDClient.cpp' run_codeql_csharp true
check cpp-js $'Envy/EDClient.cpp' run_codeql_js true
check cpp-format $'Envy/EDClient.cpp' run_format true

# JS/Remote PR: Remote tests + CodeQL x3; no Windows build.
check remote $'Remote/script.js' run_remote_js true
check remote-win $'Remote/script.js' run_windows_build false
check remote-ql-cpp $'Remote/script.js' run_codeql_cpp true
check remote-ql-js $'Remote/script.js' run_codeql_js true
check remote-ql-cs $'Remote/script.js' run_codeql_csharp true

# C# PR: CodeQL x3 including csharp; no Windows Envy build.
check csharp $'Languages/Tools/SkinUpdater/Program.cs' run_codeql_csharp true
check csharp-win $'Languages/Tools/SkinUpdater/Program.cs' run_windows_build false
check csharp-ql-cpp $'Languages/Tools/SkinUpdater/Program.cs' run_codeql_cpp true
check csharp-ql-js $'Languages/Tools/SkinUpdater/Program.cs' run_codeql_js true

# Workflow-only PR: CodeQL x3 always.
check workflow $'.github/workflows/build.yml' run_codeql_cpp true
check workflow-js $'.github/workflows/build.yml' run_codeql_js true
check workflow-cs $'.github/workflows/build.yml' run_codeql_csharp true
check workflow-format $'.github/workflows/build.yml' run_format true

check deps $'vcpkg.json' run_dep_review true
check deps-win $'vcpkg.json' run_windows_build true

got=$(GITHUB_OUTPUT= CLASSIFY_EVENT=push bash .github/scripts/classify-changes.sh | awk -F= '$1=="run_windows_build"{v=$2} END{print v}')
if [ "$got" != "true" ]; then echo "FAIL push run_windows_build=$got"; fail=1; else echo "OK   push-full"; fi
exit "$fail"
