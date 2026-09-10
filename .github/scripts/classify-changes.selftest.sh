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
check docs-only $'docs/foo.md\nREADME.md' docs_only true
check docs-only-win $'docs/foo.md\nREADME.md' run_windows_build false
check docs-only-cpp $'docs/foo.md\nREADME.md' run_codeql_cpp false
check docs-only-js $'docs/foo.md\nREADME.md' run_codeql_js false
check docs-only-cs $'docs/foo.md\nREADME.md' run_codeql_csharp false
check docs-only-remote $'docs/foo.md\nREADME.md' run_remote_js false
check cpp $'Envy/EDClient.cpp' run_windows_build true
check cpp-ql $'Envy/EDClient.cpp' run_codeql_cpp true
check cpp-cs $'Envy/EDClient.cpp' run_codeql_csharp false
check cpp-js $'Envy/EDClient.cpp' run_codeql_js false
check remote $'Remote/script.js' run_remote_js true
check remote-win $'Remote/script.js' run_windows_build false
check csharp $'Languages/Tools/SkinUpdater/Program.cs' run_codeql_csharp true
check csharp-win $'Languages/Tools/SkinUpdater/Program.cs' run_windows_build false
check deps $'vcpkg.json' run_dep_review true
check deps-win $'vcpkg.json' run_windows_build true
got=$(GITHUB_OUTPUT= CLASSIFY_EVENT=push bash .github/scripts/classify-changes.sh | awk -F= '$1=="run_windows_build"{v=$2} END{print v}')
if [ "$got" != "true" ]; then echo "FAIL push run_windows_build=$got"; fail=1; else echo "OK   push-full"; fi
exit "$fail"
