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
	if [[ "$got" != "$expect" ]]; then
		echo "FAIL $name: $key got='$got' want='$expect'"
		CLASSIFY_EVENT=pull_request CLASSIFY_FILES="$files" bash .github/scripts/classify-changes.sh
		fail=1
	else
		echo "OK   $name ($key=$got)"
	fi
}

readonly F_DOCS=$'docs/foo.md\nREADME.md'
readonly F_CPP='Envy/EDClient.cpp'
readonly F_CPP_NORMAL='Envy/Strings.cpp'
readonly F_REMOTE='Remote/script.js'
readonly F_CSHARP='Languages/Tools/SkinUpdater/Program.cs'
readonly F_WORKFLOW='.github/workflows/build.yml'
readonly F_CI_ONLY='.github/workflows/authorship-hygiene.yml'
readonly F_VCPKG='vcpkg.json'
readonly F_QUALITY='.github/workflows/code-quality.yml'
readonly F_CODEQL='.github/workflows/codeql.yml'
readonly F_INTEROP='tools/interop/run.py'
readonly F_RULESET='.github/rulesets/protect-develop.desired.json'

# Advisory diagnostics remain visible but cannot become disconnected Actions outputs.
diagnostic_output=$(mktemp)
trap 'rm -f "$diagnostic_output"' EXIT
GITHUB_OUTPUT="$diagnostic_output" CLASSIFY_EVENT=pull_request CLASSIFY_FILES="$F_WORKFLOW" \
 bash .github/scripts/classify-changes.sh >/dev/null
if grep -Eq '^(run_x64_release|run_win32_release|run_windows_build|run_csharp_analysis|risk_level|needs_runtime_test)=' "$diagnostic_output"; then
 echo 'FAIL advisory diagnostics leaked into Actions outputs'
 fail=1
fi

check docs-only "$F_DOCS" docs_only true
check docs-only-x64 "$F_DOCS" run_x64_release false
check docs-only-win32 "$F_DOCS" run_win32_release false
check docs-only-remote "$F_DOCS" run_remote_js false
check docs-only-docs "$F_DOCS" run_docs_check true
check docs-risk-low "$F_DOCS" risk_level low

check cpp "$F_CPP" run_x64_release true
check cpp-win32 "$F_CPP" run_win32_release true
check cpp-risk-high "$F_CPP" risk_level high
check normal-cpp "$F_CPP_NORMAL" risk_level normal
check remote "$F_REMOTE" run_remote_js true
check remote-win "$F_REMOTE" run_x64_release false
check csharp-win "$F_CSHARP" run_win32_release false
check csharp-analysis "$F_CSHARP" run_csharp_analysis true
check workflow-win "$F_WORKFLOW" run_win32_release true
check deps "$F_VCPKG" run_dep_review true
check deps-win "$F_VCPKG" run_win32_release true

readonly F_PROBE='tools/crash-probe/CrashProbe.cpp'
readonly F_PROBE_DOCS=$'tools/crash-probe/CrashProbe.cpp\ndocs/10_dev/crash-reporting.md'
readonly F_PROBE_ENVY=$'tools/crash-probe/CrashProbe.cpp\nEnvy/Envy.cpp'
check crash-probe-win "$F_PROBE" run_x64_release false
check crash-probe-cpp "$F_PROBE" cpp false
check crash-probe-docs "$F_PROBE_DOCS" run_x64_release false
check crash-probe-envy "$F_PROBE_ENVY" run_x64_release true
check interop-docs "$F_INTEROP" run_docs_check true
check interop-win "$F_INTEROP" run_x64_release false
check interop-docs-only "$F_INTEROP" docs_only true

readonly F_INTEROP_WF='.github/workflows/ed2k-interop-harness.yml'
check interop-wf-win "$F_INTEROP_WF" run_x64_release false
check interop-wf-docs-only "$F_INTEROP_WF" docs_only false

check ci-only-win32 "$F_CI_ONLY" run_win32_release false
check ci-only-x64 "$F_CI_ONLY" run_x64_release false
check ruleset-risk-high "$F_RULESET" risk_level high
readonly F_AGENTS='AGENTS.md'
check agents-not-docs-only "$F_AGENTS" docs_only false
check agents-risk-high "$F_AGENTS" risk_level high
check ruleset-runtime-separate "$F_RULESET" needs_runtime_test false
check workflow-runtime-separate "$F_WORKFLOW" needs_runtime_test false
check remote-js-runtime-separate "$F_REMOTE" needs_runtime_test false
check installer-runtime 'Installer/Envy.iss' needs_runtime_test true

check force-remote "$F_QUALITY" run_remote_js true
check codeql-config-remote "$F_CODEQL" run_remote_js false

for governance_file in \
	.github/scripts/classify-changes.sh \
	.github/scripts/audit-ruleset.py \
	.github/scripts/pr-phase.py \
	.github/scripts/format-check.sh
do
	check "governance-risk-${governance_file##*/}" "$governance_file" risk_level high
done
# classify/audit-ruleset/pr-phase also force full PR applicability (Remote + dep review).
for governance_file in \
	.github/scripts/classify-changes.sh \
	.github/scripts/audit-ruleset.py \
	.github/scripts/pr-phase.py \
	.github/workflows/pr-phase.yml
do
	check "governance-remote-${governance_file##*/}" "$governance_file" run_remote_js true
	check "governance-deps-${governance_file##*/}" "$governance_file" run_dep_review true
done

absent() {
	local name="$1"
	local files="$2"
	local key="$3"
	local out
	out="$(GITHUB_OUTPUT= CLASSIFY_EVENT=pull_request CLASSIFY_FILES="$files" bash .github/scripts/classify-changes.sh)"
	if grep -q "^${key}=" <<<"$out"; then
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

got=$(GITHUB_OUTPUT= CLASSIFY_EVENT=push bash .github/scripts/classify-changes.sh | awk -F= '$1=="run_x64_release"{v=$2} END{print v}')
if [[ "$got" != "true" ]]; then echo "FAIL push run_x64_release=$got"; fail=1; else echo "OK   push-full"; fi
exit "$fail"
