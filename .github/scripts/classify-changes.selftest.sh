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

# Unconsumed lane flags must not become Actions outputs (and are no longer
# emitted on stdout). risk_level stays stdout-only.
diagnostic_output=$(mktemp)
trap 'rm -f "$diagnostic_output"' EXIT
GITHUB_OUTPUT="$diagnostic_output" CLASSIFY_EVENT=pull_request CLASSIFY_FILES="$F_WORKFLOW" \
 bash .github/scripts/classify-changes.sh >/dev/null
if grep -Eq '^(run_x64_release|run_win32_release|run_windows_build|run_csharp_analysis|risk_level|needs_runtime_test)=' "$diagnostic_output"; then
	echo 'FAIL advisory diagnostics leaked into Actions outputs'
	fail=1
else
	echo 'OK   no-advisory-outputs'
fi

check docs-only "$F_DOCS" docs_only true
check docs-only-remote "$F_DOCS" run_remote_js false
check docs-only-deps "$F_DOCS" run_dep_review false
check docs-only-docs "$F_DOCS" run_docs_check true
check docs-risk-low "$F_DOCS" risk_level low

check cpp "$F_CPP" cpp true
check cpp-risk-high "$F_CPP" risk_level high
check normal-cpp "$F_CPP_NORMAL" risk_level normal
check remote "$F_REMOTE" run_remote_js true
check csharp-flag "$F_CSHARP" csharp true
check workflow-flag "$F_WORKFLOW" workflow true
check workflow-not-docs-only "$F_WORKFLOW" docs_only false
check deps "$F_VCPKG" run_dep_review true
check deps-build "$F_VCPKG" build true

readonly F_PROBE='tools/crash-probe/CrashProbe.cpp'
readonly F_PROBE_DOCS=$'tools/crash-probe/CrashProbe.cpp\ndocs/10_dev/crash-reporting.md'
readonly F_PROBE_ENVY=$'tools/crash-probe/CrashProbe.cpp\nEnvy/Envy.cpp'
check crash-probe-cpp "$F_PROBE" cpp false
check crash-probe-docs-only "$F_PROBE_DOCS" docs_only true
check crash-probe-envy "$F_PROBE_ENVY" cpp true
check interop-docs "$F_INTEROP" run_docs_check true
check interop-docs-only "$F_INTEROP" docs_only true

readonly F_INTEROP_WF='.github/workflows/ed2k-interop-harness.yml'
check interop-wf-docs-only "$F_INTEROP_WF" docs_only false
check interop-wf-remote "$F_INTEROP_WF" run_remote_js false

check ci-only-remote "$F_CI_ONLY" run_remote_js false
check ci-only-deps "$F_CI_ONLY" run_dep_review false
check ruleset-risk-high "$F_RULESET" risk_level high
readonly F_AGENTS='AGENTS.md'
check agents-not-docs-only "$F_AGENTS" docs_only false
check agents-risk-high "$F_AGENTS" risk_level high

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
# classify/audit-ruleset/pr-phase also force Remote JS + dep-review.
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
absent no-x64-diag "$F_CPP" run_x64_release
absent no-win32-diag "$F_CPP" run_win32_release
absent no-windows-diag "$F_CPP" run_windows_build
absent no-csharp-diag "$F_CPP" run_csharp_analysis
absent no-runtime-diag "$F_CPP" needs_runtime_test

got=$(GITHUB_OUTPUT= CLASSIFY_EVENT=push bash .github/scripts/classify-changes.sh | awk -F= '$1=="run_remote_js"{v=$2} END{print v}')
if [[ "$got" != "true" ]]; then echo "FAIL push run_remote_js=$got"; fail=1; else echo "OK   push-full"; fi
exit "$fail"
