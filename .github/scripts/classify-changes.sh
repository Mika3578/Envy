#!/usr/bin/env bash
# Classify pull-request paths into CI buckets and change risk.
#
# Exposes consumed GitHub Actions flags through $GITHUB_OUTPUT. Advisory lane
# and risk diagnostics remain stdout-only. Non-PR events force a full run.
#
# Required merge contexts must always be emitted by workflows (job runs with
# success no-op when a dimension is not applicable). Do not skip entire
# workflows with path filters when a context is required.
#
# Optional:
#   CLASSIFY_FILES   newline-separated path list (skips GitHub API)
#   CLASSIFY_EVENT   override github.event_name (default: $EVENT_NAME)
set -euo pipefail

EVENT_NAME="${CLASSIFY_EVENT:-${EVENT_NAME:-${GITHUB_EVENT_NAME:-}}}"

write_out() {
	local key="$1"
	local value="$2"
	printf '%s=%s\n' "$key" "$value"
	if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
		printf '%s=%s\n' "$key" "$value" >>"$GITHUB_OUTPUT"
	fi
}

write_diagnostic() {
	printf '%s=%s\n' "$1" "$2"
}

emit_all() {
	local value="$1"
	write_out cpp "$value"
	write_out build "$value"
	write_out remote "$value"
	write_out csharp "$value"
	write_out dependencies "$value"
	write_out docs "$value"
	write_out workflow "$value"
	write_out docs_only "false"
	write_diagnostic run_x64_release "$value"
	write_diagnostic run_win32_release "$value"
	write_diagnostic run_windows_build "$value"
	write_out run_remote_js "$value"
	write_out run_dep_review "$value"
	write_out run_docs_check "$value"
	write_diagnostic run_csharp_analysis "$value"
	write_diagnostic risk_level "high"
	write_diagnostic needs_runtime_test "$value"
}

if [[ "$EVENT_NAME" != "pull_request" ]]; then
	echo "Event '$EVENT_NAME' is not a pull_request; requesting full validation."
	emit_all true
	exit 0
fi

files=""
if [[ -n "${CLASSIFY_FILES:-}" ]]; then
	files="$CLASSIFY_FILES"
else
	if [[ -z "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]]; then
		echo "::error::GH_TOKEN is required to list pull request files."
		exit 1
	fi
	repo="${GITHUB_REPOSITORY:?}"
	pr="${PR_NUMBER:-${GITHUB_PR_NUMBER:-}}"
	if [[ -z "$pr" ]]; then
		echo "::error::PR number is missing."
		exit 1
	fi
	files="$(gh api --paginate "repos/${repo}/pulls/${pr}/files" --jq '.[].filename')"
fi

if [[ -z "${files//[$'\t\r\n ']/}" ]]; then
	echo "No files listed; treating as docs-only."
	write_out cpp false
	write_out build false
	write_out remote false
	write_out csharp false
	write_out dependencies false
	write_out docs true
	write_out workflow false
	write_out docs_only true
	write_diagnostic run_x64_release false
	write_diagnostic run_win32_release false
	write_diagnostic run_windows_build false
	write_out run_remote_js false
	write_out run_dep_review false
	write_out run_docs_check true
	write_diagnostic run_csharp_analysis false
	write_diagnostic risk_level low
	write_diagnostic needs_runtime_test false
	exit 0
fi

cpp=false
build=false
remote=false
csharp=false
dependencies=false
docs=false
workflow=false
other=false
risk_high=false
risk_low_only=true
needs_runtime=false

force_x64=false
force_win32=false
force_remote=false
force_dep_review=false
force_all_pr=false

match_prefix() {
	local path="$1"
	local prefix="$2"
	[[ "$path" == "$prefix"* ]]
}

is_high_risk_path() {
	local f="$1"
	case "$f" in
	AGENTS.md | MODERNIZATION.md)
		return 0
		;;
	.github/settings.yml | .github/CODEOWNERS | .github/dependabot.yml | \
	.github/scripts/classify-changes.sh | .github/scripts/audit-ruleset.py)
		return 0
		;;
	.github/copilot-instructions.md | .github/pull_request_template.md)
		return 0
		;;
	esac
	if match_prefix "$f" ".github/rulesets/" || \
	   match_prefix "$f" ".github/skills/" || \
	   match_prefix "$f" ".github/workflows/" || \
	   match_prefix "$f" "Installer/"; then
		return 0
	fi
	case "$f" in
	*Packet*.cpp | *Packet*.h | *PacketLength*.h | \
	*SecureRandom* | *RemotePassword* | *CryptLayer* | *Crypt*.cpp | *Crypt*.h)
		return 0
		;;
	esac
	if match_prefix "$f" "Remote/"; then
		return 0
	fi
	if match_prefix "$f" "Envy/ED" || \
	   match_prefix "$f" "Envy/Kad" || \
	   match_prefix "$f" "Envy/Kademlia" || \
	   match_prefix "$f" "Envy/BT" || \
	   match_prefix "$f" "Envy/DC" || \
	   match_prefix "$f" "Envy/G1" || \
	   match_prefix "$f" "Envy/G2" || \
	   match_prefix "$f" "Envy/Datagram"; then
		return 0
	fi
	return 1
}

is_low_risk_path() {
	local f="$1"
	case "$f" in
	*.md | *.markdown | *.rst | LICENSE | COPYING | ReadMe.txt | README* | \
	.gitignore | .gitattributes | .editorconfig | CHANGELOG.md)
		return 0
		;;
	esac
	if match_prefix "$f" "docs/" || \
	   match_prefix "$f" "Templates/" || \
	   match_prefix "$f" ".github/ISSUE_TEMPLATE/" || \
	   match_prefix "$f" "tools/interop/" || \
	   match_prefix "$f" ".cursor/" || \
	   match_prefix "$f" ".continue/" || \
	   [[ "$f" == .github/*.md ]]; then
		return 0
	fi
	if match_prefix "$f" "Languages/" && ! match_prefix "$f" "Languages/Tools/SkinUpdater/"; then
		return 0
	fi
	return 1
}

while IFS= read -r f; do
	[[ -z "$f" ]] && continue
	f="${f//\\//}"

	if is_high_risk_path "$f"; then
		risk_high=true
		risk_low_only=false
	fi
	if ! is_low_risk_path "$f"; then
		risk_low_only=false
	fi

	classified=false

	if match_prefix "$f" "tools/crash-probe/"; then
		classified=true
		continue
	fi

	case "$f" in
	.github/workflows/build.yml | \
	.github/workflows/release.yml | \
	.github/workflows/copilot-setup-steps.yml | \
	.github/actions/windows-msbuild/*)
		workflow=true
		build=true
		force_x64=true
		force_win32=true
		classified=true
		;;
	.github/workflows/codeql.yml | .github/codeql/*)
		workflow=true
		classified=true
		;;
	.github/workflows/codeql-csharp.yml)
		workflow=true
		csharp=true
		classified=true
		;;
	.github/workflows/code-quality.yml)
		workflow=true
		force_remote=true
		classified=true
		;;
	.github/workflows/format-check.yml | .clang-format | .clang-format-ignore | \
	.github/scripts/format-check.sh)
		workflow=true
		classified=true
		;;
	.github/workflows/dependency-review.yml | .github/dependabot.yml)
		workflow=true
		dependencies=true
		force_dep_review=true
		classified=true
		;;
	.github/workflows/security.yml)
		workflow=true
		classified=true
		;;
	.github/workflows/clang-tidy.yml | .clang-tidy)
		workflow=true
		classified=true
		;;
	.github/workflows/classify-changes.yml | \
	.github/scripts/classify-changes.sh | \
	.github/scripts/audit-ruleset.py | \
	.github/rulesets/*)
		workflow=true
		force_all_pr=true
		csharp=true
		classified=true
		;;
	.github/workflows/* | .github/actions/* | .github/scripts/* | \
	.github/settings.yml | .github/labeler.yml | .github/CODEOWNERS)
		workflow=true
		classified=true
		;;
	esac

	case "$f" in
	vcpkg.json | vcpkg-configuration.json)
		dependencies=true
		build=true
		force_x64=true
		force_win32=true
		force_dep_review=true
		classified=true
		;;
	*/package.json | */package-lock.json | */yarn.lock | */pnpm-lock.yaml | \
	package.json | package-lock.json)
		dependencies=true
		force_dep_review=true
		classified=true
		;;
	esac

	if match_prefix "$f" "Remote/"; then
		remote=true
		classified=true
	fi

	if match_prefix "$f" "Languages/Tools/SkinUpdater/" || [[ "$f" == *.cs || "$f" == *.csproj ]]; then
		csharp=true
		classified=true
	fi

	case "$f" in
	*.cpp | *.cxx | *.cc | *.c | *.h | *.hpp | *.hh | *.idl | *.rc | *.def)
		cpp=true
		classified=true
		;;
	*.vcxproj | *.vcxproj.filters | *.props | *.targets | CMakeLists.txt | CMakePresets.json)
		build=true
		cpp=true
		classified=true
		;;
	*.sln)
		if [[ "$f" == *SkinUpdater* ]]; then
			csharp=true
		else
			build=true
			cpp=true
		fi
		classified=true
		;;
	esac

	if match_prefix "$f" "Envy/" || \
	   match_prefix "$f" "TorrentEnvy/" || \
	   match_prefix "$f" "HashLib/" || \
	   match_prefix "$f" "tests/" || \
	   match_prefix "$f" "Plugins/" || \
	   match_prefix "$f" "Services/" || \
	   match_prefix "$f" "Unpacker/" || \
	   match_prefix "$f" "SkinBuilder/" || \
	   match_prefix "$f" "Installer/" || \
	   match_prefix "$f" "Visual Studio/" || \
	   match_prefix "$f" "cmake/"; then
		cpp=true
		build=true
		classified=true
	fi

	case "$f" in
	*.md | *.markdown | *.rst | LICENSE | COPYING | ReadMe.txt | README* | \
	.gitignore | .gitattributes | .editorconfig)
		docs=true
		classified=true
		;;
	esac
	if match_prefix "$f" "docs/" || \
	   match_prefix "$f" "Templates/" || \
	   match_prefix "$f" ".github/ISSUE_TEMPLATE/" || \
	   match_prefix "$f" "tools/interop/" || \
	   [[ "$f" == .github/*.md ]]; then
		docs=true
		classified=true
	fi

	if match_prefix "$f" "Languages/" && ! match_prefix "$f" "Languages/Tools/SkinUpdater/"; then
		docs=true
		classified=true
	fi

	if match_prefix "$f" "Installer/" || match_prefix "$f" "Skins/" || match_prefix "$f" "Envy/Page" || match_prefix "$f" "Envy/Dlg" || match_prefix "$f" "Envy/Ctrl"; then
		needs_runtime=true
	fi

	if [[ "$classified" == false ]]; then
		other=true
	fi
done <<<"$files"

if [[ "$force_all_pr" == true ]]; then
	force_x64=true
	force_win32=true
	force_dep_review=true
	force_remote=true
fi

run_x64=false
run_win32=false
run_remote_js=false
run_dep_review=false
run_docs_check=false
run_csharp=false

if [[ "$cpp" == true || "$build" == true || "$force_x64" == true || "$other" == true ]]; then
	run_x64=true
fi
if [[ "$cpp" == true || "$build" == true || "$force_win32" == true || "$other" == true ]]; then
	run_win32=true
fi
# Docs-only and Remote-only JS changes do not need Windows Release builds.
if [[ "$remote" == true && "$cpp" == false && "$build" == false && "$force_x64" == false && "$other" == false ]]; then
	run_x64=false
	run_win32=false
fi
if [[ "$force_remote" == true ]]; then
	run_remote_js=true
fi
if [[ "$remote" == true || "$force_remote" == true ]]; then
	run_remote_js=true
fi
if [[ "$dependencies" == true || "$force_dep_review" == true ]]; then
	run_dep_review=true
fi
if [[ "$docs" == true ]]; then
	run_docs_check=true
fi
if [[ "$csharp" == true ]]; then
	run_csharp=true
fi

docs_only=false
if [[ "$cpp" == false && "$build" == false && "$remote" == false && \
      "$csharp" == false && "$dependencies" == false && "$workflow" == false && \
      "$other" == false && "$docs" == true ]]; then
	docs_only=true
	run_x64=false
	run_win32=false
	run_remote_js=false
	run_dep_review=false
	run_csharp=false
fi

# Pure CI/workflow/metadata changes (no product sources): x64 smoke via lint job;
# skip expensive Win32 unless build/release paths changed.
if [[ "$workflow" == true && "$cpp" == false && "$build" == false && "$other" == false && "$docs_only" == false ]]; then
	if [[ "$force_win32" == false ]]; then
		run_win32=false
	fi
	if [[ "$force_x64" == false && "$force_win32" == false ]]; then
		run_x64=false
	fi
fi

risk_level=normal
if [[ "$risk_high" == true ]]; then
	risk_level=high
elif [[ "$risk_low_only" == true ]]; then
	risk_level=low
fi

# High-risk governance still requires maintainer review; runtime validation
# is requested separately by product-path classification above.

echo "Changed files:"
echo "$files"
echo "cpp=$cpp build=$build remote=$remote csharp=$csharp dependencies=$dependencies docs=$docs workflow=$workflow other=$other docs_only=$docs_only risk_level=$risk_level"

write_out cpp "$cpp"
write_out build "$build"
write_out remote "$remote"
write_out csharp "$csharp"
write_out dependencies "$dependencies"
write_out docs "$docs"
write_out workflow "$workflow"
write_out docs_only "$docs_only"
write_diagnostic run_x64_release "$run_x64"
write_diagnostic run_win32_release "$run_win32"
write_diagnostic run_windows_build "$run_x64"
write_out run_remote_js "$run_remote_js"
write_out run_dep_review "$run_dep_review"
write_out run_docs_check "$run_docs_check"
write_diagnostic run_csharp_analysis "$run_csharp"
write_diagnostic risk_level "$risk_level"
write_diagnostic needs_runtime_test "$needs_runtime"
