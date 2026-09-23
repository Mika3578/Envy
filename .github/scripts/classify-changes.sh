#!/usr/bin/env bash
# Classify pull-request paths into CI buckets.
#
# Outputs GitHub Actions flags (true/false) to $GITHUB_OUTPUT when set,
# otherwise prints them to stdout. Non-PR events force a full run.
#
# CodeQL (c-cpp / javascript-typescript / csharp) and Format Check always run
# on every PR via their own workflows/jobs — they are intentionally NOT gated
# here (avoids Code Scanning "configuration not found" and false-green format).
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
	write_out run_windows_build "$value"
	write_out run_remote_js "$value"
	write_out run_dep_review "$value"
	write_out run_docs_check "$value"
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
	# Fail closed: do not use process-substitution mapfile (masks gh api failure).
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
	write_out run_windows_build false
	write_out run_remote_js false
	write_out run_dep_review false
	write_out run_docs_check true
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

force_windows=false
force_remote=false
force_dep_review=false
force_all_pr=false

match_prefix() {
	local path="$1"
	local prefix="$2"
	[[ "$path" == "$prefix"* ]]
}

while IFS= read -r f; do
	[[ -z "$f" ]] && continue
	f="${f//\\//}"

	classified=false

	# Isolated crash-engine probe: not Envy.sln / not root vcpkg.json.
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
		force_windows=true
		classified=true
		;;
	.github/workflows/codeql.yml | .github/codeql/* | \
	.github/workflows/codeql-csharp.yml)
		workflow=true
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
	.github/workflows/pr-gate.yml | \
	.github/scripts/classify-changes.sh | \
	.github/scripts/pr-gate.sh | \
	.github/scripts/pr-gate-conclusions.sh)
		workflow=true
		force_all_pr=true
		classified=true
		;;
	.github/workflows/* | .github/actions/* | .github/scripts/* | \
	.github/settings.yml | .github/labeler.yml | .github/CODEOWNERS | \
	.github/dependabot.yml)
		workflow=true
		classified=true
		;;
	esac

	case "$f" in
	vcpkg.json | Remote/tests/package.json | Remote/tests/package-lock.json)
		dependencies=true
		build=true
		force_windows=true
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

	if [[ "$classified" == false ]]; then
		other=true
	fi
done <<<"$files"

if [[ "$force_all_pr" == true ]]; then
	force_windows=true
	force_dep_review=true
	force_remote=true
fi

run_windows_build=false
run_remote_js=false
run_dep_review=false
run_docs_check=false

if [[ "$cpp" == true || "$build" == true || "$force_windows" == true || "$other" == true ]]; then
	run_windows_build=true
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

docs_only=false
if [[ "$cpp" == false && "$build" == false && "$remote" == false && \
      "$csharp" == false && "$dependencies" == false && "$workflow" == false && \
      "$other" == false && "$docs" == true ]]; then
	docs_only=true
	run_windows_build=false
	run_remote_js=false
	run_dep_review=false
fi

echo "Changed files:"
echo "$files"
echo "cpp=$cpp build=$build remote=$remote csharp=$csharp dependencies=$dependencies docs=$docs workflow=$workflow other=$other docs_only=$docs_only"

write_out cpp "$cpp"
write_out build "$build"
write_out remote "$remote"
write_out csharp "$csharp"
write_out dependencies "$dependencies"
write_out docs "$docs"
write_out workflow "$workflow"
write_out docs_only "$docs_only"
write_out run_windows_build "$run_windows_build"
write_out run_remote_js "$run_remote_js"
write_out run_dep_review "$run_dep_review"
write_out run_docs_check "$run_docs_check"
