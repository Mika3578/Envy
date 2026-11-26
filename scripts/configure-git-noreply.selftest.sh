#!/usr/bin/env bash
# Self-test for configure-git-noreply.sh.
#
# Stubs `gh` on PATH and runs the script with --local inside a temporary
# repository, so the caller's Git config is never touched. Covers gh error
# bodies, the literal "null", multi-line output, a valid login paired with a
# non-numeric id, and the interactive prompt fallback plus prompt refusal.
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
script="$script_dir/configure-git-noreply.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"

cat > "$tmp/bin/gh" <<'STUB'
#!/usr/bin/env bash
state="${FAKE_GH_STATE:?FAKE_GH_STATE must name a state file}"
n="$(cat "$state" 2>/dev/null || echo 0)"
n=$(( n + 1 ))
echo "$n" > "$state"
case "${FAKE_GH_MODE:-}" in
	ok)
		if [[ $n -eq 1 ]]; then echo "octocat"; else echo "583231"; fi ;;
	null)
		if [[ $n -eq 1 ]]; then echo "null"; else echo "null"; fi ;;
	error)
		echo '{"message":"Bad credentials"}' >&2
		exit 1 ;;
	multiline)
		if [[ $n -eq 1 ]]; then printf 'octocat\nextra\n'; else echo "583231"; fi ;;
	badid)
		if [[ $n -eq 1 ]]; then echo "octocat"; else echo "583231x"; fi ;;
	*)
		echo "unexpected stub mode" >&2
		exit 99 ;;
esac
STUB
chmod +x "$tmp/bin/gh"

# Runs the script in a fresh temporary repository. When input is non-empty it
# is fed as prompt answers; otherwise stdin is closed so a prompt fails.
run_in_repo() {
	local mode="$1"
	local input="$2"
	rm -rf "$tmp/repo"
	git init -q "$tmp/repo"
	echo 0 > "$tmp/state"
	(
		cd "$tmp/repo"
		export PATH="$tmp/bin:$PATH"
		export FAKE_GH_MODE="$mode"
		export FAKE_GH_STATE="$tmp/state"
		if [[ -n "$input" ]]; then
			printf '%s\n' "$input" | bash "$script" --local >/dev/null 2>&1
		else
			bash "$script" --local >/dev/null 2>&1 </dev/null
		fi
	)
}

expect_email() {
	[[ "$(git -C "$tmp/repo" config --local user.email)" == "$1" ]]
}

# gh returns a usable identity: no prompt, canonical noreply email configured.
run_in_repo ok ""
expect_email "583231+octocat@users.noreply.github.com"

# JSON error body, literal null, multi-line output and a non-numeric id all
# fall through to the prompt, which then configures the same identity.
for mode in error null multiline badid; do
	run_in_repo "$mode" $'octocat\n583231'
	expect_email "583231+octocat@users.noreply.github.com"
done

# A prompt answer that violates the login rules is refused.
if run_in_repo error $'bad--login!\n583231'; then
	echo "invalid prompt login was accepted" >&2
	exit 1
fi

echo "configure-git-noreply self-test passed."
