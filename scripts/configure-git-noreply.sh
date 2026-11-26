#!/usr/bin/env bash
# Configure a local GitHub noreply identity for this clone.
# Overwrites a non-noreply identity (including Cloud Agent defaults).
# Does not write personal mailboxes. Does not change global git config
# unless --global is passed explicitly.
set -euo pipefail

SCOPE="--local"
if [[ "${1:-}" == "--global" ]]; then
	SCOPE="--global"
	shift
fi

login=""
userid=""

# GitHub logins: alphanumerics and single interior hyphens, at most 39 chars.
login_is_valid() {
	[[ ${#1} -le 39 && "$1" =~ ^[A-Za-z0-9]+(-[A-Za-z0-9]+)*$ ]]
}

if command -v gh >/dev/null 2>&1; then
	login="$(gh api user --jq .login 2>/dev/null || true)"
	userid="$(gh api user --jq .id 2>/dev/null || true)"
	# gh failure output (JSON error bodies, "null") lands on stdout, so a
	# non-empty value is not proof of a usable identity. Only a login and id
	# in their canonical formats count; anything else falls through to the
	# interactive prompt below.
	if ! login_is_valid "$login" || [[ ! "$userid" =~ ^[0-9]+$ ]]; then
		login=""
		userid=""
	fi
fi

if [[ -z "$login" ]]; then
	printf 'GitHub login: '
	read -r login
fi
if [[ -z "$userid" ]]; then
	printf 'GitHub numeric user id (from https://api.github.com/users/%s): ' "$login"
	read -r userid
fi

if ! login_is_valid "$login"; then
	echo "Refusing invalid GitHub login." >&2
	exit 1
fi
if [[ ! "$userid" =~ ^[0-9]+$ ]]; then
	echo "Refusing invalid GitHub user id." >&2
	exit 1
fi

email="${userid}+${login}@users.noreply.github.com"

git config "$SCOPE" user.name "$login"
git config "$SCOPE" user.email "$email"
git config "$SCOPE" user.useConfigOnly true

echo "Configured $SCOPE git identity:"
echo "  user.name=$login"
echo "  user.email=${userid}+${login}@users.noreply.github.com"
echo "  user.useConfigOnly=true"
echo "Agents must not invent a different identity or add Co-authored-by trailers."
