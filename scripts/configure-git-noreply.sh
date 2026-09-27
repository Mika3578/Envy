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

if command -v gh >/dev/null 2>&1; then
	login="$(gh api user --jq .login 2>/dev/null || true)"
	userid="$(gh api user --jq .id 2>/dev/null || true)"
	if [[ -z "$login" || -z "$userid" ]]; then
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

if [[ ! "$login" =~ ^[A-Za-z0-9-]+$ ]]; then
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
