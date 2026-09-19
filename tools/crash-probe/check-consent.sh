#!/usr/bin/env bash
# Consent / privacy static checks for the isolated crash probe.
# Fails if an ingest host, upload URL, or Sentry transport feature sneaks in.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
probe="${root}/tools/crash-probe"
fail=0

die_match() {
	local label="$1"
	local file="$2"
	echo "FAIL ${label}: ${file}"
	fail=1
}

# Probe C++ must not embed an HTTP(S) ingest endpoint.
if grep -nE 'https?://|sentry\\.io|bugsplat\\.com|backtrace\\.io|saucelabs\\.com' "${probe}/CrashProbe.cpp"; then
	die_match "ingest-host-in-cpp" "${probe}/CrashProbe.cpp"
else
	echo "OK   CrashProbe.cpp has no ingest host / URL"
fi

if ! grep -q 'upload_url=' "${probe}/CrashProbe.cpp"; then
	echo "FAIL CrashProbe.cpp must print upload_url="
	fail=1
else
	echo "OK   CrashProbe.cpp prints upload_url"
fi

if ! grep -q 'uploads_enabled' "${probe}/CrashProbe.cpp"; then
	echo "FAIL CrashProbe.cpp must print uploads_enabled"
	fail=1
else
	echo "OK   CrashProbe.cpp prints uploads_enabled"
fi

# Sentry manifest: backend only, no default transport, no wer-on-static claim.
sentry_json="${probe}/vcpkg-sentry.json"
if ! command -v jq >/dev/null 2>&1; then
	echo "WARN jq not installed; skipping structured sentry manifest checks"
else
	features="$(jq -c '.dependencies[0].features' "${sentry_json}")"
	defaults="$(jq -c '.dependencies[0]["default-features"]' "${sentry_json}")"
	if [[ "${defaults}" != "false" ]]; then
		echo "FAIL sentry default-features must be false (got ${defaults})"
		fail=1
	else
		echo "OK   sentry default-features=false"
	fi
	if [[ "${features}" != '["backend"]' ]]; then
		echo "FAIL sentry features must be [\"backend\"] only (got ${features})"
		fail=1
	else
		echo "OK   sentry features=[backend]"
	fi
	if jq -e '.dependencies[0].features[] | select(. == "transport")' "${sentry_json}" >/dev/null; then
		echo "FAIL sentry features must not include transport"
		fail=1
	else
		echo "OK   sentry features omit transport"
	fi
	if ! jq -e '.dependencies[] | select(. == "crashpad")' "${probe}/vcpkg-crashpad.json" >/dev/null; then
		echo "FAIL crashpad manifest must depend on crashpad"
		fail=1
	else
		echo "OK   crashpad manifest depends on crashpad"
	fi
fi

if grep -Eq 'sentry-native|"crashpad"' "${root}/vcpkg.json"; then
	echo "FAIL root vcpkg.json lists a crash SDK (evaluation must stay isolated)"
	fail=1
else
	echo "OK   root vcpkg.json isolation"
fi

exit "${fail}"
