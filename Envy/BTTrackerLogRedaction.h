//
// BTTrackerLogRedaction.h
//
// Pure tracker-URL log-redaction helper (no network / MFC / Win32).
// Shared by the BitTorrent tracker request path and EnvyTests.
//
// BEP 27 (https://www.bittorrent.org/beps/bep_0027.html) private-tracker
// passkeys reach logs through tracker URLs; debug logs must never contain
// them. See also Envy/BTDiscoveryPolicy.h for the discovery gate.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <cstddef>

// Length of the log-safe prefix of a tracker URL: the scheme and host
// (with port), with any path or query removed. Passkeys ride announce
// query strings and some private trackers embed them in the path; a
// credential segment cannot be told apart from ordinary path structure,
// so nothing after the host is logged. Userinfo credentials (user:pass@
// before the host) are not produced by tracker announce URLs and are not
// handled here.
inline size_t BtTrackerLogLength(const wchar_t* pszTracker)
{
	if (pszTracker == nullptr)
		return 0;

	// The authority starts after the "://" scheme separator; without a
	// scheme the whole string is treated as host material.
	size_t nStart = 0;
	for (size_t i = 0; pszTracker[i] != 0; ++i)
	{
		if (pszTracker[i] == L':' && pszTracker[i + 1] == L'/' &&
		    pszTracker[i + 2] == L'/')
		{
			nStart = i + 3;
			break;
		}
		if (pszTracker[i] == L'/' || pszTracker[i] == L'?')
			break;
	}

	for (size_t i = nStart; pszTracker[i] != 0; ++i)
	{
		if (pszTracker[i] == L'/' || pszTracker[i] == L'?')
			return i;
	}

	size_t nLength = nStart;
	while (pszTracker[nLength] != 0)
		++nLength;
	return nLength;
}
