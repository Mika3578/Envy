//
// BTTrackerLogRedaction.h
//
// Pure tracker-URL log-redaction helper (no network / MFC).
// Shared by the BitTorrent tracker request path and EnvyTests.
//
// BEP 27 (https://www.bittorrent.org/beps/bep_0027.html) private-tracker
// passkeys ride the announce query string; debug logs must never contain
// them. See also Envy/BTDiscoveryPolicy.h for the discovery gate.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <windows.h>
#include <cstddef>

// Length of a tracker URL with any query component removed, for logging.
// Passkeys ride the announce query string (e.g. ?passkey=...); logs must
// never contain them. Scheme, host and path stay visible for diagnosis.
// Path-embedded credentials cannot be detected generically.
inline size_t BtTrackerLogLength(const wchar_t* pszTracker)
{
	if ( pszTracker == NULL )
		return 0;

	size_t nLength = 0;
	while ( pszTracker[ nLength ] != 0 )
		++nLength;

	for ( size_t i = 0; i < nLength; ++i )
	{
		if ( pszTracker[ i ] == L'?' )
			return i;
	}

	return nLength;
}
