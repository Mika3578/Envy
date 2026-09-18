//
// DcPacketLengthValidate.h
//
// Pure NMDC/DC frame length predicates before "nLength - prefix - 1"
// arithmetic (trailing '|'). Shared by parsers and EnvyTests (#81).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <windows.h>

// "$HubTopic " prefix length including trailing space.
constexpr DWORD DC_HUBTOPIC_PREFIX_LEN = 10u;
// "$HubName " prefix length including trailing space.
constexpr DWORD DC_HUBNAME_PREFIX_LEN = 9u;

// Payload after a fixed ASCII prefix, excluding the mandatory trailing '|'.
// Reject before callers compute nLength - nPrefix - 1.
inline BOOL DcPrefixedPayloadLengthOk(DWORD nLength, DWORD nPrefix)
{
	return nLength >= nPrefix + 1;
}

inline DWORD DcPrefixedPayloadBytes(DWORD nLength, DWORD nPrefix)
{
	return nLength - nPrefix - 1;
}

// Public chat "<nick> message|" — UTF8Decode from offset 1 excluding '|'.
inline BOOL DcChatAnglePayloadLengthOk(DWORD nLength)
{
	return nLength >= 2;
}

inline DWORD DcChatAnglePayloadBytes(DWORD nLength)
{
	return nLength - 2;
}

// HubName description after "Title " split: bytes from after the space to
// before the trailing '|' require nLength >= nSpaceIndex + 2.
inline BOOL DcHubNameDescriptionLengthOk(DWORD nLength, int nSpaceIndex)
{
	if ( nSpaceIndex < 0 )
		return FALSE;
	return nLength >= static_cast< DWORD >( nSpaceIndex ) + 2u;
}

inline DWORD DcHubNameDescriptionBytes(DWORD nLength, int nSpaceIndex)
{
	return nLength - static_cast< DWORD >( nSpaceIndex ) - 2u;
}
