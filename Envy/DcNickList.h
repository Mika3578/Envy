//
// DcNickList.h
//
// Bounded NMDC $NickList parser and nick predicates. Shared by
// CDCNeighbour and EnvyTests. $NickList is nick-only ($$-separated);
// $MyINFO remains the metadata path. Identity is hub + nick, not nick
// globally.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include "DcPacketLengthValidate.h"

#include <stddef.h>

// NMDC nicks are short; 80 bytes of UTF-8 is above DC++ / ADC limits.
constexpr DWORD DC_NICK_BYTES_MAX = 80u;

// Drop an oversized $NickList payload rather than walking it forever.
constexpr DWORD DC_NICKLIST_PAYLOAD_MAX = 1024u * 1024u;

inline BOOL DcNickBytesOk(const char* p, size_t n)
{
	if ( p == NULL || n == 0 || n > DC_NICK_BYTES_MAX )
		return FALSE;
	for ( size_t i = 0; i < n; ++i )
	{
		const unsigned char c = static_cast< unsigned char >( p[ i ] );
		// Space, '$', '|' and controls are illegal in NMDC nicks.
		if ( c < 32 || c == 127 || c == ' ' || c == '$' || c == '|' )
			return FALSE;
	}
	return TRUE;
}

inline BOOL DcNickListPayloadOk(size_t nBytes)
{
	return nBytes <= DC_NICKLIST_PAYLOAD_MAX;
}

// Split $$ -separated nicks. Empty tokens and illegal nicks are skipped.
// onNick(p, n) should return FALSE to stop (cap reached). Returns FALSE
// only when the payload itself is oversize; truncated-by-cap is success.
template< typename F >
inline BOOL DcParseNickList(const char* p, size_t nBytes, F&& onNick)
{
	if ( p == NULL || nBytes == 0 )
		return TRUE;
	if ( ! DcNickListPayloadOk( nBytes ) )
		return FALSE;

	size_t nStart = 0;
	size_t i = 0;
	while ( i <= nBytes )
	{
		const BOOL bEnd = ( i == nBytes );
		const BOOL bSep = ( ! bEnd && p[ i ] == '$' &&
			( ( i + 1 < nBytes && p[ i + 1 ] == '$' ) || ( i + 1 == nBytes ) ) );
		if ( ! bEnd && ! bSep )
		{
			++i;
			continue;
		}

		const size_t nTok = i - nStart;
		if ( nTok > 0 && DcNickBytesOk( p + nStart, nTok ) )
		{
			if ( ! onNick( p + nStart, nTok ) )
				return TRUE;
		}

		if ( bEnd )
			break;
		if ( i + 1 < nBytes && p[ i ] == '$' && p[ i + 1 ] == '$' )
			i += 2;
		else
			++i;
		nStart = i;
	}
	return TRUE;
}
