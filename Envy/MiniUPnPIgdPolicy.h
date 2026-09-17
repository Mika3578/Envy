//
// MiniUPnPIgdPolicy.h
//
// Pure MiniUPnPc IGD/SSDP policy helpers shared by MiniUPnP.cpp and EnvyTests.
// GetValidIGD return codes (MiniUPnPc 2.0):
//   0 = no IGD, 1 = valid connected, 2 = valid not connected, 3 = UPnP but not IGD
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <cstring>
#include <cstdio>

//////////////////////////////////////////////////////////////////////
// GetValidIGD result policy

inline bool MiniUPnPIgdResultAllowsWanCommands( int nGetValidIgdResult )
{
	return nGetValidIgdResult == 1 || nGetValidIgdResult == 2;
}

inline bool MiniUPnPIgdResultMeansNoUsableIgd( int nGetValidIgdResult )
{
	return nGetValidIgdResult == 0 || nGetValidIgdResult == 3;
}

inline bool MiniUPnPIgdResultOwnsUrls( int nGetValidIgdResult )
{
	return nGetValidIgdResult > 0;
}

//////////////////////////////////////////////////////////////////////
// String helpers

inline bool MiniUPnPAsciiContainsNoCase( const char* pszHaystack, const char* pszNeedle )
{
	if ( ! pszHaystack || ! pszNeedle || ! *pszNeedle )
		return false;

	for ( const char* p = pszHaystack; *p; ++p )
	{
		const char* h = p;
		const char* n = pszNeedle;
		while ( *h && *n )
		{
			char chH = *h;
			char chN = *n;
			if ( chH >= 'A' && chH <= 'Z' )
				chH = static_cast< char >( chH - 'A' + 'a' );
			if ( chN >= 'A' && chN <= 'Z' )
				chN = static_cast< char >( chN - 'A' + 'a' );
			if ( chH != chN )
				break;
			++h;
			++n;
		}
		if ( ! *n )
			return true;
	}
	return false;
}

//////////////////////////////////////////////////////////////////////
// SSDP ST classification

// Explicit NAT/IGD advertisements only (direct WAN mapping candidates).
inline bool MiniUPnPIsExplicitIgdAdvertisement( const char* pszServiceType )
{
	if ( ! pszServiceType || ! *pszServiceType )
		return false;
	if ( MiniUPnPAsciiContainsNoCase( pszServiceType, "InternetGatewayDevice" ) )
		return true;
	if ( MiniUPnPAsciiContainsNoCase( pszServiceType, "WANIPConnection" ) )
		return true;
	if ( MiniUPnPAsciiContainsNoCase( pszServiceType, "WANPPPConnection" ) )
		return true;
	return false;
}

// WPS / Wi-Fi Alliance UPnP is never a WAN IGD for port mapping.
inline bool MiniUPnPSsdpLooksLikeNonIgd( const char* pszDescUrl, const char* pszServiceType )
{
	if ( MiniUPnPAsciiContainsNoCase( pszDescUrl, "wps_device.xml" ) )
		return true;
	if ( MiniUPnPAsciiContainsNoCase( pszServiceType, "WFAWLANConfig" ) )
		return true;
	if ( MiniUPnPAsciiContainsNoCase( pszServiceType, "WFADevice" ) )
		return true;
	if ( MiniUPnPAsciiContainsNoCase( pszServiceType, "MediaServer" ) )
		return true;
	if ( MiniUPnPAsciiContainsNoCase( pszServiceType, "BasicDevice" ) )
		return true;
	return false;
}

//////////////////////////////////////////////////////////////////////
// HTTP LOCATION host vs gateway IPv4 (no substring false positives)

// Parse a dotted-quad into network-order DWORD. Rejects trailing junk.
inline bool MiniUPnPParseDottedIpv4( const char* psz, DWORD* pnOut )
{
	if ( ! psz || ! pnOut )
		return false;

	unsigned int b0 = 0;
	unsigned int b1 = 0;
	unsigned int b2 = 0;
	unsigned int b3 = 0;
	if ( char chEnd = 0;
		 sscanf_s( psz, "%u.%u.%u.%u%c", &b0, &b1, &b2, &b3, &chEnd, 1 ) != 4 )
		return false;
	if ( b0 > 255 || b1 > 255 || b2 > 255 || b3 > 255 )
		return false;

	unsigned char bytes[ 4 ] =
	{
		static_cast< unsigned char >( b0 ),
		static_cast< unsigned char >( b1 ),
		static_cast< unsigned char >( b2 ),
		static_cast< unsigned char >( b3 )
	};
	DWORD n = 0;
	memcpy( &n, bytes, 4 );
	*pnOut = n;
	return true;
}

// Extract host from http(s)://[userinfo@]host[:port]/path]
inline bool MiniUPnPExtractHttpUrlHost( const char* pszUrl, char* pszHostOut, size_t nHostChars )
{
	if ( ! pszUrl || ! pszHostOut || nHostChars < 2 )
		return false;
	pszHostOut[ 0 ] = 0;

	const char* p = pszUrl;
	if ( const char* pszScheme = strstr( p, "://" ); pszScheme )
		p = pszScheme + 3;
	if ( ! *p )
		return false;

	// Skip userinfo@
	for ( const char* q = p; *q && *q != '/' && *q != '?' && *q != '#'; ++q )
	{
		if ( *q == '@' )
		{
			p = q + 1;
			break;
		}
	}

	size_t nLen = 0;
	if ( *p == '[' )
	{
		++p;
		while ( *p && *p != ']' && nLen + 1 < nHostChars )
			pszHostOut[ nLen++ ] = *p++;
		pszHostOut[ nLen ] = 0;
		return nLen > 0;
	}

	while ( *p && *p != ':' && *p != '/' && *p != '?' && *p != '#' && nLen + 1 < nHostChars )
		pszHostOut[ nLen++ ] = *p++;
	pszHostOut[ nLen ] = 0;
	return nLen > 0;
}

inline bool MiniUPnPHttpUrlHostEqualsIpv4( const char* pszUrl, DWORD nGatewayIpv4 )
{
	char szHost[ 256 ] = {};
	if ( ! MiniUPnPExtractHttpUrlHost( pszUrl, szHost, sizeof( szHost ) ) )
		return false;

	DWORD nHost = 0;
	if ( ! MiniUPnPParseDottedIpv4( szHost, &nHost ) )
		return false;
	return nHost == nGatewayIpv4;
}

inline bool MiniUPnPHttpUrlHostEqualsIpv4String( const char* pszUrl, const char* pszGatewayIpv4 )
{
	DWORD nGateway = 0;
	if ( ! MiniUPnPParseDottedIpv4( pszGatewayIpv4, &nGateway ) )
		return false;
	return MiniUPnPHttpUrlHostEqualsIpv4( pszUrl, nGateway );
}

// Count unique LOCATION URLs by exact string equality (same policy as
// MiniUPnPDescUrlAlreadySeen / MiniUPnPFilterDevList). Path is case-sensitive.
inline int MiniUPnPCountUniqueLocations( const char* const* ppszUrls, int nCount )
{
	if ( ! ppszUrls || nCount <= 0 )
		return 0;

	int nUnique = 0;
	for ( int i = 0; i < nCount; ++i )
	{
		if ( ! ppszUrls[ i ] || ! ppszUrls[ i ][ 0 ] )
			continue;
		bool bSeen = false;
		for ( int j = 0; j < i; ++j )
		{
			if ( ppszUrls[ j ] && strcmp( ppszUrls[ j ], ppszUrls[ i ] ) == 0 )
			{
				bSeen = true;
				break;
			}
		}
		if ( ! bSeen )
			++nUnique;
	}
	return nUnique;
}
