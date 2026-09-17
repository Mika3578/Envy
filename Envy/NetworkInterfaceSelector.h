//
// NetworkInterfaceSelector.h
//
// Pure IPv4 adapter-selection helpers for Internet-facing LAN choice
// (SSDP / UPnP discovery). Shared by NetworkInterfaceSelector.cpp and
// EnvyTests smoke coverage. Windows enumeration lives in the .cpp.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <WinSock2.h>
#include <Windows.h>

#include <cstdio>
#include <cwchar>

//////////////////////////////////////////////////////////////////////
// Candidate description (filled by enumeration or tests)

struct NetworkIpv4Candidate
{
	ULONG	IfIndex;
	ULONG	Ipv4Metric;			// Lower is preferred (Windows interface metric)
	DWORD	Address;			// IPv4 in network byte order (IN_ADDR.s_addr)
	DWORD	Gateway;			// IPv4 gateway in network byte order; 0 if none
	bool	bUp;
	bool	bLoopback;
	bool	bApipa;
	bool	bVirtualLikely;		// Hyper-V / VMware / VirtualBox-style description
	bool	bPreferredInternet;	// True when GetBestRoute2 selected this IfIndex
};

enum NetworkInterfaceSelectorLimits : ULONG
{
	NetworkInterfaceSelectorMaxDiscovery = 4
};

inline bool NetworkIpv4IsZero( DWORD nAddr )
{
	return nAddr == 0 || nAddr == INADDR_NONE;
}

inline bool NetworkIpv4IsLoopback( DWORD nAddr )
{
	const unsigned char* p = reinterpret_cast< const unsigned char* >( &nAddr );
	return p[ 0 ] == 127;
}

inline bool NetworkIpv4IsApipa( DWORD nAddr )
{
	const unsigned char* p = reinterpret_cast< const unsigned char* >( &nAddr );
	return p[ 0 ] == 169 && p[ 1 ] == 254;
}

// True when the friendly/description string looks like a common virtual
// adapter that should not be used for SSDP unless it is the Internet route.
inline bool NetworkAdapterDescriptionLooksVirtual( const wchar_t* pszDescription )
{
	if ( ! pszDescription || ! *pszDescription )
		return false;

	static const wchar_t* const kVirtualMarkers[] =
	{
		L"hyper-v",
		L"vmware",
		L"virtualbox",
		L"vbox",
		L"virtual ethernet",
		L"virtual adapter",
		L"loopback"
	};

	wchar_t szLower[ 256 ] = {};
	size_t nLen = 0;
	for ( ; pszDescription[ nLen ] && nLen + 1 < _countof( szLower ); ++nLen )
	{
		const wchar_t ch = pszDescription[ nLen ];
		szLower[ nLen ] = ( ch >= L'A' && ch <= L'Z' ) ? static_cast< wchar_t >( ch + ( L'a' - L'A' ) ) : ch;
	}
	szLower[ nLen ] = 0;

	for ( size_t i = 0; i < _countof( kVirtualMarkers ); ++i )
	{
		if ( wcsstr( szLower, kVirtualMarkers[ i ] ) != nullptr )
			return true;
	}
	return false;
}

// Eligible for SSDP toward a LAN IGD: up, non-loopback, non-APIPA, has a
// gateway. Virtual adapters are skipped unless they are the preferred
// Internet-facing route (e.g. selected VPN).
inline bool NetworkIpv4CandidateIsEligible( const NetworkIpv4Candidate& oCandidate )
{
	if ( ! oCandidate.bUp )
		return false;
	if ( oCandidate.bLoopback || NetworkIpv4IsLoopback( oCandidate.Address ) )
		return false;
	if ( oCandidate.bApipa || NetworkIpv4IsApipa( oCandidate.Address ) )
		return false;
	if ( NetworkIpv4IsZero( oCandidate.Address ) )
		return false;
	if ( NetworkIpv4IsZero( oCandidate.Gateway ) )
		return false;
	if ( oCandidate.bVirtualLikely && ! oCandidate.bPreferredInternet )
		return false;
	return true;
}

// Rank eligible candidates: preferred Internet route first, then ascending
// IPv4 interface metric. Writes up to nMaxOut indices into pnOutIndices.
// Returns the number of indices written.
inline ULONG NetworkFindBestDiscoveryCandidate(
	const NetworkIpv4Candidate* pCandidates,
	ULONG nLimit,
	const bool* pbUsed,
	bool bPreferredOnly )
{
	ULONG nBest = nLimit;
	for ( ULONG i = 0; i < nLimit; ++i )
	{
		if ( pbUsed[ i ] )
			continue;
		if ( ! NetworkIpv4CandidateIsEligible( pCandidates[ i ] ) )
			continue;
		if ( bPreferredOnly && ! pCandidates[ i ].bPreferredInternet )
			continue;
		if ( nBest == nLimit ||
			 pCandidates[ i ].Ipv4Metric < pCandidates[ nBest ].Ipv4Metric ||
			 ( pCandidates[ i ].Ipv4Metric == pCandidates[ nBest ].Ipv4Metric &&
			   pCandidates[ i ].IfIndex < pCandidates[ nBest ].IfIndex ) )
		{
			nBest = i;
		}
	}
	return nBest;
}

inline ULONG NetworkOrderDiscoveryCandidates(
	const NetworkIpv4Candidate* pCandidates,
	ULONG nCount,
	ULONG* pnOutIndices,
	ULONG nMaxOut )
{
	if ( ! pCandidates || ! pnOutIndices || nMaxOut == 0 )
		return 0;

	ULONG nWritten = 0;
	bool bUsed[ 64 ] = {};
	const ULONG nLimit = nCount < _countof( bUsed ) ? nCount : _countof( bUsed );

	auto takeNext = [ & ]( bool bPreferPreferred )
	{
		const ULONG nBest = NetworkFindBestDiscoveryCandidate(
			pCandidates, nLimit, bUsed, bPreferPreferred );
		if ( nBest == nLimit )
			return false;
		bUsed[ nBest ] = true;
		pnOutIndices[ nWritten++ ] = nBest;
		return true;
	};

	while ( nWritten < nMaxOut && takeNext( true ) )
	{
		// Keep preferring Internet-facing adapters until the cap is filled.
	}
	while ( nWritten < nMaxOut && takeNext( false ) )
	{
		// Fill remaining slots by ascending interface metric.
	}

	return nWritten;
}

// Format dotted-quad into a NUL-terminated buffer (max 16 bytes including NUL).
inline bool NetworkFormatIpv4( DWORD nAddr, char* pszOut, size_t nOutChars )
{
	if ( ! pszOut || nOutChars < 16 )
		return false;
	const unsigned char* p = reinterpret_cast< const unsigned char* >( &nAddr );
	const int nPrinted = _snprintf_s( pszOut, nOutChars, _TRUNCATE, "%u.%u.%u.%u",
		static_cast< unsigned >( p[ 0 ] ),
		static_cast< unsigned >( p[ 1 ] ),
		static_cast< unsigned >( p[ 2 ] ),
		static_cast< unsigned >( p[ 3 ] ) );
	return nPrinted > 0;
}

// Prefer GetAdaptersAddresses gateway; if missing, use GetBestRoute2 NextHop
// when it is a usable IPv4 host route (not 0.0.0.0 / loopback).
inline DWORD NetworkGatewayPreferAdapterThenRouteNextHop(
	DWORD nAdapterGateway,
	DWORD nRouteNextHop )
{
	if ( ! NetworkIpv4IsZero( nAdapterGateway ) &&
		 ! NetworkIpv4IsLoopback( nAdapterGateway ) )
		return nAdapterGateway;
	if ( ! NetworkIpv4IsZero( nRouteNextHop ) &&
		 ! NetworkIpv4IsLoopback( nRouteNextHop ) )
		return nRouteNextHop;
	return 0;
}

//////////////////////////////////////////////////////////////////////
// Windows enumeration (implemented in NetworkInterfaceSelector.cpp)

// Enumerate IPv4 unicast addresses via GetAdaptersAddresses. Marks the
// Internet-facing IfIndex from GetBestRoute2 when available.
// Returns false only when enumeration itself fails.
bool NetworkEnumerateIpv4Candidates(
	NetworkIpv4Candidate* pOut,
	ULONG nMaxOut,
	ULONG* pnCount );

// Fill pszOutAddresses[i] with dotted-quad local IPv4 addresses for SSDP,
// ordered for discovery (preferred Internet adapter first). Respects an
// optional forced bind address (Connection.InBind / InHost).
// *pnCount is in/out: input = capacity, output = filled count.
bool NetworkCollectSsdpDiscoveryIpv4Addresses(
	const IN_ADDR* pForcedBindAddress,
	char ( *pszOutAddresses )[ 16 ],
	DWORD* pnOutGateways,
	ULONG* pnCount );
