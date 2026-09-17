//
// NetworkInterfaceSelector.cpp
//
// Internet-facing IPv4 adapter selection using GetAdaptersAddresses and
// GetBestRoute2. Used by MiniUPnPc SSDP discovery to bind multicast to the
// LAN adapter that actually reaches the default gateway / Internet.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "StdAfx.h"
#include "NetworkInterfaceSelector.h"

#include <WS2tcpip.h>
#include <netioapi.h>

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#define new DEBUG_NEW
#endif	// Debug

namespace
{
	// Well-known public IPv4 used only to ask Windows which interface would
	// carry Internet traffic. No packet is sent by GetBestRoute2.
	const DWORD kInternetProbeAddress = 0x08080808;	// 8.8.8.8 network order

	struct InternetFacingRoute
	{
		ULONG	IfIndex;
		DWORD	NextHop;	// IPv4 network order; 0 if unavailable / on-link
	};

	InternetFacingRoute ResolveInternetFacingRoute()
	{
		InternetFacingRoute oRoute = {};

		SOCKADDR_INET oDestination = {};
		oDestination.Ipv4.sin_family = AF_INET;
		oDestination.Ipv4.sin_addr.s_addr = kInternetProbeAddress;

		MIB_IPFORWARD_ROW2 oBestRoute = {};
		SOCKADDR_INET oBestSource = {};
		if ( const DWORD nStatus = GetBestRoute2(
				nullptr,
				0,
				nullptr,
				&oDestination,
				0,
				&oBestRoute,
				&oBestSource );
			 nStatus != NO_ERROR )
			return oRoute;

		oRoute.IfIndex = oBestRoute.InterfaceIndex;
		if ( oBestRoute.NextHop.si_family == AF_INET )
		{
			const DWORD nNextHop = oBestRoute.NextHop.Ipv4.sin_addr.s_addr;
			if ( ! NetworkIpv4IsZero( nNextHop ) && ! NetworkIpv4IsLoopback( nNextHop ) )
				oRoute.NextHop = nNextHop;
		}
		return oRoute;
	}

	DWORD FirstIpv4Gateway( const IP_ADAPTER_ADDRESSES* pAdapter )
	{
		for ( IP_ADAPTER_GATEWAY_ADDRESS_LH* pGateway = pAdapter->FirstGatewayAddress;
			  pGateway != nullptr;
			  pGateway = pGateway->Next )
		{
			if ( ! pGateway->Address.lpSockaddr ||
				 pGateway->Address.lpSockaddr->sa_family != AF_INET )
				continue;

			auto* pIn =
				reinterpret_cast< const sockaddr_in* >( pGateway->Address.lpSockaddr );
			if ( ! NetworkIpv4IsZero( pIn->sin_addr.s_addr ) )
				return pIn->sin_addr.s_addr;
		}
		return 0;
	}

	DWORD LookupGatewayForLocalAddress(
		const NetworkIpv4Candidate* pCandidates,
		ULONG nCandidateCount,
		DWORD nLocalAddress )
	{
		for ( ULONG i = 0; i < nCandidateCount; ++i )
		{
			if ( pCandidates[ i ].Address == nLocalAddress &&
				 ! NetworkIpv4IsZero( pCandidates[ i ].Gateway ) )
				return pCandidates[ i ].Gateway;
		}
		return 0;
	}
}

bool NetworkEnumerateIpv4Candidates(
	NetworkIpv4Candidate* pOut,
	ULONG nMaxOut,
	ULONG* pnCount )
{
	if ( pnCount )
		*pnCount = 0;
	if ( ! pOut || nMaxOut == 0 || ! pnCount )
		return false;

	ULONG nBuffer = 16 * 1024;
	auto_array< BYTE > pBuffer( new BYTE[ nBuffer ] );
	ULONG nResult = ERROR_BUFFER_OVERFLOW;

	for ( int nAttempt = 0; nAttempt < 3; ++nAttempt )
	{
		nResult = GetAdaptersAddresses(
			AF_INET,
			GAA_FLAG_INCLUDE_GATEWAYS |
				GAA_FLAG_SKIP_ANYCAST |
				GAA_FLAG_SKIP_MULTICAST |
				GAA_FLAG_SKIP_DNS_SERVER,
			nullptr,
			reinterpret_cast< PIP_ADAPTER_ADDRESSES >( pBuffer.get() ),
			&nBuffer );

		if ( nResult == ERROR_BUFFER_OVERFLOW )
		{
			pBuffer.reset( new BYTE[ nBuffer ] );
			continue;
		}
		break;
	}

	if ( nResult != NO_ERROR )
		return false;

	const InternetFacingRoute oPreferred = ResolveInternetFacingRoute();
	ULONG nWritten = 0;

	for ( PIP_ADAPTER_ADDRESSES pAdapter =
			reinterpret_cast< PIP_ADAPTER_ADDRESSES >( pBuffer.get() );
		  pAdapter != nullptr && nWritten < nMaxOut;
		  pAdapter = pAdapter->Next )
	{
		const bool bLoopbackType = ( pAdapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK );
		const bool bUp = ( pAdapter->OperStatus == IfOperStatusUp );
		const bool bVirtual = NetworkAdapterDescriptionLooksVirtual( pAdapter->Description )
			|| NetworkAdapterDescriptionLooksVirtual( pAdapter->FriendlyName );
		const DWORD nAdapterGateway = FirstIpv4Gateway( pAdapter );
		const bool bPreferred = ( oPreferred.IfIndex != 0 &&
			pAdapter->IfIndex == oPreferred.IfIndex );
		const DWORD nGateway = NetworkGatewayPreferAdapterThenRouteNextHop(
			nAdapterGateway,
			bPreferred ? oPreferred.NextHop : 0 );
		const ULONG nMetric = pAdapter->Ipv4Metric;

		for ( IP_ADAPTER_UNICAST_ADDRESS* pUnicast = pAdapter->FirstUnicastAddress;
			  pUnicast != nullptr && nWritten < nMaxOut;
			  pUnicast = pUnicast->Next )
		{
			if ( ! pUnicast->Address.lpSockaddr ||
				 pUnicast->Address.lpSockaddr->sa_family != AF_INET )
				continue;

			auto* pIn =
				reinterpret_cast< const sockaddr_in* >( pUnicast->Address.lpSockaddr );

			NetworkIpv4Candidate& oCandidate = pOut[ nWritten ];
			oCandidate = {};
			oCandidate.IfIndex = pAdapter->IfIndex;
			oCandidate.Ipv4Metric = nMetric;
			oCandidate.Address = pIn->sin_addr.s_addr;
			oCandidate.Gateway = nGateway;
			oCandidate.bUp = bUp;
			oCandidate.bLoopback = bLoopbackType || NetworkIpv4IsLoopback( oCandidate.Address );
			oCandidate.bApipa = NetworkIpv4IsApipa( oCandidate.Address );
			oCandidate.bVirtualLikely = bVirtual;
			oCandidate.bPreferredInternet = bPreferred;
			++nWritten;
		}
	}

	*pnCount = nWritten;
	return true;
}

bool NetworkCollectSsdpDiscoveryIpv4Addresses(
	const IN_ADDR* pForcedBindAddress,
	char ( *pszOutAddresses )[ 16 ],
	DWORD* pnOutGateways,
	ULONG* pnCount )
{
	if ( ! pszOutAddresses || ! pnCount || *pnCount == 0 )
		return false;

	const ULONG nCapacity = *pnCount;
	*pnCount = 0;
	if ( pnOutGateways )
	{
		for ( ULONG i = 0; i < nCapacity; ++i )
			pnOutGateways[ i ] = 0;
	}

	NetworkIpv4Candidate oCandidates[ 32 ] = {};
	ULONG nCandidateCount = 0;
	const bool bEnumerated = NetworkEnumerateIpv4Candidates(
		oCandidates, _countof( oCandidates ), &nCandidateCount );

	if ( pForcedBindAddress &&
		 ! NetworkIpv4IsZero( pForcedBindAddress->s_addr ) &&
		 ! NetworkIpv4IsLoopback( pForcedBindAddress->s_addr ) )
	{
		if ( ! NetworkFormatIpv4( pForcedBindAddress->s_addr, pszOutAddresses[ 0 ], 16 ) )
			return false;
		if ( pnOutGateways && bEnumerated )
		{
			pnOutGateways[ 0 ] = LookupGatewayForLocalAddress(
				oCandidates, nCandidateCount, pForcedBindAddress->s_addr );
		}
		*pnCount = 1;
		return true;
	}

	if ( ! bEnumerated )
		return false;

	ULONG nOrder[ NetworkInterfaceSelectorMaxDiscovery ] = {};
	const ULONG nMaxOrdered = ( nCapacity < static_cast< ULONG >( NetworkInterfaceSelectorMaxDiscovery ) )
		? nCapacity
		: static_cast< ULONG >( NetworkInterfaceSelectorMaxDiscovery );
	const ULONG nOrdered = NetworkOrderDiscoveryCandidates(
		oCandidates,
		nCandidateCount,
		nOrder,
		nMaxOrdered );

	for ( ULONG i = 0; i < nOrdered; ++i )
	{
		const NetworkIpv4Candidate& oCandidate = oCandidates[ nOrder[ i ] ];
		if ( ! NetworkFormatIpv4( oCandidate.Address, pszOutAddresses[ i ], 16 ) )
			continue;
		if ( pnOutGateways )
			pnOutGateways[ i ] = oCandidate.Gateway;
		++( *pnCount );
	}

	return *pnCount > 0;
}
