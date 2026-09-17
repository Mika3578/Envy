//
// MiniUPnP.cpp
//
// This file is part of Envy (getenvy.com) © 2016-2018
// Portions copyright Shareaza 2014 and PeerProject 2014-2016
//
// Envy is free software. You may redistribute and/or modify it
// under the terms of the GNU Affero General Public License
// as published by the Free Software Foundation (fsf.org);
// version 3 or later at your option. (AGPLv3)
//
// Envy is distributed in the hope that it will be useful,
// but AS-IS WITHOUT ANY WARRANTY; without even implied warranty
// of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU Affero General Public License 3.0 for details:
// (http://www.gnu.org/licenses/agpl.html)
//

#include "StdAfx.h"
#include "Settings.h"
#include "Envy.h"
#include "MiniUPnP.h"
#include "Network.h"
#include "NetworkInterfaceSelector.h"
#include "MiniUPnPIgdPolicy.h"

// MiniUPnPc library
// Copyright (c) 2005-2015 Thomas Bernard
#include <MiniUPnP/miniupnpc.h>
#include <MiniUPnP/upnpcommands.h>
#include <MiniUPnP/upnpdev.h>
#include <MiniUPnP/upnperrors.h>
#pragma comment( lib, "miniupnpc" )

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#define new DEBUG_NEW
#endif	// Debug

namespace
{
	CString MiniUPnPErrorText( int nResult )
	{
		const char* psz = strupnperror( nResult );
		return CString( CA2T( psz ? psz : "unknown" ) );
	}

	bool MiniUPnPDescUrlAlreadySeen( const char* pszUrl, const char* const* pszSeen, int nSeen )
	{
		if ( ! pszUrl )
			return false;
		for ( int i = 0; i < nSeen; ++i )
		{
			// Exact LOCATION string match: path is case-sensitive.
			if ( pszSeen[ i ] && strcmp( pszSeen[ i ], pszUrl ) == 0 )
				return true;
		}
		return false;
	}

	// Keep unique description URLs that pass keepPredicate; free the rest.
	template< typename TKeepPred >
	UPNPDev* MiniUPnPFilterDevList( UPNPDev* pDevList, TKeepPred keepPred, int* pnKept, int* pnDropped )
	{
		if ( pnKept )
			*pnKept = 0;
		if ( pnDropped )
			*pnDropped = 0;
		if ( ! pDevList )
			return nullptr;

		UPNPDev* pKeepHead = nullptr;
		UPNPDev* pKeepTail = nullptr;
		UPNPDev* pDropHead = nullptr;
		const char* pszSeenUrls[ 64 ] = {};
		int nSeen = 0;

		UPNPDev* pDevice = pDevList;
		while ( pDevice != nullptr )
		{
			UPNPDev* pNext = pDevice->pNext;
			pDevice->pNext = nullptr;

			bool bKeep = keepPred( pDevice );
			if ( bKeep && MiniUPnPDescUrlAlreadySeen( pDevice->descURL, pszSeenUrls, nSeen ) )
				bKeep = false;

			if ( bKeep )
			{
				if ( pDevice->descURL && nSeen < static_cast< int >( _countof( pszSeenUrls ) ) )
					pszSeenUrls[ nSeen++ ] = pDevice->descURL;
				if ( ! pKeepHead )
					pKeepHead = pDevice;
				else
					pKeepTail->pNext = pDevice;
				pKeepTail = pDevice;
				if ( pnKept )
					++( *pnKept );
			}
			else
			{
				pDevice->pNext = pDropHead;
				pDropHead = pDevice;
				if ( pnDropped )
					++( *pnDropped );
			}

			pDevice = pNext;
		}

		if ( pDropHead )
			freeUPNPDevlist( pDropHead );

		return pKeepHead;
	}

	void MiniUPnPLogSsdpList( UPNPDev* pDevList )
	{
		for ( UPNPDev* pDevice = pDevList; pDevice != nullptr; pDevice = pDevice->pNext )
		{
			theApp.Message( MSG_DEBUG,
				L"UPnP SSDP device: location=%s ST=%s",
				(LPCTSTR)CA2T( pDevice->descURL ),
				(LPCTSTR)CA2T( pDevice->st ) );
		}
	}

	// Targeted NAT search list (one SSDP wait window via searchalltypes=1).
	// IGD:2 / WANIP:2 are valid UDA types even though MiniUPnPc 2.0's stock
	// upnpDiscover() leaves them under #if 0.
	const char* const* MiniUPnPTargetedIgdDeviceTypes()
	{
		static const char* const kTypes[] =
		{
			"urn:schemas-upnp-org:device:InternetGatewayDevice:2",
			"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
			"urn:schemas-upnp-org:service:WANIPConnection:2",
			"urn:schemas-upnp-org:service:WANIPConnection:1",
			"urn:schemas-upnp-org:service:WANPPPConnection:1",
			nullptr
		};
		return kTypes;
	}

	const char* const* MiniUPnPRootdeviceDeviceTypes()
	{
		static const char* const kTypes[] =
		{
			"upnp:rootdevice",
			nullptr
		};
		return kTypes;
	}

	// Consume pRootList (always freed). Sets *pnResult to GetValidIGD code,
	// or 3 for non-IGD / 0 when no candidate remained after filtering.
	bool MiniUPnPValidateGatewayRootDevice(
		UPNPDev* pRootList,
		UPNPUrls* pUrls,
		IGDdatas* pData,
		char* pszInternalIP,
		size_t nInternalIPChars,
		int* pnResult )
	{
		if ( ! pUrls || ! pData || ! pszInternalIP || ! pnResult )
		{
			if ( pRootList )
				freeUPNPDevlist( pRootList );
			return false;
		}

		if ( ! pRootList || ! pRootList->descURL )
		{
			if ( pRootList )
				freeUPNPDevlist( pRootList );
			*pnResult = 0;
			return false;
		}

		theApp.Message( MSG_INFO,
			L"UPnP trying gateway root-device fallback: %s",
			(LPCTSTR)CA2T( pRootList->descURL ) );

		const bool bLooksWps = MiniUPnPSsdpLooksLikeNonIgd( pRootList->descURL, pRootList->st );
		*pnResult = UPNP_GetValidIGD(
			pRootList, pUrls, pData, pszInternalIP, static_cast< int >( nInternalIPChars ) );
		freeUPNPDevlist( pRootList );

		if ( MiniUPnPIgdResultAllowsWanCommands( *pnResult ) )
			return true;

		if ( MiniUPnPIgdResultOwnsUrls( *pnResult ) )
			FreeUPNPUrls( pUrls );
		*pUrls = {};
		theApp.Message( MSG_ERROR,
			bLooksWps
				? L"UPnP gateway root device exposes WFA/WPS only; no usable IGD WAN service."
				: L"UPnP gateway root device does not expose a usable IGD WAN service." );
		*pnResult = 3;
		return false;
	}
}


CMiniUPnP::CMiniUPnP()
	: m_nExternalTCPPort	( 0 )
	, m_nExternalUDPPort	( 0 )
{
}

CMiniUPnP::~CMiniUPnP()
{
	StopAsyncFind();
}

void CMiniUPnP::StartDiscovery()
{
	BeginThread( "MiniUPnP" );
}

void CMiniUPnP::StopAsyncFind()
{
	CloseThread();
}

void CMiniUPnP::DeletePorts()
{
	CStringA sPort;

	if ( m_nExternalTCPPort )
	{
		sPort.Format( "%u", m_nExternalTCPPort );
		int result = UPNP_DeletePortMapping( m_sControlURL, m_sServiceType, sPort, "TCP", 0 );
		if ( result == UPNPCOMMAND_SUCCESS )
			theApp.Message( MSG_DEBUG, L"UPnP successfully unmapped TCP port %u.", m_nExternalTCPPort );
		else
			theApp.Message( MSG_DEBUG, L"UPnP failed to unmap TCP port %u, error %d.", m_nExternalTCPPort, result );
		m_nExternalTCPPort = 0;
	}

	if ( m_nExternalUDPPort )
	{
		sPort.Format( "%u", m_nExternalUDPPort );
		int result = UPNP_DeletePortMapping( m_sControlURL, m_sServiceType, sPort, "UDP", 0 );
		if ( result == UPNPCOMMAND_SUCCESS )
			theApp.Message( MSG_DEBUG, L"UPnP successfully unmapped UDP port %u.", m_nExternalUDPPort );
		else
			theApp.Message( MSG_DEBUG, L"UPnP failed to unmap UDP port %u, error %d.", m_nExternalUDPPort, result );
		m_nExternalUDPPort = 0;
	}
}

bool CMiniUPnP::IsAsyncFindRunning()
{
	return IsThreadAlive();
}

bool CMiniUPnP::MapAndVerifyProtocol( LPCSTR pszProtocol, WORD nPort, char* pszInternalIP, int& nCommandResult )
{
	CStringA sPort;
	sPort.Format( "%u", nPort );

	CString strInfo;
	strInfo.Format( L"%s at %s:%u",
		( pszProtocol && _stricmp( pszProtocol, "UDP" ) == 0 ) ? CLIENT_NAME L" UDP" : CLIENT_NAME L" TCP",
		(LPCTSTR)CA2T( pszInternalIP ),
		nPort );

	nCommandResult = UPNP_AddPortMapping(
		m_sControlURL, m_sServiceType, sPort, sPort, pszInternalIP,
		(LPCSTR)CT2A( strInfo ), pszProtocol, nullptr, nullptr );
	if ( nCommandResult != UPNPCOMMAND_SUCCESS )
	{
		theApp.Message( MSG_DEBUG,
			L"UPnP failed to map %hs port %u: %d (%s).",
			pszProtocol, nPort, nCommandResult, (LPCTSTR)MiniUPnPErrorText( nCommandResult ) );
		return false;
	}

	char sRealPort[ 6 ] = {};
	nCommandResult = UPNP_GetSpecificPortMappingEntry(
		m_sControlURL, m_sServiceType, sPort, pszProtocol, nullptr,
		pszInternalIP, sRealPort, nullptr, nullptr, nullptr );
	if ( nCommandResult != UPNPCOMMAND_SUCCESS )
	{
		theApp.Message( MSG_DEBUG,
			L"UPnP failed to get mapped %hs port %u: %d (%s).",
			pszProtocol, nPort, nCommandResult, (LPCTSTR)MiniUPnPErrorText( nCommandResult ) );
		return false;
	}

	const WORD nMapped = static_cast< WORD >( atoi( sRealPort ) );
	if ( _stricmp( pszProtocol, "UDP" ) == 0 )
		m_nExternalUDPPort = nMapped;
	else
		m_nExternalTCPPort = nMapped;

	theApp.Message( MSG_DEBUG, L"UPnP successfully mapped %hs port %u.", pszProtocol, nMapped );
	return true;
}

bool CMiniUPnP::TryMapPortPair( WORD nPort, char* pszInternalIP, bool bRandomPort, int& nCommandResult )
{
	if ( ! MapAndVerifyProtocol( "TCP", nPort, pszInternalIP, nCommandResult ) )
		return false;

	if ( ! MapAndVerifyProtocol( "UDP", nPort, pszInternalIP, nCommandResult ) )
	{
		DeletePorts();
		return false;
	}

	const bool bMapped = ( m_nExternalTCPPort != 0 ) &&
		( m_nExternalTCPPort == m_nExternalUDPPort ) &&
		( m_nExternalTCPPort == nPort );
	if ( ! bMapped )
	{
		DeletePorts();
		return false;
	}

	Network.AcquireLocalAddress( (LPCTSTR)CA2T( m_sExternalAddress ), nPort );
	Settings.Connection.InPort = nPort;
	Settings.Connection.RandomPort = bRandomPort;
	return true;
}

static void MiniUPnPAdvanceMappingRetryPort( WORD& nPort, bool& bRandomPort )
{
	if ( ! bRandomPort && ( nPort < 1024 || nPort >= 65535 ) )
		bRandomPort = true;

	if ( ! bRandomPort )
		nPort++;
	else
		nPort = Network.RandomPort();
}

bool CMiniUPnP::TryMapWithPortRetries( char* pszInternalIP, int& nCommandResult )
{
	WORD nPort = static_cast< WORD >( Settings.Connection.InPort );
	bool bRandomPort = Settings.Connection.RandomPort != FALSE;

	if ( nPort == 0 )
		nPort = Network.RandomPort();

	for ( int i = 0; i < 5 && IsThreadEnabled(); ++i )
	{
		if ( TryMapPortPair( nPort, pszInternalIP, bRandomPort, nCommandResult ) )
			return true;

		Sleep( 200 );
		MiniUPnPAdvanceMappingRetryPort( nPort, bRandomPort );
	}
	return false;
}

void CMiniUPnP::OnRun()
{
	BOOL bSuccess = FALSE;
	int error = 0;
	// -1 means discovery returned no device list, so no later MiniUPnPc op ran.
	// (UPNP_GetValidIGD uses 0 for failure; UPNPCOMMAND_SUCCESS is also 0.)
	int result = -1;

	// Bind SSDP to the Internet-facing LAN IPv4 (or explicit InBind/InHost).
	CStringA sMulticastInterface;
	LPCSTR pszMulticastInterface = nullptr;
	IN_ADDR oForcedBind = {};
	const IN_ADDR* pForcedBind = nullptr;

	if ( Settings.Connection.InBind && ! Settings.Connection.InHost.IsEmpty() )
	{
		SOCKADDR_IN pBindAddress = {};
		if ( CNetwork::Resolve( Settings.Connection.InHost, 0, &pBindAddress ) &&
			 pBindAddress.sin_addr.s_addr != INADDR_ANY &&
			 pBindAddress.sin_addr.s_addr != INADDR_NONE )
		{
			oForcedBind = pBindAddress.sin_addr;
			pForcedBind = &oForcedBind;
		}
		else
		{
			theApp.Message( MSG_ERROR, L"UPnP MiniUPnPc could not resolve configured bind interface: %s.",
				(LPCTSTR)Settings.Connection.InHost );
		}
	}

	char szDiscoveryAddresses[ NetworkInterfaceSelectorMaxDiscovery ][ 16 ] = {};
	DWORD nDiscoveryGateways[ NetworkInterfaceSelectorMaxDiscovery ] = {};
	ULONG nDiscoveryCount = NetworkInterfaceSelectorMaxDiscovery;
	if ( ! NetworkCollectSsdpDiscoveryIpv4Addresses(
			pForcedBind,
			szDiscoveryAddresses,
			nDiscoveryGateways,
			&nDiscoveryCount ) )
	{
		nDiscoveryCount = 0;
		theApp.Message( MSG_DEBUG, L"UPnP MiniUPnPc found no eligible IPv4 discovery interfaces." );
	}

	UPNPDev* pDevList = nullptr;
	DWORD nSelectedGateway = 0;
	const DWORD nFallbackTimeout =
		Settings.Connection.UPnPTimeout < 2000 ? Settings.Connection.UPnPTimeout : 2000;

	for ( ULONG nTry = 0; nTry < nDiscoveryCount && IsThreadEnabled(); ++nTry )
	{
		sMulticastInterface = szDiscoveryAddresses[ nTry ];
		pszMulticastInterface = sMulticastInterface;
		nSelectedGateway = nDiscoveryGateways[ nTry ];

		char szGateway[ 16 ] = {};
		if ( nSelectedGateway != 0 )
			NetworkFormatIpv4( nSelectedGateway, szGateway, _countof( szGateway ) );

		const DWORD nTimeout = ( nTry == 0 ) ? Settings.Connection.UPnPTimeout : nFallbackTimeout;
		theApp.Message( MSG_DEBUG,
			L"UPnP MiniUPnPc targeted discovery on interface %s (gateway %s).",
			(LPCTSTR)CA2T( pszMulticastInterface ),
			szGateway[ 0 ] ? (LPCTSTR)CA2T( szGateway ) : L"unknown" );

		error = 0;
		const ULONGLONG tDiscoverStart = GetTickCount64();
		// searchalltypes=1: send all targeted M-SEARCH then wait ONE delay window.
		UPNPDev* pRawList = upnpDiscoverDevices(
			MiniUPnPTargetedIgdDeviceTypes(),
			static_cast< int >( nTimeout ),
			pszMulticastInterface,
			nullptr,
			UPNP_LOCAL_PORT_ANY,
			0,
			2,
			&error,
			1 );
		const DWORD nDiscoverMs = static_cast< DWORD >( GetTickCount64() - tDiscoverStart );

		int nResponses = 0;
		for ( UPNPDev* p = pRawList; p != nullptr; p = p->pNext )
			++nResponses;

		if ( pRawList )
			MiniUPnPLogSsdpList( pRawList );

		int nKept = 0;
		int nDropped = 0;
		pDevList = MiniUPnPFilterDevList( pRawList,
			[]( const UPNPDev* pDevice )
			{
				return MiniUPnPIsExplicitIgdAdvertisement( pDevice->st )
					&& ! MiniUPnPSsdpLooksLikeNonIgd( pDevice->descURL, pDevice->st );
			},
			&nKept, &nDropped );

		theApp.Message( MSG_INFO,
			L"UPnP targeted SSDP discovery completed in %u ms: responses=%d IGD candidates=%d.",
			nDiscoverMs, nResponses, nKept );

		// Stop after the preferred interface yields any SSDP activity or a hard error.
		if ( pDevList || nResponses > 0 || error != 0 )
			break;
	}

	char internalIPAddress[ 16 ] = {};
	UPNPUrls urls = {};
	IGDdatas data = {};
	bool bHaveUsableIgd = false;

	if ( pDevList )
	{
		result = UPNP_GetValidIGD( pDevList, &urls, &data, internalIPAddress, sizeof( internalIPAddress ) );
		freeUPNPDevlist( pDevList );
		pDevList = nullptr;

		if ( MiniUPnPIgdResultAllowsWanCommands( result ) )
			bHaveUsableIgd = true;
		else if ( MiniUPnPIgdResultOwnsUrls( result ) )
		{
			FreeUPNPUrls( &urls );
			urls = {};
		}
	}

	if ( ! bHaveUsableIgd && nSelectedGateway != 0 && IsThreadEnabled() )
	{
		char szGateway[ 16 ] = {};
		NetworkFormatIpv4( nSelectedGateway, szGateway, _countof( szGateway ) );

		if ( result == -1 || MiniUPnPIgdResultMeansNoUsableIgd( result ) )
			theApp.Message( MSG_INFO, L"No explicit IGD/WAN service advertisements found." );

		error = 0;
		const ULONGLONG tFallbackStart = GetTickCount64();
		UPNPDev* pRootList = upnpDiscoverDevices(
			MiniUPnPRootdeviceDeviceTypes(),
			static_cast< int >( nFallbackTimeout ),
			pszMulticastInterface,
			nullptr,
			UPNP_LOCAL_PORT_ANY,
			0,
			2,
			&error,
			0 );

		if ( pRootList )
			MiniUPnPLogSsdpList( pRootList );

		int nKept = 0;
		int nDropped = 0;
		const DWORD nGatewayCopy = nSelectedGateway;
		pRootList = MiniUPnPFilterDevList( pRootList,
			[ nGatewayCopy ]( const UPNPDev* pDevice )
			{
				// Gateway-only fallback: keep root-device descriptions hosted by
				// the selected gateway and avoid fetching unrelated LAN device
				// descriptions as NAT candidates.
				if ( ! pDevice->descURL )
					return false;
				return MiniUPnPHttpUrlHostEqualsIpv4( pDevice->descURL, nGatewayCopy );
			},
			&nKept, &nDropped );

		const DWORD nFallbackMs = static_cast< DWORD >( GetTickCount64() - tFallbackStart );
		theApp.Message( MSG_INFO,
			L"UPnP gateway root-device fallback completed in %u ms: candidates=%d.",
			nFallbackMs, nKept );

		if ( MiniUPnPValidateGatewayRootDevice(
				pRootList, &urls, &data, internalIPAddress, sizeof( internalIPAddress ), &result ) )
		{
			bHaveUsableIgd = true;
		}
		else if ( result == 0 )
		{
			theApp.Message( MSG_ERROR,
				L"UPnP: no usable Internet Gateway Device found on gateway %s.",
				(LPCTSTR)CA2T( szGateway ) );
		}
	}
	else if ( ! bHaveUsableIgd && error != 0 && result == -1 )
	{
		theApp.Message( MSG_ERROR, L"UPnP MiniUPnPc discovery failed with error %d.", error );
	}
	else if ( ! bHaveUsableIgd && result == -1 )
	{
		result = 0;
		if ( pszMulticastInterface )
			theApp.Message( MSG_ERROR, L"UPnP MiniUPnPc discovery found no devices on interface %s.",
				(LPCTSTR)CA2T( pszMulticastInterface ) );
		else
			theApp.Message( MSG_ERROR, L"UPnP MiniUPnPc discovery found no devices on the selected Internet-facing IPv4 interfaces." );
	}

	if ( bHaveUsableIgd && MiniUPnPIgdResultAllowsWanCommands( result ) )
	{
		m_sServiceType = data.first.servicetype;
		m_sControlURL = urls.controlURL;
		FreeUPNPUrls( &urls );
		urls = {};

		if ( result == 1 )
		{
			theApp.Message( MSG_DEBUG, L"UPnP IGD valid and connected: %s",
				(LPCTSTR)CA2T( m_sControlURL ) );
		}
		else
		{
			theApp.Message( MSG_DEBUG,
				L"UPnP IGD found but reports not connected; attempting mapping: %s",
				(LPCTSTR)CA2T( m_sControlURL ) );
		}

		result = UPNP_GetExternalIPAddress( m_sControlURL, m_sServiceType, m_sExternalAddress.GetBuffer( 16 ) );
		m_sExternalAddress.ReleaseBuffer();
		if ( result == UPNPCOMMAND_SUCCESS && ! m_sExternalAddress.IsEmpty() )
		{
			if ( TryMapWithPortRetries( internalIPAddress, result ) )
				bSuccess = TRUE;
		}
		else
		{
			theApp.Message( MSG_DEBUG,
				L"UPnP failed to get external IP address: %d (%s).",
				result, (LPCTSTR)MiniUPnPErrorText( result ) );
		}
	}
	else
	{
		if ( MiniUPnPIgdResultOwnsUrls( result ) )
			FreeUPNPUrls( &urls );

		if ( result == 3 )
		{
			theApp.Message( MSG_ERROR,
				L"UPnP MiniUPnPc found no usable Internet Gateway Device." );
		}
		else if ( result == 0 )
		{
			theApp.Message( MSG_ERROR, L"UPnP: no usable Internet Gateway Device found." );
		}
		else if ( result != -1 )
		{
			theApp.Message( MSG_ERROR, L"UPnP GetValidIGD failed with result %d.", result );
		}
	}

	if ( bSuccess )
		Network.OnMapSuccess();
	else
	{
		if ( IsThreadEnabled() && result != -1 && ! MiniUPnPIgdResultMeansNoUsableIgd( result ) )
			theApp.Message( MSG_ERROR, L"UPnP MiniUPnPc backend failed after discovery (last command result %d).", result );
		Network.OnMapFailed();
	}
}
