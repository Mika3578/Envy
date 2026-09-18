//
// Firewall.cpp
//
// This file is part of Envy (getenvy.com) © 2016-2018
// Portions copyright Shareaza 2002-2007 and PeerProject 2008-2014
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

// CFirewall: Windows Firewall with Advanced Security via INetFwPolicy2 (#166).

#include "StdAfx.h"
#include "Firewall.h"
#include "FirewallWfasPolicy.h"
#include "Envy.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#define new DEBUG_NEW
#endif	// Debug

namespace
{
	void LogFirewallHRESULT( LPCWSTR pszOperation, HRESULT hr )
	{
		theApp.Message( MSG_ERROR, L"Windows Firewall %s failed (HRESULT 0x%08lX).", pszOperation, (DWORD)hr );
	}

	BOOL LogFirewallInterfaceFailure( LPCWSTR pszOperation, HRESULT hr, IUnknown* pInterface )
	{
		if ( FAILED( hr ) )
		{
			LogFirewallHRESULT( pszOperation, hr );
			return FALSE;
		}
		if ( ! pInterface )
		{
			theApp.Message( MSG_ERROR,
				L"Windows Firewall %s returned a null interface (HRESULT 0x%08lX).",
				pszOperation, (DWORD)hr );
			return FALSE;
		}
		return TRUE;
	}

	BOOL ProfileAllowsExceptions( INetFwPolicy2* pPolicy2, NET_FW_PROFILE_TYPE2 nProfile )
	{
		VARIANT_BOOL vbBlock = VARIANT_FALSE;
		const HRESULT hr = pPolicy2->get_BlockAllInboundTraffic( nProfile, &vbBlock );
		if ( FAILED( hr ) )
			return FALSE;
		return vbBlock == VARIANT_FALSE;
	}
}

CFirewall::CFirewall()
{
}

CFirewall::~CFirewall()
{
}

CString CFirewall::UPnPRuleGroupName()
{
	// Localized group name resource used by WFAS for UPnP Framework rules.
	return L"@FirewallAPI.dll,-32752";
}

BOOL CFirewall::Init()
{
	Policy2.Release();
	Rules.Release();
	Rule.Release();

	HRESULT hr = Policy2.CoCreateInstance( __uuidof( NetFwPolicy2 ) );
	if ( ! LogFirewallInterfaceFailure( L"WFAS policy initialization", hr, Policy2 ) )
		return FALSE;

	hr = Policy2->get_Rules( &Rules );
	if ( ! LogFirewallInterfaceFailure( L"WFAS rules collection", hr, Rules ) )
		return FALSE;

	return TRUE;
}

BOOL CFirewall::FindRuleByApplication( const CString& path, INetFwRule** ppRule ) const
{
	if ( ppRule == nullptr )
		return FALSE;
	*ppRule = nullptr;

	if ( ! Rules )
		return FALSE;

	CComPtr< IUnknown > pEnumerator;
	HRESULT hr = Rules->get__NewEnum( &pEnumerator );
	if ( FAILED( hr ) || ! pEnumerator )
		return FALSE;

	CComQIPtr< IEnumVARIANT > pEnum( pEnumerator );
	if ( ! pEnum )
		return FALSE;

	const CString strWanted( path );
	for ( ;; )
	{
		CComVariant var;
		ULONG nFetched = 0;
		hr = pEnum->Next( 1, &var, &nFetched );
		if ( hr != S_OK || nFetched == 0 )
			break;

		if ( var.vt != VT_DISPATCH || var.pdispVal == nullptr )
			continue;

		CComQIPtr< INetFwRule > pRule( var.pdispVal );
		if ( ! pRule )
			continue;

		CComBSTR bstrApp;
		if ( FAILED( pRule->get_ApplicationName( &bstrApp ) ) || bstrApp.Length() == 0 )
			continue;

		if ( strWanted.CompareNoCase( CString( bstrApp ) ) == 0 )
		{
			*ppRule = pRule.Detach();
			return TRUE;
		}
	}

	return FALSE;
}

BOOL CFirewall::SetupService( NET_FW_SERVICE_TYPE service )
{
	BOOL bEnabled = FALSE;
	if ( ! IsServiceEnabled( service, &bEnabled ) )
		return FALSE;
	if ( ! bEnabled )
	{
		if ( ! EnableService( service ) )
			return FALSE;
		Sleep( 3000 );
	}
	return TRUE;
}

BOOL CFirewall::SetupProgram( const CString& path, const CString& name, BOOL bRemove )
{
	BOOL bListed = FALSE;
	if ( ! IsProgramListed( path, &bListed ) )
		return FALSE;

	if ( ! bListed && ! bRemove )
	{
		if ( ! AddProgram( path, name ) )
			return FALSE;
	}
	else if ( bListed && bRemove )
	{
		return RemoveProgram( path );
	}

	BOOL bEnabled = FALSE;
	if ( ! IsProgramEnabled( path, &bEnabled ) )
		return FALSE;
	if ( ! bEnabled )
	{
		if ( ! EnableProgram( path ) )
			return FALSE;
	}

	return TRUE;
}

BOOL CFirewall::IsProgramListed( const CString& path, BOOL* listed )
{
	if ( ! listed )
		return FALSE;
	*listed = FALSE;

	Rule.Release();
	if ( FindRuleByApplication( path, &Rule ) )
	{
		*listed = TRUE;
		return TRUE;
	}

	*listed = FALSE;
	return TRUE;	// Query succeeded; program simply not listed
}

BOOL CFirewall::IsServiceEnabled( NET_FW_SERVICE_TYPE service, BOOL* enabled )
{
	if ( ! enabled )
		return FALSE;
	*enabled = FALSE;

	if ( ! Policy2 )
	{
		LogFirewallHRESULT( L"UPnP rule-group lookup (policy unavailable)", E_NOINTERFACE );
		return FALSE;
	}

	// Only UPnP is used by Envy today (SSDP / MiniUPnPc companion exception).
	if ( service != NET_FW_SERVICE_UPNP )
		return FALSE;

	long nProfiles = 0;
	HRESULT hr = Policy2->get_CurrentProfileTypes( &nProfiles );
	if ( FAILED( hr ) || nProfiles == 0 )
		nProfiles = WFAS_PROFILE_ALL;

	VARIANT_BOOL vbEnabled = VARIANT_FALSE;
	hr = Policy2->get_IsRuleGroupCurrentlyEnabled( CComBSTR( UPnPRuleGroupName() ), &vbEnabled );
	if ( FAILED( hr ) )
	{
		// Fallback: ask whether the group is enabled on the current profile mask.
		hr = Policy2->IsRuleGroupEnabled( nProfiles, CComBSTR( UPnPRuleGroupName() ), &vbEnabled );
		if ( FAILED( hr ) )
		{
			LogFirewallHRESULT( L"UPnP rule-group state query", hr );
			return FALSE;
		}
	}

	*enabled = ( vbEnabled != VARIANT_FALSE );
	return TRUE;
}

BOOL CFirewall::IsProgramEnabled( const CString& path, BOOL* enabled )
{
	if ( ! enabled )
		return FALSE;
	*enabled = FALSE;

	BOOL bListed = FALSE;
	if ( ! IsProgramListed( path, &bListed ) )
		return FALSE;
	if ( ! bListed || ! Rule )
		return FALSE;

	VARIANT_BOOL v = VARIANT_FALSE;
	HRESULT hr = Rule->get_Enabled( &v );
	if ( FAILED( hr ) )
		return FALSE;

	*enabled = ( v != VARIANT_FALSE );
	return TRUE;
}

BOOL CFirewall::AreExceptionsAllowed() const
{
	if ( ! Policy2 )
		return FALSE;

	long nTypes = 0;
	HRESULT hr = Policy2->get_CurrentProfileTypes( &nTypes );
	if ( FAILED( hr ) )
	{
		LogFirewallHRESULT( L"current WFAS profile types query", hr );
		return FALSE;
	}

	const BOOL bDomain = ProfileAllowsExceptions( Policy2, NET_FW_PROFILE2_DOMAIN );
	const BOOL bPrivate = ProfileAllowsExceptions( Policy2, NET_FW_PROFILE2_PRIVATE );
	const BOOL bPublic = ProfileAllowsExceptions( Policy2, NET_FW_PROFILE2_PUBLIC );

	return WfasExceptionsAllowedForMask( nTypes, bDomain, bPrivate, bPublic );
}

BOOL CFirewall::AddProgram( const CString& path, const CString& name )
{
	if ( ! Rules )
		return FALSE;

	Rule.Release();
	HRESULT hr = Rule.CoCreateInstance( __uuidof( NetFwRule ) );
	if ( FAILED( hr ) || ! Rule )
		return FALSE;

	hr = Rule->put_Name( CComBSTR( name ) );
	if ( FAILED( hr ) )
		return FALSE;

	hr = Rule->put_ApplicationName( CComBSTR( path ) );
	if ( FAILED( hr ) )
		return FALSE;

	hr = Rule->put_Direction( NET_FW_RULE_DIR_IN );
	if ( FAILED( hr ) )
		return FALSE;

	hr = Rule->put_Action( NET_FW_ACTION_ALLOW );
	if ( FAILED( hr ) )
		return FALSE;

	hr = Rule->put_Protocol( NET_FW_IP_PROTOCOL_ANY );
	if ( FAILED( hr ) )
		return FALSE;

	// Register on Domain/Private/Public so Public-network hosts are covered (#166).
	hr = Rule->put_Profiles( NET_FW_PROFILE2_ALL );
	if ( FAILED( hr ) )
		return FALSE;

	hr = Rule->put_Enabled( VARIANT_TRUE );
	if ( FAILED( hr ) )
		return FALSE;

	hr = Rules->Add( Rule );
	if ( FAILED( hr ) )
	{
		LogFirewallHRESULT( L"add application rule", hr );
		return FALSE;
	}

	return TRUE;
}

BOOL CFirewall::RemoveProgram( const CString& path )
{
	if ( ! Rules )
		return FALSE;

	Rule.Release();
	if ( ! FindRuleByApplication( path, &Rule ) || ! Rule )
		return TRUE;	// Already absent

	CComBSTR bstrName;
	HRESULT hr = Rule->get_Name( &bstrName );
	if ( FAILED( hr ) || bstrName.Length() == 0 )
		return FALSE;

	hr = Rules->Remove( bstrName );
	if ( FAILED( hr ) )
	{
		LogFirewallHRESULT( L"remove application rule", hr );
		return FALSE;
	}

	Rule.Release();
	return TRUE;
}

BOOL CFirewall::EnableService( NET_FW_SERVICE_TYPE service )
{
	if ( ! Policy2 )
	{
		LogFirewallHRESULT( L"UPnP rule-group enable (policy unavailable)", E_NOINTERFACE );
		return FALSE;
	}

	if ( service != NET_FW_SERVICE_UPNP )
		return FALSE;

	const HRESULT hr = Policy2->EnableRuleGroup(
		NET_FW_PROFILE2_ALL,
		CComBSTR( UPnPRuleGroupName() ),
		VARIANT_TRUE );
	if ( FAILED( hr ) )
	{
		LogFirewallHRESULT( L"UPnP rule-group enable", hr );
		return FALSE;
	}

	return TRUE;
}

BOOL CFirewall::EnableProgram( const CString& path )
{
	BOOL bListed = FALSE;
	if ( ! IsProgramListed( path, &bListed ) )
		return FALSE;
	if ( ! bListed || ! Rule )
		return FALSE;

	const HRESULT hr = Rule->put_Enabled( VARIANT_TRUE );
	if ( FAILED( hr ) )
		return FALSE;

	return TRUE;
}
