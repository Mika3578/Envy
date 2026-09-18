//
// FirewallWfasPolicy.h
//
// Pure helpers for Windows Firewall with Advanced Security (WFAS) profile
// bitmasks (#166 / D-009 P1). No COM — shared with EnvyTests.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <windows.h>

// Mirror NET_FW_PROFILE2_* from netfw.h without requiring the SDK header in tests.
constexpr long WFAS_PROFILE_DOMAIN  = 0x1L;
constexpr long WFAS_PROFILE_PRIVATE = 0x2L;
constexpr long WFAS_PROFILE_PUBLIC  = 0x4L;
constexpr long WFAS_PROFILE_ALL     = ( WFAS_PROFILE_DOMAIN | WFAS_PROFILE_PRIVATE | WFAS_PROFILE_PUBLIC );

inline BOOL WfasProfileBitEnabled( long nMask, long nProfileBit )
{
	return ( nMask & nProfileBit ) != 0;
}

// True when every set profile bit in nMask reports exceptions allowed
// (blockAllInbound == FALSE). Empty mask → FALSE.
inline BOOL WfasExceptionsAllowedForMask( long nMask, BOOL bDomainAllows, BOOL bPrivateAllows, BOOL bPublicAllows )
{
	if ( nMask == 0 )
		return FALSE;

	if ( WfasProfileBitEnabled( nMask, WFAS_PROFILE_DOMAIN ) && ! bDomainAllows )
		return FALSE;
	if ( WfasProfileBitEnabled( nMask, WFAS_PROFILE_PRIVATE ) && ! bPrivateAllows )
		return FALSE;
	if ( WfasProfileBitEnabled( nMask, WFAS_PROFILE_PUBLIC ) && ! bPublicAllows )
		return FALSE;

	// At least one known profile bit must be present and allowed.
	const BOOL bAny =
		( WfasProfileBitEnabled( nMask, WFAS_PROFILE_DOMAIN ) && bDomainAllows )
		|| ( WfasProfileBitEnabled( nMask, WFAS_PROFILE_PRIVATE ) && bPrivateAllows )
		|| ( WfasProfileBitEnabled( nMask, WFAS_PROFILE_PUBLIC ) && bPublicAllows );
	return bAny;
}
