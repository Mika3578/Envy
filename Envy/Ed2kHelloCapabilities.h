//
// Ed2kHelloCapabilities.h
//
// Pure ED2K/eMule Hello FeatureVersions packing helpers (no network / MFC).
// Shared by CEDClient::SendHello and EnvyTests smoke tests.
//
// Advertising rule (#87): Hello capability bits must match implemented
// behavior. Do not advertise incomplete capabilities.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <windows.h>

#include "SecureIdentPolicy.h"

// AICH FeatureVersions nibble (bits 29-31 of MiscOptions1 / CT_FEATUREVERSIONS).
// Local AICH hashing may exist (CAICHManager), but C2C AICH request/answer
// handlers are not implemented. Advertise 0 until wire recovery works.
inline BYTE Ed2kAichAdvertisedVersion()
{
	return 0;
}

// CryptLayer bits in MiscOptions2 (eMule CT_MOREFEATUREVERSIONS / MISCOPTIONS2):
//   bit 7 Supports, bit 8 Requests, bit 9 Requires
// Envy currently has packet-level PUBLICKEY/ANSWERCryptLayer helpers, but that
// is not proven equivalent to eMule/aMule TCP protocol-obfuscation semantics.
// Keep all three at 0 until a dedicated obfuscation interop audit lands.
inline BOOL Ed2kCryptLayerSupportsAdvertised()
{
	return FALSE;
}

inline BOOL Ed2kCryptLayerRequestsAdvertised()
{
	return FALSE;
}

inline BOOL Ed2kCryptLayerRequiresAdvertised()
{
	return FALSE;
}

// Pack MiscOptions1 / ED2K_CT_FEATUREVERSIONS (layout matches eMule).
inline DWORD Ed2kPackFeatureVersions1(
	BYTE nAichVersion,
	BOOL bUnicode,
	BYTE nUdpVersion,
	BYTE nCompressionVersion,
	BYTE nSecureIdentVersion,
	BYTE nSourceExchangeVersion,
	BYTE nExtendedRequestVersion,
	BYTE nCommentsVersion,
	BOOL bPreview)
{
	return ( ( (DWORD)( nAichVersion & 0x07 ) << 29 ) |
			 ( ( bUnicode ? 1u : 0u ) << 28 ) |
			 ( (DWORD)( nUdpVersion & 0x0F ) << 24 ) |
			 ( (DWORD)( nCompressionVersion & 0x0F ) << 20 ) |
			 ( (DWORD)( nSecureIdentVersion & 0x0F ) << 16 ) |
			 ( (DWORD)( nSourceExchangeVersion & 0x0F ) << 12 ) |
			 ( (DWORD)( nExtendedRequestVersion & 0x0F ) << 8 ) |
			 ( (DWORD)( nCommentsVersion & 0x0F ) << 4 ) |
			 ( bPreview ? 1u : 0u ) );
}

// Pack MiscOptions2 / ED2K_CT_MOREFEATUREVERSIONS (layout matches eMule).
inline DWORD Ed2kPackFeatureVersions2(
	BOOL bCaptcha,
	BOOL bSourceExchange2,
	BOOL bRequiresCryptLayer,
	BOOL bRequestsCryptLayer,
	BOOL bSupportsCryptLayer,
	BOOL bExtMultipacket,
	BOOL bLargeFiles,
	BYTE nKadVersion)
{
	// eMule clamps request/require against support.
	const BOOL bSupports = bSupportsCryptLayer ? TRUE : FALSE;
	const BOOL bRequests = ( bRequestsCryptLayer && bSupports ) ? TRUE : FALSE;
	const BOOL bRequires = ( bRequiresCryptLayer && bRequests ) ? TRUE : FALSE;

	return ( ( ( bCaptcha ? 1u : 0u ) << 11 ) |
			 ( ( bSourceExchange2 ? 1u : 0u ) << 10 ) |
			 ( ( bRequires ? 1u : 0u ) << 9 ) |
			 ( ( bRequests ? 1u : 0u ) << 8 ) |
			 ( ( bSupports ? 1u : 0u ) << 7 ) |
			 ( ( bExtMultipacket ? 1u : 0u ) << 5 ) |
			 ( ( bLargeFiles ? 1u : 0u ) << 4 ) |
			 ( (DWORD)( nKadVersion & 0x0F ) ) );
}

// Extractors for tests / debug.
inline BYTE Ed2kFeatureVersions1Aich(DWORD nOpt1)
{
	return (BYTE)( ( nOpt1 >> 29 ) & 0x07 );
}

inline BYTE Ed2kFeatureVersions1SecureIdent(DWORD nOpt1)
{
	return (BYTE)( ( nOpt1 >> 16 ) & 0x0F );
}

inline BOOL Ed2kFeatureVersions2SupportsCrypt(DWORD nOpt2)
{
	return ( ( nOpt2 >> 7 ) & 0x01 ) != 0;
}

inline BOOL Ed2kFeatureVersions2RequestsCrypt(DWORD nOpt2)
{
	return ( ( nOpt2 >> 8 ) & 0x01 ) != 0;
}

inline BOOL Ed2kFeatureVersions2RequiresCrypt(DWORD nOpt2)
{
	return ( ( nOpt2 >> 9 ) & 0x01 ) != 0;
}
