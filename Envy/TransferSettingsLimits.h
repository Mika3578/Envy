//
// TransferSettingsLimits.h
//
// Pure helpers for transfer-settings limits (no MFC CSettings / dialogs).
// Shared by the Uploads/Downloads settings pages and EnvyTests.
//
// Bandwidth.Uploads / Bandwidth.Downloads store bytes/second. 0 = unlimited.
// Uploads.MaxPerHost is simultaneous upload transfers (upsUploading +
// upsQueued, plus upsPreQueue in EnforcePerHostLimit) per IPv4 address.
//
// Legacy UI tokens MAX and NONE remain accepted. Display uses "Unlimited"
// (IDS_SETTINGS_BANDWIDTH_UNLIMITED) plus the current language string.
//
// Uploads.FairUseMode is persisted for old profiles but has no core consumer.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <cwchar>
#include <cwctype>
#include <windows.h>

inline DWORD TransferBandwidthUnlimitedValue()
{
	return 0;
}

inline const wchar_t* TransferBandwidthUnlimitedDisplayToken()
{
	return L"Unlimited";
}

inline DWORD TransferMaxPerHostDefault()
{
	return 2;
}

inline DWORD TransferMaxPerHostMin()
{
	return 1;
}

inline DWORD TransferMaxPerHostMax()
{
	return 64;
}

inline bool TransferThrottleModeDefault()
{
	return false;	// Average (soft) limit
}

inline bool TransferFairUseModeDefault()
{
	return false;
}

inline bool TransferFairUseModeImplemented()
{
	return false;
}

inline bool TransferBandwidthSettingIsUnlimited(DWORD nBytesPerSecond)
{
	return nBytesPerSecond == TransferBandwidthUnlimitedValue();
}

inline DWORD TransferBandwidthBytesToSetting(unsigned long long nBytes)
{
	if ( nBytes == 0 )
		return TransferBandwidthUnlimitedValue();
	if ( nBytes > 0xFFFFFFFFull )
		return 0xFFFFFFFFul;
	return static_cast< DWORD >( nBytes );
}

inline DWORD TransferMaxPerHostClamp(unsigned long long nValue)
{
	if ( nValue < TransferMaxPerHostMin() )
		return TransferMaxPerHostMin();
	if ( nValue > TransferMaxPerHostMax() )
		return TransferMaxPerHostMax();
	return static_cast< DWORD >( nValue );
}

inline DWORD TransferMaxPerHostFromSigned(long long nValue)
{
	if ( nValue < 0 )
		return TransferMaxPerHostMin();
	return TransferMaxPerHostClamp( static_cast< unsigned long long >( nValue ) );
}

inline const wchar_t* TransferBandwidthTokenSkipPrefix(const wchar_t* pszText)
{
	if ( pszText == NULL )
		return L"";
	if ( *pszText == 0x200E )
		++pszText;
	while ( *pszText == L' ' || *pszText == L'\t' )
		++pszText;
	return pszText;
}

inline bool TransferWcsContainsNoCase(const wchar_t* pszHaystack, const wchar_t* pszNeedle)
{
	if ( pszHaystack == NULL || pszNeedle == NULL || *pszNeedle == 0 )
		return false;

	for ( const wchar_t* p = pszHaystack; *p; ++p )
	{
		const wchar_t* a = p;
		const wchar_t* b = pszNeedle;
		while ( *a && *b && towlower( static_cast< wint_t >( *a ) ) ==
			towlower( static_cast< wint_t >( *b ) ) )
		{
			++a;
			++b;
		}
		if ( *b == 0 )
			return true;
	}
	return false;
}

// True when the combo/edit text means unlimited.
// Legacy: empty, MAX, NONE. Current display: Unlimited plus optional locale.
// Note: "MAX" is a substring, matching the historical _tcsistr("MAX") check
// (so "MAXIMUM" is also treated as unlimited).
inline bool TransferBandwidthTokenIsUnlimited(const wchar_t* pszText,
	const wchar_t* pszLocalizedUnlimited = NULL)
{
	const wchar_t* psz = TransferBandwidthTokenSkipPrefix( pszText );
	if ( *psz == 0 )
		return true;

	if ( TransferWcsContainsNoCase( psz, L"MAX" ) ||
		TransferWcsContainsNoCase( psz, L"NONE" ) ||
		TransferWcsContainsNoCase( psz, L"UNLIMITED" ) )
	{
		return true;
	}

	if ( pszLocalizedUnlimited && *pszLocalizedUnlimited &&
		TransferWcsContainsNoCase( psz, pszLocalizedUnlimited ) )
	{
		return true;
	}

	return false;
}
