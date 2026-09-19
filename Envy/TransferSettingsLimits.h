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
// Uploads.FairUseMode: when true, each remote IPv4 client may receive at most
// 10% of an audio/video library file (schema Audio.xsd / Video.xsd). Partials
// and BitTorrent are not limited. Settings.cpp Add() defaults must stay equal
// to the constants below.
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
	return false; // Average (soft) limit
}

inline bool TransferFairUseModeDefault()
{
	return false;
}

inline bool TransferFairUseModeImplemented()
{
	return true;
}

inline unsigned int TransferFairUseSharePercent()
{
	return 10;
}

inline unsigned int TransferFairUseGrantLimit()
{
	return 4096;
}

// Audio/video library files (including extension-guessed schema). Historical
// "unknown audio/video" maps to this media class, not to missing metadata.
inline bool TransferFairUseIsMedia(bool bAudio, bool bVideo)
{
	return bAudio || bVideo;
}

inline bool TransferFairUseApplies(bool bEnabled, bool bMedia, bool bPartial, bool bBitTorrent)
{
	return bEnabled && bMedia && !bPartial && !bBitTorrent;
}

// 10% of nFileSize, overflow-safe. Empty files: 0. Files under 10 bytes: 1.
inline unsigned long long TransferFairUseMaxBytes(unsigned long long nFileSize)
{
	const unsigned int nPercent = TransferFairUseSharePercent();
	if (nFileSize == 0 || nPercent == 0)
		return 0;
	if (nPercent >= 100)
		return nFileSize;

	const unsigned long long nMax = (nFileSize / 100ull) * nPercent + ((nFileSize % 100ull) * nPercent) / 100ull;
	return nMax == 0 ? 1ull : nMax;
}

// Clip [nOffset, nOffset+nLength) so newly granted bytes stay within the 10%
// cap minus nAlreadyGranted. Returns false when nothing may be sent.
inline bool TransferFairUseClipRange(unsigned long long& nOffset, unsigned long long& nLength, unsigned long long nFileSize, unsigned long long nAlreadyGranted)
{
	if (nFileSize == 0 || nLength == 0 || nOffset >= nFileSize)
		return false;

	const unsigned long long nToEnd = nFileSize - nOffset;
	if (nLength > nToEnd)
		nLength = nToEnd;

	const unsigned long long nMax = TransferFairUseMaxBytes(nFileSize);
	if (nAlreadyGranted >= nMax)
		return false;

	const unsigned long long nRemain = nMax - nAlreadyGranted;
	if (nLength > nRemain)
		nLength = nRemain;

	return nLength > 0;
}

inline bool TransferBandwidthSettingIsUnlimited(DWORD nBytesPerSecond)
{
	return nBytesPerSecond == TransferBandwidthUnlimitedValue();
}

inline DWORD TransferBandwidthBytesToSetting(unsigned long long nBytes)
{
	if (nBytes == 0)
		return TransferBandwidthUnlimitedValue();
	if (nBytes > 0xFFFFFFFFull)
		return 0xFFFFFFFFul;
	return static_cast<DWORD>(nBytes);
}

inline DWORD TransferMaxPerHostClamp(unsigned long long nValue)
{
	if (nValue < TransferMaxPerHostMin())
		return TransferMaxPerHostMin();
	if (nValue > TransferMaxPerHostMax())
		return TransferMaxPerHostMax();
	return static_cast<DWORD>(nValue);
}

inline DWORD TransferMaxPerHostFromSigned(long long nValue)
{
	if (nValue < 0)
		return TransferMaxPerHostMin();
	return TransferMaxPerHostClamp(static_cast<unsigned long long>(nValue));
}

inline const wchar_t* TransferBandwidthTokenSkipPrefix(const wchar_t* pszText)
{
	if (pszText == NULL)
		return L"";
	if (*pszText == 0x200E)
		++pszText;
	while (*pszText == L' ' || *pszText == L'\t')
		++pszText;
	return pszText;
}

inline bool TransferWcsContainsNoCase(const wchar_t* pszHaystack, const wchar_t* pszNeedle)
{
	if (pszHaystack == NULL || pszNeedle == NULL || *pszNeedle == 0)
		return false;

	for (const wchar_t* p = pszHaystack; *p; ++p)
	{
		const wchar_t* a = p;
		const wchar_t* b = pszNeedle;
		while (*a && *b && towlower(static_cast<wint_t>(*a)) == towlower(static_cast<wint_t>(*b)))
		{
			++a;
			++b;
		}
		if (*b == 0)
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
	const wchar_t* psz = TransferBandwidthTokenSkipPrefix(pszText);
	if (*psz == 0)
		return true;

	if (TransferWcsContainsNoCase(psz, L"MAX") ||
	    TransferWcsContainsNoCase(psz, L"NONE") ||
	    TransferWcsContainsNoCase(psz, L"UNLIMITED"))
	{
		return true;
	}

	if (pszLocalizedUnlimited && *pszLocalizedUnlimited &&
	    TransferWcsContainsNoCase(psz, pszLocalizedUnlimited))
	{
		return true;
	}

	return false;
}
