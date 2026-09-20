//
// WizardQuickStartPolicy.h
//
// Pure QuickStart helpers (no MFC dialogs / CSettings object).
// Shared by the wizard connection/networks pages, Settings/Scheduler upload
// limit writers, and EnvyTests.
//
// Connection.InSpeed / OutSpeed store kilobits/second using the historical
// 1024-bit kilobit. Bandwidth.Uploads stores bytes/second; 0 = unlimited.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cwchar>
#include <cwctype>
#include <limits>

enum WizardBandwidthParseError
{
	WizardBandwidthParseNone = 0,
	WizardBandwidthParseEmpty,
	WizardBandwidthParseInvalid,
	WizardBandwidthParseNegative,
	WizardBandwidthParseZero,
	WizardBandwidthParseUnknownUnit,
	WizardBandwidthParseTrailingJunk,
	WizardBandwidthParseOverflow
};

enum WizardBandwidthUnit
{
	WizardBandwidthUnitKbps = 0,
	WizardBandwidthUnitMbps,
	WizardBandwidthUnitGbps
};

inline bool WizardIsFinite(double nValue)
{
	return std::isfinite(nValue) != 0;
}

inline bool WizardIsSpace(wchar_t nChar)
{
	return nChar == L' ' || nChar == L'\t' || nChar == L'\r' || nChar == L'\n';
}

inline const wchar_t* WizardSkipSpaces(const wchar_t* psz)
{
	while (psz && WizardIsSpace(*psz))
		++psz;
	return psz ? psz : L"";
}

inline bool WizardStartsWithNoCase(const wchar_t* psz, const wchar_t* pszPrefix, size_t nLen)
{
	if (!psz || !pszPrefix)
		return false;
	for (size_t i = 0; i < nLen; ++i)
	{
		if (psz[i] == 0)
			return false;
		if (towlower(static_cast<wint_t>(psz[i])) !=
		    towlower(static_cast<wint_t>(pszPrefix[i])))
			return false;
	}
	return true;
}

// Longest-match unit. Returns 0 when no recognized unit is present.
inline size_t WizardMatchBandwidthUnit(const wchar_t* psz, WizardBandwidthUnit& nUnit)
{
	static const struct
	{
		const wchar_t* pszToken;
		size_t nLen;
		WizardBandwidthUnit nUnit;
	} kUnits[] = {
		{ L"kbit/s", 6, WizardBandwidthUnitKbps },
		{ L"mbit/s", 6, WizardBandwidthUnitMbps },
		{ L"gbit/s", 6, WizardBandwidthUnitGbps },
		{ L"kbps", 4, WizardBandwidthUnitKbps },
		{ L"mbps", 4, WizardBandwidthUnitMbps },
		{ L"gbps", 4, WizardBandwidthUnitGbps },
		{ L"kb/s", 4, WizardBandwidthUnitKbps },
		{ L"mb/s", 4, WizardBandwidthUnitMbps },
		{ L"gb/s", 4, WizardBandwidthUnitGbps },
		{ L"kbit", 4, WizardBandwidthUnitKbps },
		{ L"mbit", 4, WizardBandwidthUnitMbps },
		{ L"gbit", 4, WizardBandwidthUnitGbps },
		{ L"kb", 2, WizardBandwidthUnitKbps },
		{ L"mb", 2, WizardBandwidthUnitMbps },
		{ L"gb", 2, WizardBandwidthUnitGbps },
		{ L"k", 1, WizardBandwidthUnitKbps },
		{ L"m", 1, WizardBandwidthUnitMbps },
		{ L"g", 1, WizardBandwidthUnitGbps }
	};

	for (size_t i = 0; i < sizeof(kUnits) / sizeof(kUnits[0]); ++i)
	{
		if (WizardStartsWithNoCase(psz, kUnits[i].pszToken, kUnits[i].nLen))
		{
			const wchar_t nNext = psz[kUnits[i].nLen];
			if (nNext == 0 || WizardIsSpace(nNext) || nNext == L'(')
			{
				nUnit = kUnits[i].nUnit;
				return kUnits[i].nLen;
			}
		}
	}
	return 0;
}

inline bool WizardSkipOptionalDisplaySuffix(const wchar_t*& psz, WizardBandwidthParseError& nError)
{
	psz = WizardSkipSpaces(psz);
	if (*psz == L'(')
	{
		++psz;
		while (*psz && *psz != L')')
			++psz;
		if (*psz != L')')
		{
			nError = WizardBandwidthParseTrailingJunk;
			return false;
		}
		++psz;
		psz = WizardSkipSpaces(psz);
	}
	if (*psz != 0)
	{
		nError = WizardBandwidthParseTrailingJunk;
		return false;
	}
	return true;
}

inline std::uint32_t WizardBandwidthMultiplier(WizardBandwidthUnit nUnit)
{
	if (nUnit == WizardBandwidthUnitGbps)
		return 1024u * 1024u;
	if (nUnit == WizardBandwidthUnitMbps)
		return 1024u;
	return 1u;
}

// Strict parser. Does not repair malformed text into a valid value.
// Bare numbers are kbps. Optional "(...)" after a unit is the combo display.
inline bool ParseWizardBandwidthKbps(const wchar_t* pszText, std::uint32_t& nKbps, WizardBandwidthParseError& nError)
{
	nKbps = 0;
	nError = WizardBandwidthParseNone;

	const wchar_t* psz = WizardSkipSpaces(pszText);
	if (psz == NULL || *psz == 0)
	{
		nError = WizardBandwidthParseEmpty;
		return false;
	}
	if (*psz == L'-')
	{
		nError = WizardBandwidthParseNegative;
		return false;
	}

	errno = 0;
	wchar_t* pszEnd = NULL;
	const double nValue = wcstod(psz, &pszEnd);
	if (pszEnd == psz)
	{
		nError = WizardBandwidthParseInvalid;
		return false;
	}
	if (errno == ERANGE || !WizardIsFinite(nValue))
	{
		nError = WizardBandwidthParseOverflow;
		return false;
	}
	if (nValue < 0.0)
	{
		nError = WizardBandwidthParseNegative;
		return false;
	}

	psz = WizardSkipSpaces(pszEnd);
	WizardBandwidthUnit nUnit = WizardBandwidthUnitKbps;
	const size_t nUnitLen = WizardMatchBandwidthUnit(psz, nUnit);
	if (nUnitLen == 0)
	{
		if (*psz != 0 && *psz != L'(')
		{
			nError = WizardBandwidthParseUnknownUnit;
			return false;
		}
		nUnit = WizardBandwidthUnitKbps;
	}
	else
	{
		psz += nUnitLen;
	}

	if (!WizardSkipOptionalDisplaySuffix(psz, nError))
		return false;

	if (nValue == 0.0)
	{
		nError = WizardBandwidthParseZero;
		return false;
	}

	const double nMultiplier = static_cast<double>(WizardBandwidthMultiplier(nUnit));
	const double nMaxKbps = static_cast<double>((std::numeric_limits<std::uint32_t>::max)());
	if (nValue > (nMaxKbps / nMultiplier))
	{
		nError = WizardBandwidthParseOverflow;
		return false;
	}

	const double nScaled = nValue * nMultiplier;
	if (!WizardIsFinite(nScaled) || nScaled > nMaxKbps)
	{
		nError = WizardBandwidthParseOverflow;
		return false;
	}

	const std::uint32_t nRounded = static_cast<std::uint32_t>(nScaled + 0.5);
	if (nRounded == 0)
	{
		nError = WizardBandwidthParseZero;
		return false;
	}

	nKbps = nRounded;
	return true;
}

inline std::uint32_t WizardFreeBandwidthFactorClamp(std::uint32_t nFactor)
{
	return nFactor > 99u ? 99u : nFactor;
}

// Keep (100 - FreeBandwidthFactor)% of OutSpeed, convert kbps to bytes/s,
// then floor to a whole KiB/s. Matches the Scheduler/comment semantics
// ("trimmed down to nearest KB") without 32-bit percentage truncation.
// Result 0 keeps the existing Bandwidth.Uploads unlimited meaning.
inline std::uint32_t WizardUploadLimitBytesPerSecond(std::uint32_t nOutSpeedKbps, std::uint32_t nFreeBandwidthFactor)
{
	const std::uint32_t nFactor = WizardFreeBandwidthFactorClamp(nFreeBandwidthFactor);
	const std::uint64_t nKept = 100ull - nFactor;
	const std::uint64_t nKeptKbps = (static_cast<std::uint64_t>(nOutSpeedKbps) * nKept) / 100ull;
	const std::uint64_t nKBps = nKeptKbps / 8ull;
	const std::uint64_t nBytes = nKBps * 1024ull;
	if (nBytes == 0)
		return 0;
	if (nBytes > 0xFFFFFFFFull)
		return 0xFFFFFFFFu;
	return static_cast<std::uint32_t>(nBytes);
}

// Documented listen-port policy for QuickStart (unprivileged TCP).
inline bool WizardListenPortIsValid(std::uint32_t nPort)
{
	return nPort >= 1024u && nPort <= 65535u;
}

inline std::uint32_t WizardListenPortMin()
{
	return 1024u;
}

inline std::uint32_t WizardListenPortMax()
{
	return 65535u;
}

// Connection page must not bootstrap or connect; network choices come later.
inline bool WizardConnectionPageMayBootstrap()
{
	return false;
}

inline bool WizardShouldBootstrapEd2k(bool bEd2kEnabled, std::uint32_t nServerCount, std::uint32_t nMinimum = 3u)
{
	return bEd2kEnabled && nServerCount < nMinimum;
}

inline bool WizardShouldBootstrapDc(bool bDcEnabled, std::uint32_t nHubCount, std::uint32_t nMinimum = 5u)
{
	return bDcEnabled && nHubCount < nMinimum;
}

inline bool WizardShouldConnectNetworks(bool bG1, bool bG2, bool bEd2k, bool bDc, bool bBitTorrent)
{
	return bG1 || bG2 || bEd2k || bDc || bBitTorrent;
}

// Settings.Web.Torrent is a file association, not Settings.BitTorrent.Enabled.
inline bool WizardTorrentAssociationIndependentOfEngine()
{
	return true;
}
