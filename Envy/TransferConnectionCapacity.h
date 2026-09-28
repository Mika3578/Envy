//
// TransferConnectionCapacity.h
//
// Canonical connection capacity presets (Kb/s) and pure parsing helpers.
// Shared by Connection settings, the connection wizard, and EnvyTests.
//
// Connection.InSpeed / OutSpeed are declared link capacity in kilobits per second.
// They are not user transfer-rate caps (see TransferSettingsLimits.h).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include "TransferSettingsLimits.h"

#include <cmath>
#include <cwchar>
#include <cwctype>

namespace TransferConnectionCapacityDetail
{
static const DWORD kPresets[] = {
	56, 128, 256, 384, 512, 640, 768, 1024, 1544, 1550, 2048, 3072, 4096, 5120,
	8192, 10240, 12288, 16384, 20480, 24576, 25400, 30720, 44800, 45000, 50800,
	77000, 102400, 155000, 204800, 307200, 409600, 512000, 972800, 1024000,
	2621440, 5242880, 10485760
};
static const unsigned int kPresetCount =
    static_cast<unsigned int>(sizeof(kPresets) / sizeof(kPresets[0]));

struct WizardProfile
{
	DWORD nDownloadKilobits;
	DWORD nUploadKilobits;
};

static const WizardProfile kWizardProfiles[] = {
	{ 56, 36 }, { 128, 128 }, { 768, 128 }, { 1536, 256 }, { 3100, 2040 }, { 4096, 768 }, { 8192, 1024 }, { 10240, 2048 }, { 12288, 2048 }, { 16384, 5120 }, { 20480, 5120 }, { 25400, 10240 }, { 30720, 10240 }, { 50800, 20480 }, { 102400, 102400 }, { 204800, 204800 }, { 307200, 307200 }, { 409600, 409600 }, { 1024000, 921600 }, { 1544, 1544 }, { 44800, 44800 }, { 102400, 102400 }, { 155000, 155000 }
};
static const unsigned int kWizardProfileCount =
    static_cast<unsigned int>(sizeof(kWizardProfiles) / sizeof(kWizardProfiles[0]));
} // namespace TransferConnectionCapacityDetail

inline unsigned int TransferConnectionCapacityPresetCount()
{
	return TransferConnectionCapacityDetail::kPresetCount;
}

inline DWORD TransferConnectionCapacityPresetKilobits(unsigned int nIndex)
{
	if (nIndex >= TransferConnectionCapacityDetail::kPresetCount)
		return 0;
	return TransferConnectionCapacityDetail::kPresets[nIndex];
}

inline unsigned int TransferConnectionCapacityWizardProfileCount()
{
	return TransferConnectionCapacityDetail::kWizardProfileCount;
}

inline DWORD TransferConnectionCapacityWizardProfileDownload(unsigned int nIndex)
{
	if (nIndex >= TransferConnectionCapacityDetail::kWizardProfileCount)
		return 0;
	return TransferConnectionCapacityDetail::kWizardProfiles[nIndex].nDownloadKilobits;
}

inline DWORD TransferConnectionCapacityWizardProfileUpload(unsigned int nIndex)
{
	if (nIndex >= TransferConnectionCapacityDetail::kWizardProfileCount)
		return 0;
	return TransferConnectionCapacityDetail::kWizardProfiles[nIndex].nUploadKilobits;
}

inline bool TransferConnectionCapacityShouldSyncUploadLimitOnConnectionApply()
{
	return false;
}

inline bool TransferConnectionCapacityShouldSetWizardUploadDefault(bool bFirstRun)
{
	return bFirstRun;
}

// Connection settings Apply: preserve explicit Bandwidth.Uploads (OutSpeed is capacity only).
inline DWORD TransferBandwidthUploadAfterConnectionSettingsApply(DWORD nExistingUploadsBytesPerSecond,
                                                                 DWORD nOutSpeedKilobitsPerSecond,
                                                                 unsigned int nFreeBandwidthFactor)
{
	if (TransferConnectionCapacityShouldSyncUploadLimitOnConnectionApply())
	{
		return TransferBandwidthUploadLimitFromOutboundKilobits(nOutSpeedKilobitsPerSecond,
		                                                        nFreeBandwidthFactor);
	}
	return nExistingUploadsBytesPerSecond;
}

enum class TransferConnectionCapacityParseStatus
{
	Ok,
	Malformed,
	Negative,
	Overflow
};

struct TransferConnectionCapacityParseResult
{
	TransferConnectionCapacityParseStatus eStatus;
	unsigned long long nKilobitsPerSecond;
};

inline const wchar_t* TransferConnectionCapacitySkipLeadingSpace(const wchar_t* psz)
{
	if (psz == NULL)
		return L"";
	if (*psz == 0x200E)
		++psz;
	while (*psz == L' ' || *psz == L'\t')
		++psz;
	return psz;
}

inline bool TransferConnectionCapacityContainsUnit(const wchar_t* psz, const wchar_t* pszUnit)
{
	return TransferWcsContainsNoCase(psz, pszUnit);
}

inline bool TransferConnectionCapacityContainsByteUnit(const wchar_t* psz)
{
	return wcsstr(psz, L"B/s") != NULL || wcsstr(psz, L"KB/s") != NULL ||
	       wcsstr(psz, L"MB/s") != NULL || wcsstr(psz, L"GB/s") != NULL;
}

// Parse wizard / connection free-text capacity into Kb/s (multigig-safe).
inline TransferConnectionCapacityParseResult TransferConnectionCapacityParseKilobitsText(
    const wchar_t* pszText)
{
	TransferConnectionCapacityParseResult oResult = {};
	oResult.eStatus = TransferConnectionCapacityParseStatus::Malformed;

	const wchar_t* psz = TransferConnectionCapacitySkipLeadingSpace(pszText);
	if (*psz == 0)
		return oResult;

	double val = 0.0;
	if (swscanf(psz, L"%lf", &val) != 1)
		return oResult;
	if (!std::isfinite(val) || val < 0.0)
	{
		oResult.eStatus = TransferConnectionCapacityParseStatus::Negative;
		return oResult;
	}

	// Wizard combo text includes byte/sec hints in "(...)"; ignore those for unit detection.
	wchar_t szUnitScan[192] = {};
	const wchar_t* pszUnits = psz;
	const wchar_t* pszParen = wcschr(psz, L'(');
	if (pszParen != NULL && pszParen > psz)
	{
		const size_t nMax = sizeof(szUnitScan) / sizeof(szUnitScan[0]);
		size_t nChars = static_cast<size_t>(pszParen - psz);
		size_t i = 0;
		for (; i < nChars && i + 1 < nMax; ++i)
			szUnitScan[i] = psz[i];
		szUnitScan[i] = L'\0';
		pszUnits = szUnitScan;
	}

	if (TransferConnectionCapacityContainsByteUnit(pszUnits))
		return oResult;

	const bool bGigabit = TransferConnectionCapacityContainsUnit(pszUnits, L"gbps") ||
	                      TransferConnectionCapacityContainsUnit(pszUnits, L"gb/s");
	const bool bMegabit = !bGigabit &&
	                      (TransferConnectionCapacityContainsUnit(pszUnits, L"mbps") ||
	                       TransferConnectionCapacityContainsUnit(pszUnits, L"mb/s"));
	const bool bKilobit = !bGigabit && !bMegabit &&
	                      (TransferConnectionCapacityContainsUnit(pszUnits, L"kbps") ||
	                       TransferConnectionCapacityContainsUnit(pszUnits, L"kb/s"));

	unsigned long long nKilobits = 0;
	if (bKilobit)
	{
		if (val > static_cast<double>(0xFFFFFFFFull))
		{
			oResult.eStatus = TransferConnectionCapacityParseStatus::Overflow;
			return oResult;
		}
		nKilobits = static_cast<unsigned long long>(val);
	}
	else if (bGigabit)
	{
		const double nScaled = val * 1024.0 * 1024.0;
		if (nScaled > static_cast<double>(0xFFFFFFFFull))
		{
			oResult.eStatus = TransferConnectionCapacityParseStatus::Overflow;
			return oResult;
		}
		nKilobits = static_cast<unsigned long long>(nScaled);
	}
	else if (bMegabit)
	{
		const double nScaled = val * 1024.0;
		if (nScaled > static_cast<double>(0xFFFFFFFFull))
		{
			oResult.eStatus = TransferConnectionCapacityParseStatus::Overflow;
			return oResult;
		}
		nKilobits = static_cast<unsigned long long>(nScaled);
	}
	else
	{
		// kbps / Kb/s or bare number from "NNNN kbps (...)" wizard strings.
		if (val > static_cast<double>(0xFFFFFFFFull))
		{
			oResult.eStatus = TransferConnectionCapacityParseStatus::Overflow;
			return oResult;
		}
		nKilobits = static_cast<unsigned long long>(val);
	}

	if (nKilobits < 2)
	{
		oResult.eStatus = TransferConnectionCapacityParseStatus::Malformed;
		return oResult;
	}

	oResult.eStatus = TransferConnectionCapacityParseStatus::Ok;
	oResult.nKilobitsPerSecond = nKilobits;
	return oResult;
}

inline DWORD TransferConnectionCapacityParseKilobitsTextDword(const wchar_t* pszText)
{
	const TransferConnectionCapacityParseResult oParsed =
	    TransferConnectionCapacityParseKilobitsText(pszText);
	if (oParsed.eStatus != TransferConnectionCapacityParseStatus::Ok)
		return 0;
	if (oParsed.nKilobitsPerSecond > 0xFFFFFFFFull)
		return 0xFFFFFFFFu;
	return static_cast<DWORD>(oParsed.nKilobitsPerSecond);
}
