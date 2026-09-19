//
// DcAdcGetValidate.h
//
// Pure NMDC $ADCGET / $ADCSND offset and length token predicates.
// Shared by CDCClient / CDownloadTransferDC and EnvyTests (#81 / PR).
//
// NMDC 1.5: $ADCGET length may be exactly "-1" (until end of file).
// $ADCSND must announce a real non-negative byte count (-1 is invalid).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <stddef.h>
#include <windows.h>

// Same sentinel as Envy SIZE_UNKNOWN (~0ULL); keep this header MFC-free.
// Reserved for the literal "-1" $ADCGET length token only — never accepted
// as an all-digits unsigned decimal (would collide with 2^64-1).
constexpr ULONGLONG DC_ADC_LENGTH_UNTIL_END = ~0ULL;

// Strict unsigned decimal [0-9]+ over exactly nLen bytes. Rejects empty,
// embedded NULs / junk, leading signs, and values at or above 2^64-1 so
// DC_ADC_LENGTH_UNTIL_END stays reserved for the "-1" token.
inline BOOL DcParseUnsignedDecimalU64(const char* psz, size_t nLen, ULONGLONG* pnOut)
{
	if (!psz || !pnOut || nLen == 0)
		return FALSE;

	ULONGLONG nValue = 0;

	for (size_t i = 0; i < nLen; ++i)
	{
		const char c = psz[i];
		if (c < '0' || c > '9')
			return FALSE;

		const unsigned nDigit = static_cast<unsigned>(c - '0');
		// Cap at 2^64-2: reject any digit that would reach ~0ULL.
		if (nValue > (DC_ADC_LENGTH_UNTIL_END - 1ULL - nDigit) / 10ULL)
			return FALSE;
		nValue = nValue * 10ULL + nDigit;
	}

	*pnOut = nValue;
	return TRUE;
}

// $ADCGET / $ADCSND offset: unsigned decimal only (no leading '-').
inline BOOL DcParseAdcOffsetToken(const char* psz, size_t nLen, ULONGLONG* pnOffset)
{
	return DcParseUnsignedDecimalU64(psz, nLen, pnOffset);
}

// $ADCGET length: unsigned decimal, or exactly "-1" -> until-end sentinel.
inline BOOL DcParseAdcGetLengthToken(const char* psz, size_t nLen, ULONGLONG* pnLength)
{
	if (!psz || !pnLength || nLen == 0)
		return FALSE;

	if (nLen == 2 && psz[0] == '-' && psz[1] == '1')
	{
		*pnLength = DC_ADC_LENGTH_UNTIL_END;
		return TRUE;
	}

	return DcParseUnsignedDecimalU64(psz, nLen, pnLength);
}

// $ADCSND length: unsigned decimal only; "-1" and 2^64-1 are invalid.
inline BOOL DcParseAdcSndLengthToken(const char* psz, size_t nLen, ULONGLONG* pnLength)
{
	return DcParseUnsignedDecimalU64(psz, nLen, pnLength);
}

// After a fixed-length $ADCGET, $ADCSND must announce the same byte count.
// After an until-end $ADCGET (request sentinel), $ADCSND must announce a
// real length (not the until-end sentinel).
inline BOOL DcAdcSndLengthMatchesRequest(ULONGLONG nRequested, ULONGLONG nAnnounced)
{
	if (nRequested == DC_ADC_LENGTH_UNTIL_END)
		return nAnnounced != DC_ADC_LENGTH_UNTIL_END;

	return nRequested == nAnnounced;
}
