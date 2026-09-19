//
// DcAdcGetValidate.h
//
// Pure NMDC $ADCGET / $ADCSND offset and length token predicates.
// Shared by CDCClient / CDownloadTransferDC and EnvyTests.
//
// NMDC 1.5: $ADCGET length may be exactly "-1" (until end of file).
// $ADCSND must announce a real non-negative byte count (-1 is invalid).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <windows.h>
#include <string.h>

// Same sentinel as Envy SIZE_UNKNOWN (~0ull); keep this header MFC-free.
constexpr ULONGLONG DC_ADC_LENGTH_UNTIL_END = ~0ull;

// Strict unsigned decimal [0-9]+ for the entire C string. Rejects empty,
// leading signs, partial tokens (e.g. "123x"), and overflow past 2^64-1.
inline BOOL DcParseUnsignedDecimalU64(const char* psz, ULONGLONG* pnOut)
{
	if ( ! psz || ! pnOut || *psz == '\0' )
		return FALSE;

	ULONGLONG nValue = 0;
	BOOL bDigit = FALSE;

	for ( const char* p = psz; *p; ++p )
	{
		if ( *p < '0' || *p > '9' )
			return FALSE;

		bDigit = TRUE;
		const unsigned nDigit = static_cast< unsigned >( *p - '0' );
		if ( nValue > ( DC_ADC_LENGTH_UNTIL_END - nDigit ) / 10ull )
			return FALSE;
		nValue = nValue * 10ull + nDigit;
	}

	if ( ! bDigit )
		return FALSE;

	*pnOut = nValue;
	return TRUE;
}

// $ADCGET / $ADCSND offset: unsigned decimal only (no leading '-').
inline BOOL DcParseAdcOffsetToken(const char* psz, ULONGLONG* pnOffset)
{
	return DcParseUnsignedDecimalU64( psz, pnOffset );
}

// $ADCGET length: unsigned decimal, or exactly "-1" -> until-end sentinel.
inline BOOL DcParseAdcGetLengthToken(const char* psz, ULONGLONG* pnLength)
{
	if ( ! psz || ! pnLength )
		return FALSE;

	if ( strcmp( psz, "-1" ) == 0 )
	{
		*pnLength = DC_ADC_LENGTH_UNTIL_END;
		return TRUE;
	}

	return DcParseUnsignedDecimalU64( psz, pnLength );
}

// $ADCSND length: unsigned decimal only; "-1" is invalid on the wire.
inline BOOL DcParseAdcSndLengthToken(const char* psz, ULONGLONG* pnLength)
{
	return DcParseUnsignedDecimalU64( psz, pnLength );
}

// After a fixed-length $ADCGET, $ADCSND must announce the same byte count.
// After an until-end $ADCGET (request sentinel), $ADCSND must announce a
// real length (not the until-end sentinel).
inline BOOL DcAdcSndLengthMatchesRequest(ULONGLONG nRequested, ULONGLONG nAnnounced)
{
	if ( nRequested == DC_ADC_LENGTH_UNTIL_END )
		return nAnnounced != DC_ADC_LENGTH_UNTIL_END;

	return nRequested == nAnnounced;
}
