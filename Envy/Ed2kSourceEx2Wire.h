//
// Ed2kSourceEx2Wire.h
//
// Pure ED2K Source Exchange v2 (REQUESTSOURCES2 / ANSWERSOURCES2) wire helpers.
// Layout aligned with eMule Community / aMule (not the legacy Envy file-size encoding).
//
// Standalone REQUESTSOURCES2 (0x83): <Version 1><Options 2><HASH 16>  (19 bytes).
// eMule/aMule MULTIPACKET sub-opcode 0x83 carries only <Version><Options>; the file
// hash is in the enclosing multipacket context (do not merge layouts).
// ANSWERSOURCES2 (0x84):  <Version 1><HASH 16><Count 2><records...>
//
// Record sizes (per source, after count):
//   v1:  IPv4 client + port + server + port (12)
//   v2/v3: v1 + user hash 16 (28)
//   v4: v2/v3 + crypt-options byte (29) — parsed only; obfuscation not initiated here.
//
// Shared by EDClient handlers and EnvyTests golden vectors.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <windows.h>

#ifndef ED2K_SOURCEEXCHANGE2_VERSION
#define ED2K_SOURCEEXCHANGE2_VERSION 4
#endif

#ifndef ED2K_SOURCEEXCHANGE2_VERSION_MAX
#define ED2K_SOURCEEXCHANGE2_VERSION_MAX 4
#endif

enum Ed2kSourceEx2ParseStatus
{
	Ed2kSourceEx2ParseOk = 0,
	Ed2kSourceEx2ParseTruncated,
	Ed2kSourceEx2ParseVersionZero,
	Ed2kSourceEx2ParseUnsupportedVersion,
	Ed2kSourceEx2ParseCountOverflow,
	Ed2kSourceEx2ParseRecordTruncated,
	Ed2kSourceEx2ParseTrailingBytes,
};

inline constexpr DWORD Ed2kSourceEx2RequestMinBytes()
{
	return 1u + 2u + 16u;
}

inline constexpr DWORD Ed2kSourceEx2AnswerHeaderMinBytes()
{
	return 1u + 16u + 2u;
}

inline BOOL Ed2kSourceEx2VersionSupported(BYTE nVersion)
{
	return nVersion >= 1 && nVersion <= ED2K_SOURCEEXCHANGE2_VERSION_MAX;
}

inline DWORD Ed2kSourceEx2AnswerRecordBytes(BYTE nVersion)
{
	switch (nVersion)
	{
	case 1:
		return 12u;
	case 2:
	case 3:
		return 28u;
	case 4:
		return 29u;
	default:
		return 0u;
	}
}

// Backward-compatible name used by older smoke tests (v2/v3/v4 GUID layout).
inline constexpr DWORD Ed2kSourceEx2SourceRecordBytes()
{
	return 28u;
}

inline constexpr DWORD Ed2kSourceEx2AnswerMinBytes()
{
	return Ed2kSourceEx2AnswerHeaderMinBytes();
}

inline BOOL Ed2kValidateSourcePacketBody(DWORD nRemaining, DWORD nCount, DWORD nSourceSize)
{
	if (nSourceSize == 0)
		return FALSE;

	if (nCount > (nRemaining / nSourceSize))
		return FALSE;

	return nRemaining >= nCount * nSourceSize;
}

inline BYTE Ed2kSourceEx2NegotiatedAnswerVersion(BYTE nRequestedVersion)
{
	if (!Ed2kSourceEx2VersionSupported(nRequestedVersion))
		return 0;

	return nRequestedVersion;
}

inline BYTE Ed2kSourceEx2PreferredRequestVersion()
{
	return ED2K_SOURCEEXCHANGE2_VERSION;
}

inline BOOL Ed2kSourceEx2MulRecordBytes(WORD nCount, DWORD nRecordBytes, DWORD* pnTotalOut)
{
	if (pnTotalOut == NULL || nRecordBytes == 0)
		return FALSE;

	if (nCount == 0)
	{
		*pnTotalOut = 0;
		return TRUE;
	}

	const DWORD nCount32 = (DWORD)nCount;
	if (nRecordBytes > (MAXDWORD / nCount32))
		return FALSE;

	*pnTotalOut = nCount32 * nRecordBytes;
	return TRUE;
}

inline Ed2kSourceEx2ParseStatus Ed2kSourceEx2ParseRequest(
    const BYTE* pData, DWORD nLength, BYTE* pHashOut, BYTE* pVersionOut, WORD* pOptionsOut)
{
	if (pData == NULL || pHashOut == NULL || pVersionOut == NULL || pOptionsOut == NULL)
		return Ed2kSourceEx2ParseTruncated;

	const DWORD nMin = Ed2kSourceEx2RequestMinBytes();
	if (nLength < nMin)
		return Ed2kSourceEx2ParseTruncated;

	if (nLength != nMin)
		return Ed2kSourceEx2ParseTrailingBytes;

	const BYTE nVersion = pData[0];
	if (nVersion == 0)
		return Ed2kSourceEx2ParseVersionZero;

	if (!Ed2kSourceEx2VersionSupported(nVersion))
		return Ed2kSourceEx2ParseUnsupportedVersion;

	*pVersionOut = nVersion;
	*pOptionsOut = (WORD)(pData[1] | (pData[2] << 8));
	memcpy(pHashOut, pData + 3, 16);

	return Ed2kSourceEx2ParseOk;
}

inline Ed2kSourceEx2ParseStatus Ed2kSourceEx2ParseAnswerHeader(
    const BYTE* pData, DWORD nLength, BYTE* pVersionOut, BYTE* pHashOut, WORD* pCountOut, DWORD* pRecordsRemainingOut)
{
	if (pData == NULL || pVersionOut == NULL || pHashOut == NULL || pCountOut == NULL || pRecordsRemainingOut == NULL)
		return Ed2kSourceEx2ParseTruncated;

	if (nLength < Ed2kSourceEx2AnswerHeaderMinBytes())
		return Ed2kSourceEx2ParseTruncated;

	const BYTE nVersion = pData[0];
	if (nVersion == 0)
		return Ed2kSourceEx2ParseVersionZero;

	if (!Ed2kSourceEx2VersionSupported(nVersion))
		return Ed2kSourceEx2ParseUnsupportedVersion;

	*pVersionOut = nVersion;
	memcpy(pHashOut, pData + 1, 16);
	*pCountOut = (WORD)(pData[17] | (pData[18] << 8));

	const DWORD nRecordBytes = Ed2kSourceEx2AnswerRecordBytes(nVersion);
	if (nRecordBytes == 0)
		return Ed2kSourceEx2ParseUnsupportedVersion;

	DWORD nRecordsLen = 0;
	if (!Ed2kSourceEx2MulRecordBytes(*pCountOut, nRecordBytes, &nRecordsLen))
		return Ed2kSourceEx2ParseCountOverflow;

	const DWORD nHeader = Ed2kSourceEx2AnswerHeaderMinBytes();
	if (nRecordsLen > nLength - nHeader)
		return Ed2kSourceEx2ParseRecordTruncated;

	if (nLength != nHeader + nRecordsLen)
		return Ed2kSourceEx2ParseTrailingBytes;

	*pRecordsRemainingOut = nRecordsLen;
	return Ed2kSourceEx2ParseOk;
}

inline DWORD Ed2kSourceEx2WriteRequest(BYTE* pOut, DWORD nCapacity, BYTE nVersion, WORD nOptions, const BYTE* pHash16)
{
	if (pOut == NULL || pHash16 == NULL)
		return 0;

	if (nCapacity < Ed2kSourceEx2RequestMinBytes())
		return 0;

	if (!Ed2kSourceEx2VersionSupported(nVersion))
		return 0;

	pOut[0] = nVersion;
	pOut[1] = (BYTE)(nOptions & 0xFF);
	pOut[2] = (BYTE)((nOptions >> 8) & 0xFF);
	memcpy(pOut + 3, pHash16, 16);
	return Ed2kSourceEx2RequestMinBytes();
}

// Legacy Envy REQUESTSOURCES2 used hash-first framing with a 32-bit or 64-bit file size
// field (22 or 26 bytes). That layout is not supported; detect only by exact length.
inline constexpr DWORD Ed2kSourceEx2LegacyEnvyRequestBytes32()
{
	return 16u + 4u + 2u;
}

inline constexpr DWORD Ed2kSourceEx2LegacyEnvyRequestBytes64()
{
	return 16u + 4u + 4u + 2u;
}

inline BOOL Ed2kSourceEx2LooksLikeLegacyEnvyRequest(const BYTE* pData, DWORD nLength)
{
	if (pData == NULL)
		return FALSE;

	return nLength == Ed2kSourceEx2LegacyEnvyRequestBytes32() || nLength == Ed2kSourceEx2LegacyEnvyRequestBytes64();
}
