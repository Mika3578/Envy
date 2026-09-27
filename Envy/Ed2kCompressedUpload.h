//
// Ed2kCompressedUpload.h
//
// Pure ED2K/eMule COMPRESSEDPART send-side helpers (no network / MFC).
// Wire layout and benefit policy match eMule Community UploadDiskIOThread
// CreatePackedPackets / CreateStandardPackets and aMule's equivalent.
//
// COMPRESSEDPART (0x40, OP_EMULEPROT):
//   <HASH 16><StartOffset 4><CompressedTotalSize 4><zlib data...>
// COMPRESSEDPART_I64 (0xA1, OP_EMULEPROT):
//   <HASH 16><StartOffset 8><CompressedTotalSize 4><zlib data...>
//
// I64 when StartOffset > 0xFFFFFFFF or EndOffset (exclusive, uncompressed)
// > 0xFFFFFFFF. Compressed size is always 32-bit. Multiple packets may share
// the same StartOffset + CompressedTotalSize while streaming one zlib blob.
//
// Capability: peer Hello MiscOptions1 compression nibble / MuleInfo
// ET_COMPRESSION must be version 1 (eMule m_byDataCompVer == 1).
// Fallback: compress2 failure OR compressed size >= source size → SENDINGPART.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <windows.h>

#include <cstdint>
#include <cstring>

// Opcodes (mirror EDPacket.h — keep header free of EDPacket/MFC).
#ifndef ED2K_C2C_COMPRESSEDPART
#define ED2K_C2C_COMPRESSEDPART 0x40
#endif
#ifndef ED2K_C2C_COMPRESSEDPART_I64
#define ED2K_C2C_COMPRESSEDPART_I64 0xA1
#endif
#ifndef ED2K_C2C_SENDINGPART
#define ED2K_C2C_SENDINGPART 0x46
#endif
#ifndef ED2K_C2C_SENDINGPART_I64
#define ED2K_C2C_SENDINGPART_I64 0xA2
#endif

using Ed2kUploadOffset = std::uint64_t;

// Peer compression version advertised as ED2K_VERSION_COMPRESSION (0x01).
constexpr DWORD ED2K_COMPRESSED_UPLOAD_PEER_VERSION = 1u;

// eMule CreatePackedPackets suggests togo+300; zlib compressBound is the
// portable ceiling. Cap allocations well below DWORD max / ED2K part size.
constexpr DWORD ED2K_COMPRESSED_UPLOAD_SOURCE_MAX = 9500u * 1024u; // one ED2K part
constexpr DWORD ED2K_COMPRESSED_UPLOAD_BOUND_SLACK = 300u;
constexpr DWORD ED2K_COMPRESSED_UPLOAD_WIRE_CHUNK = 10240u; // eMule default split

// Remote peer supports receiving COMPRESSEDPART (eMule/aMule: == 1).
inline BOOL Ed2kPeerSupportsCompressedUpload(DWORD nPeerCompressionVersion)
{
	return nPeerCompressionVersion == ED2K_COMPRESSED_UPLOAD_PEER_VERSION;
}

// Overflow-safe end = start + length (exclusive end used for I64 decision).
inline BOOL Ed2kCompressedUploadEndOk(Ed2kUploadOffset nStart, Ed2kUploadOffset nSourceLen,
                                      Ed2kUploadOffset* pnEndExclusive)
{
	if (nSourceLen == 0 || pnEndExclusive == NULL)
		return FALSE;
	if (nStart > (~Ed2kUploadOffset(0) - nSourceLen))
		return FALSE;
	*pnEndExclusive = nStart + nSourceLen;
	return TRUE;
}

// Source range eligible for one compress2 call.
inline BOOL Ed2kCompressedUploadSourceRangeOk(Ed2kUploadOffset nStart, Ed2kUploadOffset nSourceLen)
{
	Ed2kUploadOffset nEnd = 0;
	if (!Ed2kCompressedUploadEndOk(nStart, nSourceLen, &nEnd))
		return FALSE;
	if (nSourceLen > ED2K_COMPRESSED_UPLOAD_SOURCE_MAX)
		return FALSE;
	return TRUE;
}

// eMule/aMule: I64 when start OR exclusive end exceeds 32-bit.
inline BOOL Ed2kCompressedUploadNeedsI64(Ed2kUploadOffset nStart, Ed2kUploadOffset nEndExclusive)
{
	return (nStart > 0xFFFFFFFFull) || (nEndExclusive > 0xFFFFFFFFull);
}

// Header bytes after opcode (hash + offsets + compressed-size field).
inline DWORD Ed2kCompressedUploadHeaderBytes(BOOL bI64)
{
	return bI64 ? (16u + 8u + 4u) : (16u + 4u + 4u);
}

// eMule/aMule benefit policy: only send compressed when strictly smaller.
inline BOOL Ed2kCompressedUploadBeneficial(DWORD nSourceLen, DWORD nCompressedLen)
{
	return nCompressedLen > 0 && nCompressedLen < nSourceLen;
}

// Safe compressBound / (source+slack) result for DWORD allocation.
inline BOOL Ed2kCompressedUploadBoundOk(DWORD nSourceLen, Ed2kUploadOffset nBound, DWORD* pnBoundOut)
{
	if (nSourceLen == 0 || pnBoundOut == NULL)
		return FALSE;
	if (nBound == 0 || nBound > 0xFFFFFFFFull)
		return FALSE;
	// Refuse absurd ceilings (defense-in-depth vs peer-influenced sizes).
	if (nBound > (Ed2kUploadOffset)ED2K_COMPRESSED_UPLOAD_SOURCE_MAX + 65536ull)
		return FALSE;
	*pnBoundOut = (DWORD)nBound;
	return TRUE;
}

// Preferred output buffer size: max(compressBound, eMule togo+300).
inline BOOL Ed2kCompressedUploadSuggestBound(DWORD nSourceLen, Ed2kUploadOffset nCompressBound,
                                             DWORD* pnSuggest)
{
	if (pnSuggest == NULL || nSourceLen == 0)
		return FALSE;
	Ed2kUploadOffset nSlack = (Ed2kUploadOffset)nSourceLen +
	                          (Ed2kUploadOffset)ED2K_COMPRESSED_UPLOAD_BOUND_SLACK;
	Ed2kUploadOffset nUse = nCompressBound > nSlack ? nCompressBound : nSlack;
	return Ed2kCompressedUploadBoundOk(nSourceLen, nUse, pnSuggest);
}

// Packet body size (header + one wire chunk of the zlib stream).
inline BOOL Ed2kCompressedUploadBodySizeOk(BOOL bI64, DWORD nWireChunk, DWORD* pnBody)
{
	if (nWireChunk == 0 || pnBody == NULL)
		return FALSE;
	const DWORD nHeader = Ed2kCompressedUploadHeaderBytes(bI64);
	if (nWireChunk > 0xFFFFFFFFu - nHeader)
		return FALSE;
	*pnBody = nHeader + nWireChunk;
	return TRUE;
}

// Suggest wire chunk size for streaming a compressed blob (eMule-style).
inline DWORD Ed2kCompressedUploadWireChunkSize(DWORD nCompressedTotal)
{
	if (nCompressedTotal == 0)
		return 0;
	if (nCompressedTotal <= ED2K_COMPRESSED_UPLOAD_WIRE_CHUNK)
		return nCompressedTotal;
	return nCompressedTotal / (nCompressedTotal / ED2K_COMPRESSED_UPLOAD_WIRE_CHUNK);
}

// Choose opcode for a compressed-part packet.
inline BYTE Ed2kCompressedUploadOpcode(BOOL bI64)
{
	return bI64 ? (BYTE)ED2K_C2C_COMPRESSEDPART_I64 : (BYTE)ED2K_C2C_COMPRESSEDPART;
}

// Choose opcode for an uncompressed part packet.
inline BYTE Ed2kUncompressedUploadOpcode(BOOL bI64)
{
	return bI64 ? (BYTE)ED2K_C2C_SENDINGPART_I64 : (BYTE)ED2K_C2C_SENDINGPART;
}

// Decide whether to attempt compression for this peer/range.
inline BOOL Ed2kShouldAttemptCompressedUpload(
    DWORD nPeerCompressionVersion,
    Ed2kUploadOffset nStart,
    Ed2kUploadOffset nSourceLen)
{
	if (!Ed2kPeerSupportsCompressedUpload(nPeerCompressionVersion))
		return FALSE;
	return Ed2kCompressedUploadSourceRangeOk(nStart, nSourceLen);
}

// eMule ShouldCompressBasedOnFilename — skip already-compressed containers.
// Case-insensitive ASCII extension check; empty name allows compression.
inline BOOL Ed2kCompressedUploadFilenameAllows(LPCWSTR pszName)
{
	if (pszName == NULL || pszName[0] == L'\0')
		return TRUE;

	const WCHAR* pszExt = pszName;
	for (const WCHAR* p = pszName; *p; ++p)
	{
		if (*p == L'.' || *p == L'\\' || *p == L'/')
			pszExt = p;
	}
	if (*pszExt != L'.')
		return TRUE;

	auto eq = [](WCHAR a, WCHAR b) -> bool
	{
		if (a >= L'A' && a <= L'Z') a = (WCHAR)(a - L'A' + L'a');
		if (b >= L'A' && b <= L'Z') b = (WCHAR)(b - L'A' + L'a');
		return a == b;
	};
	auto match = [&](const WCHAR* ext) -> bool
	{
		const WCHAR* a = pszExt;
		const WCHAR* b = ext;
		while (*a && *b)
		{
			if (!eq(*a, *b))
				return false;
			++a;
			++b;
		}
		return *a == L'\0' && *b == L'\0';
	};

	if (match(L".zip") || match(L".cbz") || match(L".rar") ||
	    match(L".cbr") || match(L".ace") || match(L".ogm"))
		return FALSE;
	return TRUE;
}

// Approximate uncompressed payload credited for one compressed wire chunk
// (eMule CreatePackedPackets). Last chunk absorbs remainder.
inline DWORD Ed2kCompressedUploadPayloadCredit(
    DWORD nWireChunk,
    DWORD nCompressedTotal,
    DWORD nSourceTotal,
    DWORD nCreditedSoFar,
    BOOL bLastChunk)
{
	if (nCompressedTotal == 0 || nSourceTotal == 0 || nWireChunk == 0)
		return 0;

	Ed2kUploadOffset nCredit = ((Ed2kUploadOffset)nWireChunk * (Ed2kUploadOffset)nSourceTotal) /
	                           (Ed2kUploadOffset)nCompressedTotal;
	if (nCredit > 0xFFFFFFFFull)
		nCredit = 0xFFFFFFFFull;

	DWORD nOut = (DWORD)nCredit;
	if (bLastChunk)
	{
		if (nCreditedSoFar < nSourceTotal &&
		    nCreditedSoFar + nOut < nSourceTotal)
			nOut = nSourceTotal - nCreditedSoFar;
	}
	if (nCreditedSoFar > nSourceTotal)
		return 0;
	if (nOut > nSourceTotal - nCreditedSoFar)
		nOut = nSourceTotal - nCreditedSoFar;
	return nOut;
}

// Write COMPRESSEDPART / COMPRESSEDPART_I64 body (no TCP/protocol framing).
// pHash16 must be 16 bytes. Returns bytes written or 0 on failure.
inline DWORD Ed2kWriteCompressedPartBody(
    BYTE* pOut,
    DWORD nOutCap,
    const BYTE* pHash16,
    Ed2kUploadOffset nStart,
    DWORD nCompressedTotal,
    const BYTE* pWireData,
    DWORD nWireLen,
    BOOL bI64)
{
	if (pOut == NULL || pHash16 == NULL || pWireData == NULL || nWireLen == 0)
		return 0;

	DWORD nBody = 0;
	if (!Ed2kCompressedUploadBodySizeOk(bI64, nWireLen, &nBody))
		return 0;
	if (nBody > nOutCap)
		return 0;

	DWORD nPos = 0;
	memcpy(pOut + nPos, pHash16, 16);
	nPos += 16;

	if (bI64)
	{
		const DWORD nLo = (DWORD)(nStart & 0xffffffffull);
		const DWORD nHi = (DWORD)((nStart >> 32) & 0xffffffffull);
		memcpy(pOut + nPos, &nLo, 4);
		nPos += 4;
		memcpy(pOut + nPos, &nHi, 4);
		nPos += 4;
	}
	else
	{
		if (nStart > 0xFFFFFFFFull)
			return 0;
		const DWORD nOff = (DWORD)nStart;
		memcpy(pOut + nPos, &nOff, 4);
		nPos += 4;
	}

	memcpy(pOut + nPos, &nCompressedTotal, 4);
	nPos += 4;
	memcpy(pOut + nPos, pWireData, nWireLen);
	nPos += nWireLen;
	return nPos;
}
