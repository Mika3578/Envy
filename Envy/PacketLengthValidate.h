//
// PacketLengthValidate.h
//
// Pure inbound packet length / bounds predicates (no network / MFC).
// Shared by protocol parsers and EnvyTests smoke tests.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <windows.h>
#include <cstdint>

// ED2K TCP framing: nLength counts the type byte, so valid packets need
// nLength >= 1. Reject before callers do "nLength - 1" arithmetic.
inline BOOL Ed2kTcpPacketLengthOk(DWORD nBufferLength, DWORD nHeaderSize, DWORD nLength)
{
	if ( nBufferLength < nHeaderSize )
		return FALSE;

	if ( nLength < 1 )
		return FALSE;

	return ( nLength - 1 ) <= ( nBufferLength - nHeaderSize );
}

// BitTorrent wire framing:
//   length-prefix 0      -> real keep-alive (not an extension; handled separately)
//   length-prefix 1      -> single message-id byte; for id 20 (BEP-10) this is
//                          malformed because the extended id byte is missing
//   length-prefix >= 2   -> message id + extended id (+ optional bencode)
// This predicate only validates BEP-10 extension payload sizing before
// "nLength - 2"; it must not be used to classify keep-alives.
inline BOOL BtExtensionPayloadLengthOk(DWORD nLength)
{
	return nLength >= 2;
}

// True BitTorrent keep-alive is exclusively a zero length-prefix.
inline BOOL BtIsKeepAliveLength(DWORD nLength)
{
	return nLength == 0;
}

// QueryHit XML "{deflate}" path uses "nSize - 10" (9-byte marker + trailing NUL
// included in fixed nXMLSize). Require nSize > 10 so subtraction cannot underflow.
// CG1Packet::ReadXML uses "len - 9" because it measures length until HIT_SEP/NUL
// (separator already excluded). Both are correct for their framing — see #119.
inline BOOL G1QueryHitDeflateXmlLengthOk(int nSize)
{
	return nSize > 10;
}

// GGEP item must expose at least one payload byte before m_pBuffer[0].
inline BOOL GgepItemHasTypeByte(const BYTE* pBuffer, DWORD nLength)
{
	return pBuffer != nullptr && nLength >= 1;
}

// ED2K preview frame size vs remaining packet bytes — compare unsigned so a
// high-bit frame size cannot bypass the bound via a signed cast.
inline BOOL Ed2kPreviewFrameFits(DWORD nFrameSize, DWORD nRemaining)
{
	return nFrameSize <= nRemaining;
}

// Absolute cap for one ED2K preview image frame (PNG). Previews are thumbnails;
// multi-MB peer-advertised sizes are treated as abuse (#120).
constexpr DWORD ED2K_PREVIEW_FRAME_MAX = 4u * 1024u * 1024u;

inline BOOL Ed2kPreviewFrameAcceptable(DWORD nFrameSize, DWORD nRemaining)
{
	if ( nFrameSize == 0 || nFrameSize > ED2K_PREVIEW_FRAME_MAX )
		return FALSE;
	return Ed2kPreviewFrameFits( nFrameSize, nRemaining );
}

// Absolute cap for ED2K TAG_BLOB values in file-backed .met / collection tags (#82).
// Same 4 MiB policy as preview frames (thumbnails / metadata blobs, not payloads).
constexpr DWORD ED2K_TAG_BLOB_MAX = ED2K_PREVIEW_FRAME_MAX;

inline BOOL Ed2kTagBlobLengthOk(DWORD nBlobLen, ULONGLONG nFileRemaining)
{
	if ( nBlobLen > ED2K_TAG_BLOB_MAX )
		return FALSE;
	return nBlobLen <= nFileRemaining;
}

// File-backed ED2K tag key / TAG_STRING lengths are WORD-prefixed (#81/#82).
// Cap at WORD max; reject when claimed length exceeds remaining file bytes.
constexpr DWORD ED2K_TAG_STRING_MAX = 65535u;

inline BOOL Ed2kTagStringLengthOk(DWORD nLen, ULONGLONG nFileRemaining)
{
	if ( nLen > ED2K_TAG_STRING_MAX )
		return FALSE;
	return nLen <= nFileRemaining;
}

// ED2K hashset answer: after nBlocks, payload must be exactly nBlocks MD4 digests.
constexpr DWORD ED2K_HASHSET_DIGEST_BYTES = 16u;

inline BOOL Ed2kHashsetPayloadFits(DWORD nBlocks, DWORD nRemaining)
{
	const ULONGLONG nNeed = static_cast< ULONGLONG >( nBlocks ) * ED2K_HASHSET_DIGEST_BYTES;
	return nNeed == nRemaining;
}

// Bencode nesting limit for list/dict Decode recursion (stack exhaustion / #82).
constexpr DWORD BENODE_MAX_DEPTH = 32u;

inline BOOL BencodeDepthOk(DWORD nDepth)
{
	return nDepth <= BENODE_MAX_DEPTH;
}

// Overflow-safe base-10 parse of a length-bounded ASCII integer (bencode 'i' / lengths).
inline BOOL ParseInt64Bounded(const char* pszString, size_t nLen, __int64& nNum)
{
	// Always define the out-param so callers never observe an uninitialized value
	// if a failure path is mis-analyzed or short-circuit is skipped.
	nNum = 0;

	if ( pszString == nullptr || nLen == 0 )
		return FALSE;

	bool bNeg = false;
	size_t i = 0;
	if ( pszString[ 0 ] == '-' )
	{
		if ( nLen < 2 )
			return FALSE;
		bNeg = true;
		i = 1;
	}

	unsigned __int64 nAbs = 0;
	const unsigned __int64 nMaxPos = static_cast< unsigned __int64 >( INT64_MAX );
	const unsigned __int64 nMaxNeg = nMaxPos + 1ULL;	// magnitude of INT64_MIN

	for ( ; i < nLen; ++i )
	{
		if ( pszString[ i ] < '0' || pszString[ i ] > '9' )
			return FALSE;
		const unsigned d = static_cast< unsigned >( pszString[ i ] - '0' );
		const unsigned __int64 nLimit = bNeg ? nMaxNeg : nMaxPos;
		if ( nAbs > ( nLimit - d ) / 10ULL )
			return FALSE;
		nAbs = nAbs * 10ULL + d;
	}

	if ( bNeg )
	{
		if ( nAbs == nMaxNeg )
			nNum = INT64_MIN;
		else
			nNum = -static_cast< __int64 >( nAbs );
	}
	else
	{
		nNum = static_cast< __int64 >( nAbs );
	}
	return TRUE;
}

// Absolute cap for BEP-9 ut_metadata total info-dict size (peer-advertised).
// Matches common client practice; prevents multi-GB metadata DoS (#82).
constexpr std::uint64_t BT_UT_METADATA_MAX = 32ull * 1024ull * 1024ull;

inline BOOL BtUtMetadataSizeOk(std::uint64_t nSize)
{
	return nSize > 0 && nSize <= BT_UT_METADATA_MAX;
}

// G2 HIT_WRAP / routing embeds a GNUTELLAPACKET (#81).
// m_nLength is signed LONG — negative values must not enter unsigned
// "remaining >= header + length" math or (DWORD) cast before Write.
constexpr DWORD G1_PACKET_HEADER_BYTES = 23u;	// sizeof(GNUTELLAPACKET)
constexpr DWORD G1_WRAPPED_PAYLOAD_MAX = 256u * 1024u;	// Settings.Gnutella.MaximumPacket ceiling

inline BOOL G1WrappedPayloadLengthOk(LONG nPayloadLen)
{
	if ( nPayloadLen < 0 )
		return FALSE;
	return static_cast< DWORD >( nPayloadLen ) <= G1_WRAPPED_PAYLOAD_MAX;
}

inline BOOL G1WrappedPayloadFits(DWORD nRemaining, LONG nPayloadLen)
{
	if ( ! G1WrappedPayloadLengthOk( nPayloadLen ) )
		return FALSE;
	if ( nRemaining < G1_PACKET_HEADER_BYTES )
		return FALSE;
	return static_cast< DWORD >( nPayloadLen ) <= ( nRemaining - G1_PACKET_HEADER_BYTES );
}
