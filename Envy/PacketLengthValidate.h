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

// Cap for BitTorrent TCP message length-prefix (#81).
// Excludes keep-alive (nLength == 0); pair with BtIsKeepAliveLength for the
// zero prefix. Non-zero lengths must be in [1, BT_PACKET_LENGTH_MAX].
constexpr DWORD BT_PACKET_LENGTH_MAX = 16u * 1024u * 1024u;

inline BOOL BtPacketLengthOk(DWORD nLength)
{
	return nLength >= 1 && nLength <= BT_PACKET_LENGTH_MAX;
}

// QueryHit XML "{deflate}" path uses "nSize - 10" (9-byte marker + trailing NUL
// included in fixed nXMLSize). Require nSize > 10 so subtraction cannot underflow.
// CG1Packet::ReadXML uses "len - 9" because it measures length until HIT_SEP/NUL
// (separator already excluded). Both are correct for their framing — see #119.
inline BOOL G1QueryHitDeflateXmlLengthOk(int nSize)
{
	return nSize > 10;
}

// Cap for G1 QueryHit/G1Packet "{deflate}" XML inflate output (#81 zip-bomb).
// Aligns with Settings.Gnutella.MaximumPacket upper bound (256 KiB).
constexpr DWORD G1_DEFLATE_XML_INFLATE_MAX = 256u * 1024u;

inline BOOL G1DeflateXmlInflateOk(DWORD nOutput)
{
	return nOutput > 0 && nOutput <= G1_DEFLATE_XML_INFLATE_MAX;
}

// G1 framing (TCP + UDP): payload length is a signed LONG on the wire (#81).
// Reject negative payloads and overflow when adding the fixed header size
// before comparing against Settings.Gnutella.MaximumPacket.
constexpr DWORD G1_PACKET_HEADER_BYTES = 23u; // sizeof(GNUTELLAPACKET)

inline BOOL G1PacketTotalLengthOk(LONG nPayloadLength, DWORD nMaxTotal)
{
	if (nPayloadLength < 0)
		return FALSE;
	if (nMaxTotal <= G1_PACKET_HEADER_BYTES)
		return FALSE;
	// Legacy ProcessPackets rejects when total >= MaximumPacket (strict <).
	return static_cast<DWORD>(nPayloadLength) < (nMaxTotal - G1_PACKET_HEADER_BYTES);
}

inline DWORD G1PacketTotalLength(LONG nPayloadLength)
{
	return G1_PACKET_HEADER_BYTES + static_cast<DWORD>(nPayloadLength);
}

// G1 QueryHit QHD: claimed XML length must leave room for the trailing GUID
// (16 bytes), including when nXmlSize is 0. Fail-closed — do not soft-clamp
// nXMLSize to 0 (#81).
constexpr DWORD G1_QUERYHIT_GUID_BYTES = 16u;

inline BOOL G1QueryHitXmlFits(DWORD nXmlSize, DWORD nRemaining)
{
	if (nRemaining < G1_QUERYHIT_GUID_BYTES)
		return FALSE;
	return (nRemaining - G1_QUERYHIT_GUID_BYTES) >= nXmlSize;
}

// GGEP item must expose at least one payload byte before m_pBuffer[0].
inline BOOL GgepItemHasTypeByte(const BYTE* pBuffer, DWORD nLength)
{
	return pBuffer != nullptr && nLength >= 1;
}

// Absolute cap for GGEP DEFLATE inflate output (#81 zip-bomb).
// Aligns with Settings.Gnutella.MaximumPacket upper bound (256 KB).
constexpr DWORD GGEP_INFLATE_MAX = 256u * 1024u;

inline BOOL GgepInflateOutputOk(DWORD nOutput)
{
	return nOutput > 0 && nOutput <= GGEP_INFLATE_MAX;
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

// Absolute cap for speculative unknown-tag STRING skip heuristic (#81).
// Claims *above* this fall through to INT-sized skip; claims at or below
// that fit remaining use STRING skip; claims at or below that exceed
// remaining fail-closed (no INT guess / desync).
constexpr DWORD ED2K_UNKNOWN_TAG_STRING_SKIP_MAX = 1023u;

inline BOOL Ed2kUnknownTagStringSkipOk(DWORD nValueLen, ULONGLONG nRemaining)
{
	if (nValueLen > ED2K_UNKNOWN_TAG_STRING_SKIP_MAX)
		return FALSE;
	return nValueLen <= nRemaining;
}

// ED2K FileComment: 1-byte rating + DWORD length + comment bytes (#81).
// Cap matches ED2K_COMMENT_MAX in EDPacket.h.
constexpr DWORD ED2K_FILE_COMMENT_MAX = 250u;

inline BOOL Ed2kFileCommentHeaderFits(DWORD nRemaining)
{
	return nRemaining >= 5u; // rating + length
}

// After header consumed: claimed length must fit remaining payload (optionally pre-clamped).
inline BOOL Ed2kFileCommentLengthOk(DWORD nClaimedLen, DWORD nRemainingAfterHeader)
{
	if (nClaimedLen > ED2K_FILE_COMMENT_MAX)
		return FALSE;
	return nClaimedLen <= nRemainingAfterHeader;
}

// Wire ED2K WORD-prefixed string (ReadEDString / browse-dir framing).
// Header: remaining must cover the 2-byte length field.
inline BOOL Ed2kEdStringHeaderOk(DWORD nRemaining)
{
	return nRemaining >= 2u;
}

// Wire ED2K length-prefixed strings (ReadEDString / ReadLongEDString).
// After consuming the length field, claimed payload must fit remaining.
// Argument order matches Ed2kTagStringLengthOk / Ed2kFileCommentLengthOk (len, remaining).
inline BOOL Ed2kEdStringPayloadOk(WORD nLen, DWORD nRemainingAfterLen)
{
	return nLen <= nRemainingAfterLen;
}

inline BOOL Ed2kLongEdStringPayloadOk(DWORD nLen, DWORD nRemainingAfterLen)
{
	return nLen <= nRemainingAfterLen;
}

// Absolute cap for ED2K server MOTD / server-message wire payload (#81).
// Matches the historical post-decode 5000 TCHAR guard, applied on wire length.
constexpr DWORD ED2K_SERVER_MESSAGE_MAX = 5000u;

inline BOOL Ed2kServerMessageLengthOk(WORD nLen)
{
	return nLen <= ED2K_SERVER_MESSAGE_MAX;
}

// Wire ED2K_TAG_UINT64 value is a little-endian 64-bit integer (#81).
constexpr DWORD ED2K_TAG_UINT64_BYTES = 8u;

inline BOOL Ed2kTagUint64RemainingOk(ULONGLONG nBytesRemaining)
{
	return nBytesRemaining >= ED2K_TAG_UINT64_BYTES;
}


// ED2K hashset answer: after nBlocks, payload must be exactly nBlocks MD4 digests.
constexpr DWORD ED2K_HASHSET_DIGEST_BYTES = 16u;

inline BOOL Ed2kHashsetPayloadFits(DWORD nBlocks, DWORD nRemaining)
{
	const ULONGLONG nNeed = static_cast< ULONGLONG >( nBlocks ) * ED2K_HASHSET_DIGEST_BYTES;
	return nNeed == nRemaining;
}

// ED2K private chat MESSAGE body after the WORD length field (#81).
// Must be non-empty, exact-fit remaining, and <= ED2K_MESSAGE_MAX in EDPacket.h.
// Numeric 500 is duplicated here to keep this header free of EDPacket.h; CEDClient
// static_asserts ED2K_CHAT_MESSAGE_MAX == ED2K_MESSAGE_MAX.
constexpr DWORD ED2K_CHAT_MESSAGE_MAX = 500u;

inline BOOL Ed2kChatMessageLengthOk(DWORD nMessageLength, DWORD nRemainingAfterLength)
{
	if (nMessageLength < 1 || nMessageLength > ED2K_CHAT_MESSAGE_MAX)
		return FALSE;
	return nMessageLength == nRemainingAfterLength;
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

// Cap for CBuffer::UnBZip (DC hublist / file listing .bz2) (#81 zip-bomb).
// Same magnitude as BT_UT_METADATA_MAX / CBUFFER_INFLATE_MAX.
constexpr DWORD CBUFFER_UNBZIP_MAX = 32u * 1024u * 1024u;

inline BOOL CBufferUnBZipOutputOk(DWORD nOutput)
{
	return nOutput > 0 && nOutput <= CBUFFER_UNBZIP_MAX;
}

inline BOOL CBufferUnBZipInputOk(ULONGLONG nCompressed)
{
	return nCompressed > 0 && nCompressed <= CBUFFER_UNBZIP_MAX;
}

// Cap for CBuffer::Inflate / Ungzip when callers pass nMaxOutput=0 (#81 zip-bomb).
constexpr DWORD CBUFFER_INFLATE_MAX = 32u * 1024u * 1024u;

inline BOOL CBufferInflateOutputOk(DWORD nOutput)
{
	return nOutput > 0 && nOutput <= CBUFFER_INFLATE_MAX;
}

// Alias for InflateStreamTo backlog checks (Neighbour G1/G2 deflate, HostBrowser).
constexpr DWORD CBUFFER_INFLATE_STREAM_MAX = CBUFFER_INFLATE_MAX;

inline BOOL CBufferInflateStreamOutputOk(DWORD nOutputLength)
{
	return nOutputLength <= CBUFFER_INFLATE_STREAM_MAX;
}

// Gnutella QHT/QRP patch sizing (#81 zip-bomb).
// Expected decompressed patch bytes = hash entries packed at nBits per entry.
inline DWORD QhtPatchExpectedBytes(DWORD nHash, BYTE nBits)
{
	if (nBits != 1 && nBits != 4 && nBits != 8)
		return 0;
	const DWORD nPerByte = 8u / nBits;
	if ((nHash % nPerByte) != 0)
		return 0; // Must pack evenly into whole bytes
	return nHash / nPerByte;
}

// Compressed fragment accumulation budget before Inflate. Allow 2x expected
// plus zlib framing slack so tiny valid stored blocks are not rejected.
inline BOOL QhtPatchCompressedBudgetOk(DWORD nAccumulated, DWORD nAddend, DWORD nExpected)
{
	if (nExpected == 0)
		return FALSE;
	DWORD nBudget = (nExpected > (MAXDWORD / 2u)) ? MAXDWORD : (nExpected * 2u);
	const DWORD nSlack = 64u; // zlib header/trailer + stored-block overhead
	if (nBudget < MAXDWORD - nSlack)
		nBudget += nSlack;
	else
		nBudget = MAXDWORD;
	if (nAddend > nBudget)
		return FALSE;
	if (nAccumulated > nBudget - nAddend)
		return FALSE;
	return TRUE;
}

// Cap for ED2K EMULE/KAD/REVCONNECT packed-protocol inflate (#81 zip-bomb).
// New hard cap for EMULE/KAD/REVCONNECT packed inflate (was unlimited when nMaxOutput=0).
constexpr DWORD ED2K_PACKED_INFLATE_MAX = 512u * 1024u;

inline BOOL Ed2kPackedInflateOk(DWORD nOutput)
{
	return nOutput > 0 && nOutput <= ED2K_PACKED_INFLATE_MAX;
}

// Cap for BitTorrent tracker HTTP announce/scrape response bodies (#81/#82).
// LimitContentLength stops OnRun from buffering multi-GB gzip/deflate or plain bodies.
constexpr DWORD BT_TRACKER_HTTP_RESPONSE_MAX = 32u * 1024u * 1024u;

inline BOOL BtTrackerHttpResponseOk(DWORD nLength)
{
	return nLength > 0 && nLength <= BT_TRACKER_HTTP_RESPONSE_MAX;
}

// Cap for Discovery GWC / server-list HTTP response bodies (#81/#82).
// LimitContentLength stops OnRun from buffering multi-GB hostile discovery URLs.
constexpr DWORD DISCOVERY_HTTP_RESPONSE_MAX = 32u * 1024u * 1024u;

inline BOOL DiscoveryHttpResponseOk(DWORD nLength)
{
	return nLength > 0 && nLength <= DISCOVERY_HTTP_RESPONSE_MAX;
}

// Cap for Browse Host HTTP response bodies (peer Content-Length / buffered body) (#81/#82).
constexpr std::uint64_t HOST_BROWSER_HTTP_BODY_MAX = 32ull * 1024ull * 1024ull;

inline BOOL HostBrowserHttpBodyOk(std::uint64_t nLength)
{
	// SIZE_UNKNOWN is ~0ull in Envy StdAfx; keep this header MFC-free.
	return nLength > 0 && nLength != ~0ull && nLength <= HOST_BROWSER_HTTP_BODY_MAX;
}

inline BOOL HostBrowserHttpBufferOk(std::uint64_t nBuffered)
{
	return nBuffered <= HOST_BROWSER_HTTP_BODY_MAX;
}

// Max uncompressed bytes for one ED2K COMPRESSEDPART stream (#81 zip-bomb).
// Wire "size" is compressed length; expansion must not exceed one ED2K part
// (9500 KiB, same as HashLib ED2K_PART_SIZE).
constexpr std::uint64_t ED2K_COMPRESSEDPART_INFLATE_MAX = 9500ULL * 1024ULL;

// nFileSize == ~0ULL means SIZE_UNKNOWN (no remaining-size clamp). Keep MFC-free.
inline std::uint64_t Ed2kCompressedPartInflateBudget(std::uint64_t nFileSize,
                                                     std::uint64_t nInflateOffset)
{
	if (nFileSize == ~0ULL)
		return ED2K_COMPRESSEDPART_INFLATE_MAX;
	if (nInflateOffset >= nFileSize)
		return 0;
	const std::uint64_t nRemain = nFileSize - nInflateOffset;
	return nRemain < ED2K_COMPRESSEDPART_INFLATE_MAX ? nRemain
	                                                 : ED2K_COMPRESSEDPART_INFLATE_MAX;
}

inline BOOL Ed2kCompressedPartInflateOk(std::uint64_t nWrittenAfter, std::uint64_t nMaxUncompressed)
{
	return nWrittenAfter <= nMaxUncompressed;
}

// Overflow-safe G2 sub-packet sizing (#81).
// G2 length descriptors are 2 bits (max 3 length bytes), so body and position
// values are far below DWORD max on current wire paths; these predicates make
// the bound arithmetic order-safe (defense-in-depth / reusable for wider length
// fields) and reject truncated/oversized children without relying on
// "remaining < body + prefix".
inline BOOL G2SubpacketPayloadFits(DWORD nRemaining, DWORD nBodyLen, DWORD nPrefixLen)
{
	if (nBodyLen > nRemaining)
		return FALSE;
	if (nPrefixLen > nRemaining - nBodyLen)
		return FALSE;
	return TRUE;
}

// Overflow-safe G2 top-level frame sizing for ReadBuffer (control+len+type+body).
inline BOOL G2FrameLengthFits(DWORD nBufferLength, DWORD nBodyLen, DWORD nLenLen, DWORD nTypeLen)
{
	// Wire layout: 1 control + nLenLen + (nTypeLen+1) type bytes + nBodyLen payload.
	// Combine with subtraction to avoid wrap when callers pass large components.
	if (nBodyLen > nBufferLength)
		return FALSE;
	DWORD nRemaining = nBufferLength - nBodyLen;
	if (nLenLen > nRemaining)
		return FALSE;
	nRemaining -= nLenLen;
	if (nTypeLen > nRemaining)
		return FALSE;
	return 2u <= (nRemaining - nTypeLen);
}

// G2 HIT_WRAP / routing embeds a GNUTELLAPACKET (#81).
// m_nLength is signed LONG — negative values must not enter unsigned
// "remaining >= header + length" math or (DWORD) cast before Write.
// Absolute payload ceiling matches Settings.Gnutella.MaximumPacket (256 KiB)
// for wrapped G2->G1 conversion; CG1Packet::New only rejects negatives so
// HostBrowser may still use MaximumPacket*8.
constexpr DWORD G1_WRAPPED_PAYLOAD_MAX = 256u * 1024u;

inline BOOL G1WrappedPayloadLengthOk(LONG nPayloadLen)
{
	if (nPayloadLen < 0)
		return FALSE;
	return static_cast<DWORD>(nPayloadLen) <= G1_WRAPPED_PAYLOAD_MAX;
}

inline BOOL G1WrappedPayloadFits(DWORD nRemaining, LONG nPayloadLen)
{
	if (!G1WrappedPayloadLengthOk(nPayloadLen))
		return FALSE;
	if (nRemaining < G1_PACKET_HEADER_BYTES)
		return FALSE;
	return static_cast<DWORD>(nPayloadLen) <= (nRemaining - G1_PACKET_HEADER_BYTES);
}
