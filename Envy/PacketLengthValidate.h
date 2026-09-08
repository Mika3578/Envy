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

// QueryHit XML "{deflate}" path uses "nSize - 10" (marker 9 + trailing byte).
// Require enough bytes so that subtraction cannot underflow.
// Note: G1Packet.cpp uses "len - 9" after advancing past the marker; that
// off-by-one vs QueryHit is intentional historical behavior and is tracked
// separately — this predicate only hardens the QueryHit arithmetic.
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
