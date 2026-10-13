//
// KadSearchSourceRequest.h
//
// Pure helpers for Kad2 KADEMLIA2_SEARCH_SOURCE_REQ (0x34) outbound framing
// and the app-trigger policy that decides when an ED2K download may call
// CKademlia::SearchSource. Shared by CKademlia / CDownloadWithSearch and
// EnvyTests. No MFC / download UI coupling.
//
// Wire reference (aMule KademliaUDPListener.cpp / Search.cpp):
//   KADEMLIA2_SEARCH_SOURCE_REQ:
//     <FileHash 16><StartPosition uint16 LE><FileSize uint64 LE>
// StartPosition uses the low 15 bits (0..0x7FFF). Inbound also accepts
// exact 16-byte hash-only and 24-byte <FileHash 16><FileSize 8 LE> tails.
// The 8-byte size tail is decoded little-endian to match this helper's
// historical contract. Older CEDPacket WriteInt64 emission followed
// m_bBigEndian (TRUE by default); inbound FileSize is unused for store
// selection in this slice.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#ifndef KAD_ID_SIZE
#define KAD_ID_SIZE 16
#endif

constexpr uint16_t KAD_SEARCH_SOURCE_START_POSITION_MASK = 0x7fffu;
constexpr size_t KAD_SEARCH_SOURCE_REQ_LEGACY_BODY_SIZE = KAD_ID_SIZE + sizeof(uint64_t);
constexpr size_t KAD_SEARCH_SOURCE_REQ_TAIL_SIZE = sizeof(uint16_t) + sizeof(uint64_t);
constexpr size_t KAD_SEARCH_SOURCE_REQ_BODY_SIZE = KAD_ID_SIZE + KAD_SEARCH_SOURCE_REQ_TAIL_SIZE;

inline void KadWriteUInt16LE(uint8_t* out, uint16_t value)
{
	out[0] = static_cast<uint8_t>(value & 0xffu);
	out[1] = static_cast<uint8_t>((value >> 8) & 0xffu);
}

inline uint16_t KadReadUInt16LE(const uint8_t* in)
{
	return static_cast<uint16_t>(
	    static_cast<uint16_t>(in[0]) |
	    (static_cast<uint16_t>(in[1]) << 8));
}

inline void KadWriteUInt64LE(uint8_t* out, uint64_t value)
{
	for (size_t i = 0; i < sizeof(uint64_t); ++i)
		out[i] = static_cast<uint8_t>((value >> (8 * i)) & 0xffu);
}

inline uint64_t KadReadUInt64LE(const uint8_t* in)
{
	uint64_t value = 0;
	for (size_t i = 0; i < sizeof(uint64_t); ++i)
		value |= (static_cast<uint64_t>(in[i]) << (8 * i));
	return value;
}

// Encode the maintained Kad2 layout into out. Returns bytes written, or 0 if
// outCap is too small. Integer fields are always little-endian regardless of
// CPacket::m_bBigEndian.
inline size_t KadEncodeSearchSourceRequest(
    uint8_t* out,
    size_t outCap,
    const uint8_t fileHash[KAD_ID_SIZE],
    uint16_t startPosition,
    uint64_t fileSize)
{
	if (out == nullptr || fileHash == nullptr)
		return 0;
	if (outCap < KAD_SEARCH_SOURCE_REQ_BODY_SIZE)
		return 0;

	std::memcpy(out, fileHash, KAD_ID_SIZE);
	KadWriteUInt16LE(
	    out + KAD_ID_SIZE,
	    static_cast<uint16_t>(startPosition & KAD_SEARCH_SOURCE_START_POSITION_MASK));
	KadWriteUInt64LE(out + KAD_ID_SIZE + sizeof(uint16_t), fileSize);
	return KAD_SEARCH_SOURCE_REQ_BODY_SIZE;
}

// Decode the bytes after FileHash. Accepted shapes are:
//   0 bytes  — legacy hash-only request
//   8 bytes  — legacy Envy <FileSize uint64 LE>
//   10 bytes — Kad2 <StartPosition uint16 LE><FileSize uint64 LE>
// Any other tail length is malformed and rejected.
inline bool KadDecodeSearchSourceRequestTail(
    const uint8_t* tail,
    size_t remaining,
    uint16_t& outStartPosition,
    uint64_t& outFileSize)
{
	outStartPosition = 0;
	outFileSize = 0;

	if (remaining == 0)
		return true;
	if (tail == nullptr)
		return false;

	if (remaining == sizeof(uint64_t))
	{
		outFileSize = KadReadUInt64LE(tail);
		return true;
	}
	if (remaining == KAD_SEARCH_SOURCE_REQ_TAIL_SIZE)
	{
		outStartPosition = static_cast<uint16_t>(
		    KadReadUInt16LE(tail) & KAD_SEARCH_SOURCE_START_POSITION_MASK);
		outFileSize = KadReadUInt64LE(tail + sizeof(uint16_t));
		return true;
	}
	return false;
}

// App-trigger policy for calling SearchSource from ED2K download source
// acquisition. Period is wall-clock ms (GetTickCount style); tLastTrigger==0
// means never triggered. Size must be known — FileSize is required on the wire.
inline bool KadMayTriggerSourceSearch(
    bool bEnableKad,
    bool bKadInitialized,
    bool bHasEd2kHash,
    bool bSizeKnown,
    uint32_t tNow,
    uint32_t tLastTrigger,
    uint32_t nMinPeriodMs)
{
	if (!bEnableKad || !bKadInitialized || !bHasEd2kHash || !bSizeKnown)
		return false;
	if (tLastTrigger != 0)
	{
		const uint32_t elapsed = tNow - tLastTrigger;
		if (elapsed < nMinPeriodMs)
			return false;
	}
	return true;
}
