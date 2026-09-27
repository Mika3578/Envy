//
// KadSearchSourceRequest.h
//
// Pure helpers for Kad2 KADEMLIA2_SEARCH_SOURCE_REQ (0x34) outbound framing
// and the app-trigger policy that decides when an ED2K download may call
// CKademlia::SearchSource. Shared by CKademlia / CDownloadWithSearch and
// EnvyTests. No MFC / download UI coupling.
//
// Wire reference (aMule ProcessKademliaPacket / eMule Community):
//   KADEMLIA2_SEARCH_SOURCE_REQ:
//     <FileHash 16><FileSize 8>
// FileSize is little-endian uint64 (CEDPacket::WriteInt64 / ReadInt64).
// Older peers may omit FileSize; inbound parsers should accept hash-only.
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

// Encoded SEARCH_SOURCE_REQ body length when FileSize is present.
constexpr size_t KAD_SEARCH_SOURCE_REQ_BODY_SIZE = KAD_ID_SIZE + sizeof(uint64_t);

// Encode <FileHash 16><FileSize 8> into out. Returns bytes written, or 0 if
// outCap is too small. FileSize is little-endian (host LE on Windows/MSVC).
inline size_t KadEncodeSearchSourceRequest(
    uint8_t* out,
    size_t outCap,
    const uint8_t fileHash[KAD_ID_SIZE],
    uint64_t fileSize)
{
	if (out == nullptr || fileHash == nullptr)
		return 0;
	if (outCap < KAD_SEARCH_SOURCE_REQ_BODY_SIZE)
		return 0;

	std::memcpy(out, fileHash, KAD_ID_SIZE);
	for (size_t i = 0; i < sizeof(uint64_t); ++i)
		out[KAD_ID_SIZE + i] = static_cast<uint8_t>((fileSize >> (8 * i)) & 0xffu);
	return KAD_SEARCH_SOURCE_REQ_BODY_SIZE;
}

// Decode FileSize from a body that already consumed the 16-byte hash.
// Returns false when fewer than 8 bytes remain (legacy hash-only peers).
inline bool KadDecodeSearchSourceFileSize(
    const uint8_t* bodyAfterHash,
    size_t remaining,
    uint64_t& outFileSize)
{
	outFileSize = 0;
	if (bodyAfterHash == nullptr || remaining < sizeof(uint64_t))
		return false;

	uint64_t n = 0;
	for (size_t i = 0; i < sizeof(uint64_t); ++i)
		n |= (static_cast<uint64_t>(bodyAfterHash[i]) << (8 * i));
	outFileSize = n;
	return true;
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
