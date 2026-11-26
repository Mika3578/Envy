//
// KadPublishWire.h
//
// Pure Kad2 PUBLISH_SOURCE_REQ / PUBLISH_KEY_REQ entry framing helpers (#428).
// Wire layout follows aMule KademliaUDPListener publish paths; no MFC / sockets.
//
// PUBLISH_SOURCE_REQ (opcode 0x44):
//   <FileHash 16><SourceID 16><TagCount 1><ED2K tags...>
//
// Outbound publish from a client omits TAG_SOURCEIP; the indexing node derives
// transport IP/UDP from the datagram endpoint. Inbound parsing still accepts
// optional well-formed source-identity tags for SEARCH_RES interoperability.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#pragma once

#include "KadSearchResDelivery.h"

#include <cstring>
#include <vector>

constexpr size_t KAD_PUBLISH_SOURCE_MIN =
    KAD_ID_SIZE + KAD_ID_SIZE + 1; // file hash + source ID + tag count

constexpr size_t KAD_PUBLISH_KEY_MIN =
    KAD_ID_SIZE + 2; // keyword hash + uint16 entry count

constexpr size_t KAD_PUBLISH_KEY_MAX_ENTRIES = 50;
constexpr BYTE KAD_PUBLISH_MAX_TAGS_PER_ENTRY = 64;

struct KadPublishSourceReq
{
	BYTE fileHash[KAD_ID_SIZE]{};
	BYTE sourceId[KAD_ID_SIZE]{};
	KadSourceCandidate tags{};
};

struct KadPublishKeyEntry
{
	BYTE answerId[KAD_ID_SIZE]{};
	KadSourceCandidate tags{};
};

// Standard outbound source-publish tag set (no TAG_SOURCEIP).
inline void KadAppendPublishSourceOutboundTags(
    std::vector<BYTE>& buf,
    BYTE nSourceType,
    WORD nTcpPort,
    WORD nUdpPort)
{
	buf.push_back(3);
	KadAppendCompactIntTag(buf, KAD_ED2K_TAG_UINT8, KAD_TAG_SOURCETYPE, nSourceType);
	KadAppendCompactIntTag(buf, KAD_ED2K_TAG_UINT16, KAD_TAG_SOURCEPORT, nTcpPort);
	KadAppendCompactIntTag(buf, KAD_ED2K_TAG_UINT16, KAD_TAG_SOURCEUPORT, nUdpPort);
}

inline void KadBuildPublishSourceReqBody(
    std::vector<BYTE>& buf,
    const BYTE* pFileHash,
    const BYTE* pSourceId,
    BYTE nSourceType,
    WORD nTcpPort,
    WORD nUdpPort)
{
	buf.clear();
	KadAppendIdBytes(buf, pFileHash);
	KadAppendIdBytes(buf, pSourceId);
	KadAppendPublishSourceOutboundTags(buf, nSourceType, nTcpPort, nUdpPort);
}

// Legacy Envy SEARCH_RES / store entry slice:
//   <SourceID 16><IP uint32 LE><UDP uint16 LE><TCP uint16 LE><TagCount 1>...
inline bool KadBodyLooksLikeLegacyEnvyEntrySlice(const BYTE* pData, size_t nLen)
{
	if (!pData || nLen < KAD_ID_SIZE + 4 + 2 + 2 + 1)
		return false;
	// After a leading 16-byte ID, the next eight bytes are fixed-width endpoint
	// fields in the old private layout — not a valid ED2K tag-list opener.
	const size_t nOff = KAD_ID_SIZE;
	const BYTE bTagOrCount = pData[nOff + 8];
	if (bTagOrCount == 0)
		return false;
	// Standard TagCount with compact UINT8 sourcetype tag begins 0x89, not raw IP.
	return bTagOrCount < 0x80;
}

// Parse PUBLISH_SOURCE_REQ payload (after opcode). Fails on truncated bodies,
// excessive tag counts, missing TAG_SOURCETYPE, or legacy entry slices.
inline bool KadParsePublishSourceReqBody(
    const BYTE* pData,
    size_t nLen,
    KadPublishSourceReq& out)
{
	out = KadPublishSourceReq{};
	if (!pData || nLen < KAD_PUBLISH_SOURCE_MIN)
		return false;
	if (KadBodyLooksLikeLegacyEnvyEntrySlice(pData + KAD_ID_SIZE, nLen - KAD_ID_SIZE))
		return false;

	KadByteCursor cur{ pData, nLen, 0 };
	if (!cur.ReadBytes(out.fileHash, KAD_ID_SIZE))
		return false;
	if (!cur.ReadBytes(out.sourceId, KAD_ID_SIZE))
		return false;

	BYTE nTagCount = 0;
	if (!cur.ReadByte(nTagCount))
		return false;
	if (nTagCount == 0 || nTagCount > KAD_PUBLISH_MAX_TAGS_PER_ENTRY)
		return false;

	for (BYTE i = 0; i < nTagCount; ++i)
	{
		if (!KadConsumeSearchResTag(cur, out.tags))
			return false;
	}
	if (!out.tags.sawSourceType)
		return false;
	return cur.Remaining() == 0;
}

inline bool KadParsePublishKeyReqBody(
    const BYTE* pData,
    size_t nLen,
    BYTE* pKeywordHashOut, // optional 16
    WORD& nEntryCountOut,
    std::vector<KadPublishKeyEntry>* pEntriesOut, // null = validate only
    bool bStopAfterHeader = false)
{
	nEntryCountOut = 0;
	if (pEntriesOut)
		pEntriesOut->clear();

	if (!pData || nLen < KAD_PUBLISH_KEY_MIN)
		return false;

	KadByteCursor cur{ pData, nLen, 0 };
	BYTE keyword[KAD_ID_SIZE];
	if (!cur.ReadBytes(keyword, KAD_ID_SIZE))
		return false;
	if (!cur.ReadWordLE(nEntryCountOut))
		return false;
	if (nEntryCountOut == 0 || nEntryCountOut > KAD_PUBLISH_KEY_MAX_ENTRIES)
		return false;

	if (pKeywordHashOut)
		memcpy(pKeywordHashOut, keyword, KAD_ID_SIZE);

	if (bStopAfterHeader)
		return true;

	for (WORD i = 0; i < nEntryCountOut; ++i)
	{
		KadPublishKeyEntry entry{};
		if (!cur.ReadBytes(entry.answerId, KAD_ID_SIZE))
			return false;

		BYTE nTagCount = 0;
		if (!cur.ReadByte(nTagCount))
			return false;
		if (nTagCount == 0 || nTagCount > KAD_PUBLISH_MAX_TAGS_PER_ENTRY)
			return false;

		for (BYTE t = 0; t < nTagCount; ++t)
		{
			if (!KadConsumeSearchResTag(cur, entry.tags))
				return false;
		}
		if (!entry.tags.sawSourceType)
			return false;
		if (pEntriesOut)
			pEntriesOut->push_back(entry);
	}
	return true;
}