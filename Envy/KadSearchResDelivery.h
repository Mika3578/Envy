//
// KadSearchResDelivery.h
//
// Pure helpers for Kad2 SEARCH_RES classification and ED2K source mapping.
// Shared by CKademlia and EnvyTests. No MFC windows / download UI coupling.
//
// Wire reference (inbound SEARCH_RES): aMule Process2SearchResponse /
// ProcessSearchResponse and eMule Community equivalents:
//   KADEMLIA2_SEARCH_RES:
//     <SenderID 16><TargetID 16><Count 2>
//     [ <AnswerID 16><TagCount 1><ED2K tags...> ] * Count
// Source identity tags (name-ID form): TAG_SOURCETYPE 0xFF, TAG_SOURCEIP 0xFE,
// TAG_SOURCEPORT 0xFD, TAG_SOURCEUPORT 0xFC, TAG_SERVERIP 0xFB,
// TAG_SERVERPORT 0xFA, TAG_BUDDYHASH 0xF8, TAG_ENCRYPTION 0xF3.
//
// Search kind is taken from outstanding outbound search context, never inferred
// solely from which tags happen to be present.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <windows.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <vector>

#ifndef KAD_ID_SIZE
#define KAD_ID_SIZE 16
#endif

// Mirror PacketLengthValidate.h caps (keep values identical).
#ifndef KAD_STORE_TAG_MAX
constexpr DWORD KAD_STORE_TAG_MAX = 4u * 1024u;
#endif
#ifndef ED2K_TAG_BLOB_MAX
constexpr DWORD ED2K_TAG_BLOB_MAX = 4u * 1024u * 1024u;
#endif

inline BOOL KadSearchResTagLengthOk(WORD nTagLen)
{
	return nTagLen <= KAD_STORE_TAG_MAX;
}

inline BOOL KadSearchResBlobLengthOk(DWORD nBlobLen, size_t nRemaining)
{
	if (nBlobLen > ED2K_TAG_BLOB_MAX)
		return FALSE;
	return nBlobLen <= nRemaining;
}

// Kad2 source-publish tag name IDs (eMule opcodes.h / aMule FileTags.h).
constexpr BYTE KAD_TAG_SOURCETYPE = 0xFF;
constexpr BYTE KAD_TAG_SOURCEIP = 0xFE;
constexpr BYTE KAD_TAG_SOURCEPORT = 0xFD;
constexpr BYTE KAD_TAG_SOURCEUPORT = 0xFC;
constexpr BYTE KAD_TAG_SERVERIP = 0xFB;
constexpr BYTE KAD_TAG_SERVERPORT = 0xFA;
constexpr BYTE KAD_TAG_CLIENTLOWID = 0xF9;
constexpr BYTE KAD_TAG_BUDDYHASH = 0xF8;
constexpr BYTE KAD_TAG_ENCRYPTION = 0xF3;

// Compact / typed ED2K tag type bytes (subset used while skipping unknowns).
constexpr BYTE KAD_ED2K_TAG_HASH = 0x01;
constexpr BYTE KAD_ED2K_TAG_STRING = 0x02;
constexpr BYTE KAD_ED2K_TAG_INT = 0x03;
constexpr BYTE KAD_ED2K_TAG_FLOAT = 0x04;
constexpr BYTE KAD_ED2K_TAG_BLOB = 0x07;
constexpr BYTE KAD_ED2K_TAG_UINT16 = 0x08;
constexpr BYTE KAD_ED2K_TAG_UINT8 = 0x09;
constexpr BYTE KAD_ED2K_TAG_BSOB = 0x0A;
constexpr BYTE KAD_ED2K_TAG_UINT64 = 0x0B;
constexpr BYTE KAD_ED2K_TAG_SHORTSTRING = 0x11;

// aMule/eMule source types accepted for HighID direct TCP (types 1 and 4).
// Types 3/5 (buddy) and 6 (direct UDP callback) need Buddy/callback paths
// that are out of scope for this slice — refuse delivery rather than invent
// an incorrect ED2K server-push mapping.
constexpr BYTE KAD_SOURCE_TYPE_HIGHID = 1;
constexpr BYTE KAD_SOURCE_TYPE_HIGHID_LARGE = 4;

constexpr size_t KAD_OUTSTANDING_SEARCH_MAX = 64;
constexpr DWORD KAD_SEARCH_CONTEXT_LIFETIME_MS = 45000; // ~aMule SEARCHFILE_LIFETIME

constexpr DWORD KAD_SEARCH_RES_MIN_HEADER =
    KAD_ID_SIZE /* sender */ + KAD_ID_SIZE /* target */ + 2 /* count */;

enum class KadSearchKind : BYTE
{
	None = 0,
	Keyword = 1,
	Source = 2
};

enum class KadSearchResDisposition : BYTE
{
	DeliverSources = 0,
	IgnoreKeywordResults = 1,
	RejectUnsolicited = 2,
	RejectExpired = 3,
	RejectMismatchedTarget = 4
};

struct KadOutstandingSearch
{
	KadSearchKind kind = KadSearchKind::None;
	std::array<BYTE, KAD_ID_SIZE> target{};
	DWORD expiresAt = 0;
};

struct KadSourceCandidate
{
	BYTE sourceType = 0;
	DWORD sourceIp = 0; // TAG_SOURCEIP as published (host LE uint32 on wire)
	WORD tcpPort = 0;   // TAG_SOURCEPORT
	WORD udpPort = 0;   // TAG_SOURCEUPORT (informational)
	DWORD serverOrBuddyIp = 0;
	WORD serverOrBuddyPort = 0;
	BYTE contactId[KAD_ID_SIZE]{};
	bool sawSourceType = false;
	bool sawSourceIp = false;
	bool sawTcpPort = false;
};

struct KadEd2kSourceParams
{
	DWORD nClientID = 0;
	WORD nClientPort = 0;
	DWORD nServerIP = 0;
	WORD nServerPort = 0;
	BYTE oGUID[KAD_ID_SIZE]{};
	bool deliverable = false;
};

// Classify a SEARCH_RES against outstanding context. `targetMatchesContext`
// is true when the packet TargetID equals the registered search target.
inline KadSearchResDisposition KadClassifySearchResponse(
    bool bHasContext,
    bool bContextExpired,
    bool bTargetMatchesContext,
    KadSearchKind nKind)
{
	if (!bHasContext)
		return KadSearchResDisposition::RejectUnsolicited;
	if (bContextExpired)
		return KadSearchResDisposition::RejectExpired;
	if (!bTargetMatchesContext)
		return KadSearchResDisposition::RejectMismatchedTarget;
	if (nKind == KadSearchKind::Keyword)
		return KadSearchResDisposition::IgnoreKeywordResults;
	if (nKind == KadSearchKind::Source)
		return KadSearchResDisposition::DeliverSources;
	return KadSearchResDisposition::RejectUnsolicited;
}

inline bool KadSourceTypeIsHighIdDirect(BYTE nType)
{
	return nType == KAD_SOURCE_TYPE_HIGHID || nType == KAD_SOURCE_TYPE_HIGHID_LARGE;
}

// Map a parsed Kad source candidate into AddSourceED2K parameters.
// HighID only for this slice; buddy/callback types are not deliverable.
inline bool KadMapSourceCandidateToEd2k(
    const KadSourceCandidate& cand,
    KadEd2kSourceParams& out)
{
	out = KadEd2kSourceParams{};
	memcpy(out.oGUID, cand.contactId, KAD_ID_SIZE);

	if (!cand.sawSourceType || !KadSourceTypeIsHighIdDirect(cand.sourceType))
		return false;

	// Mandatory HighID endpoint: TCP port + source IP (aMule KademliaSearchFile).
	if (!cand.sawTcpPort || cand.tcpPort == 0)
		return false;
	if (!cand.sawSourceIp || cand.sourceIp == 0)
		return false;

	// Reject 0.x.x.x the same way AddSourceInternal does for non-push sources.
	if ((cand.sourceIp & 0xFFu) == 0)
		return false;

	out.nClientID = cand.sourceIp;
	out.nClientPort = cand.tcpPort;
	out.nServerIP = 0;
	out.nServerPort = 0;
	out.deliverable = true;
	return true;
}

// Bounded outstanding-search map. Keyed by target hash; no CDownload* ownership.
class KadOutstandingSearchMap
{
public:
	void Clear()
	{
		m_map.clear();
	}

	size_t Size() const
	{
		return m_map.size();
	}

	bool Register(KadSearchKind kind, const BYTE* pTarget, DWORD nowTick)
	{
		if (!pTarget || kind == KadSearchKind::None)
			return false;

		std::array<BYTE, KAD_ID_SIZE> key{};
		memcpy(key.data(), pTarget, KAD_ID_SIZE);

		auto it = m_map.find(key);
		if (it != m_map.end())
		{
			it->second.kind = kind;
			it->second.expiresAt = nowTick + KAD_SEARCH_CONTEXT_LIFETIME_MS;
			return true;
		}

		if (m_map.size() >= KAD_OUTSTANDING_SEARCH_MAX)
			EvictOldestUnlocked();

		if (m_map.size() >= KAD_OUTSTANDING_SEARCH_MAX)
			return false;

		KadOutstandingSearch entry;
		entry.kind = kind;
		entry.target = key;
		entry.expiresAt = nowTick + KAD_SEARCH_CONTEXT_LIFETIME_MS;
		m_map.emplace(key, entry);
		return true;
	}

	// Lookup without removing. Sets *pbExpired when an entry exists but is stale.
	bool Lookup(
	    const BYTE* pTarget,
	    DWORD nowTick,
	    KadOutstandingSearch& out,
	    bool& bExpired) const
	{
		bExpired = false;
		out = KadOutstandingSearch{};
		if (!pTarget)
			return false;

		std::array<BYTE, KAD_ID_SIZE> key{};
		memcpy(key.data(), pTarget, KAD_ID_SIZE);
		auto it = m_map.find(key);
		if (it == m_map.end())
			return false;

		out = it->second;
		if (nowTick >= out.expiresAt)
			bExpired = true;
		return true;
	}

	void Expire(DWORD nowTick)
	{
		for (auto it = m_map.begin(); it != m_map.end();)
		{
			if (nowTick >= it->second.expiresAt)
				it = m_map.erase(it);
			else
				++it;
		}
	}

private:
	void EvictOldestUnlocked()
	{
		auto oldest = m_map.begin();
		for (auto it = m_map.begin(); it != m_map.end(); ++it)
		{
			if (it->second.expiresAt < oldest->second.expiresAt)
				oldest = it;
		}
		if (oldest != m_map.end())
			m_map.erase(oldest);
	}

	std::map<std::array<BYTE, KAD_ID_SIZE>, KadOutstandingSearch> m_map;
};

// --- Byte-cursor helpers for deterministic SEARCH_RES parsing (tests + production) ---

struct KadByteCursor
{
	const BYTE* p = nullptr;
	size_t nLen = 0;
	size_t nPos = 0;

	size_t Remaining() const
	{
		return (nPos <= nLen) ? (nLen - nPos) : 0;
	}

	bool Need(size_t n) const
	{
		return Remaining() >= n;
	}

	bool ReadBytes(void* dest, size_t n)
	{
		if (!Need(n))
			return false;
		memcpy(dest, p + nPos, n);
		nPos += n;
		return true;
	}

	bool ReadByte(BYTE& v)
	{
		return ReadBytes(&v, 1);
	}

	bool ReadWordLE(WORD& v)
	{
		BYTE b[2];
		if (!ReadBytes(b, 2))
			return false;
		v = static_cast<WORD>(b[0] | (static_cast<WORD>(b[1]) << 8));
		return true;
	}

	bool ReadDwordLE(DWORD& v)
	{
		BYTE b[4];
		if (!ReadBytes(b, 4))
			return false;
		v = static_cast<DWORD>(b[0]) |
		    (static_cast<DWORD>(b[1]) << 8) |
		    (static_cast<DWORD>(b[2]) << 16) |
		    (static_cast<DWORD>(b[3]) << 24);
		return true;
	}

	bool Skip(size_t n)
	{
		if (!Need(n))
			return false;
		nPos += n;
		return true;
	}
};

inline bool KadSkipEd2kTagValue(KadByteCursor& cur, BYTE nType)
{
	switch (nType)
	{
	case KAD_ED2K_TAG_HASH:
		return cur.Skip(16);
	case KAD_ED2K_TAG_STRING:
	{
		WORD nLen = 0;
		if (!cur.ReadWordLE(nLen))
			return false;
		if (!KadSearchResTagLengthOk(nLen))
			return false;
		return cur.Skip(nLen);
	}
	case KAD_ED2K_TAG_INT:
	case KAD_ED2K_TAG_FLOAT:
		return cur.Skip(4);
	case KAD_ED2K_TAG_UINT16:
		return cur.Skip(2);
	case KAD_ED2K_TAG_UINT8:
		return cur.Skip(1);
	case KAD_ED2K_TAG_UINT64:
		return cur.Skip(8);
	case KAD_ED2K_TAG_BLOB:
	{
		DWORD nLen = 0;
		if (!cur.ReadDwordLE(nLen))
			return false;
		if (!KadSearchResBlobLengthOk(nLen, cur.Remaining()))
			return false;
		return cur.Skip(nLen);
	}
	case KAD_ED2K_TAG_BSOB:
	{
		BYTE nLen = 0;
		if (!cur.ReadByte(nLen))
			return false;
		return cur.Skip(nLen);
	}
	default:
		if (nType >= KAD_ED2K_TAG_SHORTSTRING &&
		    nType <= static_cast<BYTE>(KAD_ED2K_TAG_SHORTSTRING + 15))
		{
			const BYTE nLen = static_cast<BYTE>(nType - (KAD_ED2K_TAG_SHORTSTRING - 1));
			return cur.Skip(nLen);
		}
		// Unknown type: fail-closed (do not guess STRING vs INT).
		return false;
	}
}

inline bool KadReadEd2kIntTagValue(KadByteCursor& cur, BYTE nType, uint64_t& nValue)
{
	nValue = 0;
	switch (nType)
	{
	case KAD_ED2K_TAG_UINT8:
	{
		BYTE v = 0;
		if (!cur.ReadByte(v))
			return false;
		nValue = v;
		return true;
	}
	case KAD_ED2K_TAG_UINT16:
	{
		WORD v = 0;
		if (!cur.ReadWordLE(v))
			return false;
		nValue = v;
		return true;
	}
	case KAD_ED2K_TAG_INT:
	{
		DWORD v = 0;
		if (!cur.ReadDwordLE(v))
			return false;
		nValue = v;
		return true;
	}
	case KAD_ED2K_TAG_UINT64:
	{
		BYTE b[8];
		if (!cur.ReadBytes(b, 8))
			return false;
		nValue = 0;
		for (int i = 7; i >= 0; --i)
			nValue = (nValue << 8) | b[i];
		return true;
	}
	default:
		return false;
	}
}

// Read one ED2K tag. Applies known Kad source ints into `cand`; skips other
// well-framed optional tags; fails closed on truncation / impossible lengths.
inline bool KadConsumeSearchResTag(KadByteCursor& cur, KadSourceCandidate& cand)
{
	if (!cur.Need(1))
		return false;

	BYTE nTypeRaw = 0;
	if (!cur.ReadByte(nTypeRaw))
		return false;

	BYTE nType = nTypeRaw;
	BYTE nKey = 0;
	bool bHasNameId = false;

	if (nTypeRaw & 0x80)
	{
		nType = static_cast<BYTE>(nTypeRaw & 0x7F);
		if (!cur.ReadByte(nKey))
			return false;
		bHasNameId = true;
	}
	else
	{
		WORD nNameLen = 0;
		if (!cur.ReadWordLE(nNameLen))
			return false;
		if (nNameLen == 0)
			return false;
		if (nNameLen == 1)
		{
			if (!cur.ReadByte(nKey))
				return false;
			bHasNameId = true;
		}
		else
		{
			// Named string keys are optional metadata — skip the name then value.
			if (!KadSearchResTagLengthOk(nNameLen))
				return false;
			if (!cur.Skip(nNameLen))
				return false;
			return KadSkipEd2kTagValue(cur, nType);
		}
	}

	const bool bIntType =
	    nType == KAD_ED2K_TAG_INT ||
	    nType == KAD_ED2K_TAG_UINT8 ||
	    nType == KAD_ED2K_TAG_UINT16 ||
	    nType == KAD_ED2K_TAG_UINT64;

	if (bHasNameId && bIntType)
	{
		uint64_t nValue = 0;
		if (!KadReadEd2kIntTagValue(cur, nType, nValue))
			return false;

		switch (nKey)
		{
		case KAD_TAG_SOURCETYPE:
			cand.sourceType = static_cast<BYTE>(nValue & 0xFF);
			cand.sawSourceType = true;
			break;
		case KAD_TAG_SOURCEIP:
			cand.sourceIp = static_cast<DWORD>(nValue);
			cand.sawSourceIp = true;
			break;
		case KAD_TAG_SOURCEPORT:
			cand.tcpPort = static_cast<WORD>(nValue & 0xFFFF);
			cand.sawTcpPort = true;
			break;
		case KAD_TAG_SOURCEUPORT:
			cand.udpPort = static_cast<WORD>(nValue & 0xFFFF);
			break;
		case KAD_TAG_SERVERIP:
			cand.serverOrBuddyIp = static_cast<DWORD>(nValue);
			break;
		case KAD_TAG_SERVERPORT:
			cand.serverOrBuddyPort = static_cast<WORD>(nValue & 0xFFFF);
			break;
		case KAD_TAG_CLIENTLOWID:
		case KAD_TAG_ENCRYPTION:
			// Recognized but unused in this HighID-only slice.
			break;
		default:
			break;
		}
		return true;
	}

	// Buddyhash is a string; skip without failing.
	return KadSkipEd2kTagValue(cur, nType);
}

inline bool KadParseSearchResEntry(
    KadByteCursor& cur,
    KadSourceCandidate& cand)
{
	cand = KadSourceCandidate{};
	if (!cur.ReadBytes(cand.contactId, KAD_ID_SIZE))
		return false;

	BYTE nTagCount = 0;
	if (!cur.ReadByte(nTagCount))
		return false;

	// Defensive cap (aMule asserts <= 0xFF; keep hostile tag floods bounded).
	if (nTagCount > 64)
		return false;

	for (BYTE i = 0; i < nTagCount; ++i)
	{
		if (!KadConsumeSearchResTag(cur, cand))
			return false;
	}
	return true;
}

// Parse a full KADEMLIA2_SEARCH_RES body (after opcode). Fails closed on
// truncated frames or count larger than available well-formed entries.
inline bool KadParseSearchResBody(
    const BYTE* pData,
    size_t nLen,
    BYTE* pSenderOut, // optional 16
    BYTE* pTargetOut, // optional 16
    WORD& nCountOut,
    std::vector<KadSourceCandidate>* pEntriesOut, // null = validate only
    bool bStopAfterHeader = false)
{
	nCountOut = 0;
	if (pEntriesOut)
		pEntriesOut->clear();

	if (!pData || nLen < KAD_SEARCH_RES_MIN_HEADER)
		return false;

	KadByteCursor cur{ pData, nLen, 0 };
	BYTE sender[KAD_ID_SIZE];
	BYTE target[KAD_ID_SIZE];
	if (!cur.ReadBytes(sender, KAD_ID_SIZE))
		return false;
	if (!cur.ReadBytes(target, KAD_ID_SIZE))
		return false;
	if (!cur.ReadWordLE(nCountOut))
		return false;

	if (pSenderOut)
		memcpy(pSenderOut, sender, KAD_ID_SIZE);
	if (pTargetOut)
		memcpy(pTargetOut, target, KAD_ID_SIZE);

	if (bStopAfterHeader)
		return true;

	for (WORD i = 0; i < nCountOut; ++i)
	{
		KadSourceCandidate cand;
		if (!KadParseSearchResEntry(cur, cand))
			return false;
		if (pEntriesOut)
			pEntriesOut->push_back(cand);
	}
	return true;
}

// Append a compact UINT8/UINT16/INT name-ID tag (type|0x80, key, value).
inline void KadAppendCompactIntTag(
    std::vector<BYTE>& buf,
    BYTE nType,
    BYTE nKey,
    uint64_t nValue)
{
	buf.push_back(static_cast<BYTE>(0x80 | nType));
	buf.push_back(nKey);
	if (nType == KAD_ED2K_TAG_UINT8)
	{
		buf.push_back(static_cast<BYTE>(nValue & 0xFF));
	}
	else if (nType == KAD_ED2K_TAG_UINT16)
	{
		const WORD v = static_cast<WORD>(nValue & 0xFFFF);
		buf.push_back(static_cast<BYTE>(v & 0xFF));
		buf.push_back(static_cast<BYTE>((v >> 8) & 0xFF));
	}
	else if (nType == KAD_ED2K_TAG_INT)
	{
		const DWORD v = static_cast<DWORD>(nValue);
		buf.push_back(static_cast<BYTE>(v & 0xFF));
		buf.push_back(static_cast<BYTE>((v >> 8) & 0xFF));
		buf.push_back(static_cast<BYTE>((v >> 16) & 0xFF));
		buf.push_back(static_cast<BYTE>((v >> 24) & 0xFF));
	}
}

inline void KadAppendId(std::vector<BYTE>& buf, BYTE fill)
{
	for (int i = 0; i < KAD_ID_SIZE; ++i)
		buf.push_back(fill);
}

inline void KadAppendIdBytes(std::vector<BYTE>& buf, const BYTE* pId)
{
	buf.insert(buf.end(), pId, pId + KAD_ID_SIZE);
}

inline void KadAppendWordLE(std::vector<BYTE>& buf, WORD v)
{
	buf.push_back(static_cast<BYTE>(v & 0xFF));
	buf.push_back(static_cast<BYTE>((v >> 8) & 0xFF));
}

// Build one HighID source entry for tests.
inline void KadAppendHighIdSourceEntry(
    std::vector<BYTE>& buf,
    BYTE contactFill,
    DWORD ip,
    WORD tcpPort,
    BYTE sourceType = KAD_SOURCE_TYPE_HIGHID,
    bool bExtraUnknownOptional = false)
{
	KadAppendId(buf, contactFill);
	BYTE nTags = 3;
	if (bExtraUnknownOptional)
		++nTags;
	buf.push_back(nTags);
	KadAppendCompactIntTag(buf, KAD_ED2K_TAG_UINT8, KAD_TAG_SOURCETYPE, sourceType);
	KadAppendCompactIntTag(buf, KAD_ED2K_TAG_INT, KAD_TAG_SOURCEIP, ip);
	KadAppendCompactIntTag(buf, KAD_ED2K_TAG_UINT16, KAD_TAG_SOURCEPORT, tcpPort);
	if (bExtraUnknownOptional)
	{
		// Optional unknown name-ID UINT8 tag (0xEE) — must not corrupt parser.
		KadAppendCompactIntTag(buf, KAD_ED2K_TAG_UINT8, 0xEE, 0x42);
	}
}
