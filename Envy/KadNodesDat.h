//
// KadNodesDat.h
//
// Pure nodes.dat reader for eMule/aMule-compatible Kad bootstrap files.
// No MFC, no sockets, no UI. Suitable for EnvyTests and later fuzzing (#229/#91).
//
// File versions (little-endian integer fields unless noted):
//   v0 legacy     — leading count != 0, 25-byte records, type byte (not Kad version)
//   v1            — marker 0, version 1, count, 25-byte records + Kad version
//   v2            — marker 0, version 2, count, 34-byte records (UDP-key + verified)
//   v3 normal     — marker 0, version 3, edition 0, count, 34-byte records
//   v3 bootstrap  — marker 0, version 3, edition 1, count, 25-byte records
//
// IP on disk is the four IPv4 octets in network order, which matches
// eMule CContact::GetIPAddress() written via WriteUInt32 on little-endian
// (ReadUInt32 then ntohl for IsGoodIPPort). UDP/TCP ports are little-endian
// host-order integers (4672 = 40 12). KadUDPKey is two little-endian uint32
// fields (key, associated IP in the same internal IP encoding).
//
// Runtime Kad UDP-key protocol and IP-verified trust are NOT implemented.
// Those fields are parsed so the file is consumed correctly, then discarded.
// Do not advertise UDP-key support from this reader.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

// 256 KiB comfortably holds the documented 5000-contact practice cap
// (5000 * 34 + 16-byte v3 header = 170016) and typical 500-1000 contact
// bootstrap editions (1000 * 25 + 16 = 25016). Evidence: aMule
// CONTACT_FILE_LIMIT 500 on write, 5000 mentioned as the shared hard cap;
// bootstrap editions are 500-1000 contacts.
constexpr uint32_t KadNodesDatMaxFileBytes = 256u * 1024u;
constexpr uint32_t KadNodesDatMaxContacts = 5000u;
// aMule ReadBootstrapNodesDat keeps the 50 XOR-closest valid Kad2 contacts.
constexpr uint32_t KadNodesDatBootstrapSelect = 50u;
// aMule WriteFile samples about 200 contacts (CONTACT_FILE_LIMIT 500).
constexpr uint32_t KadNodesDatNormalImportCap = 200u;
// Import-boundary eclipse hedge; not a full routing-table /24 subsystem.
constexpr uint32_t KadNodesDatMaxPerSlash24 = 2u;
// Kad1 contacts (version <= 1) are ignored, matching aMule ReadFile.
constexpr uint8_t KadNodesDatMinKad2Version = 2u;
// eMule KADEMLIA_VERSION5_48a: UDP/53 without encryption is rejected.
constexpr uint8_t KadNodesDatDnsPortEncVersion = 5u;
constexpr uint16_t KadNodesDatDnsUdpPort = 53u;

constexpr uint32_t KadNodesDatRecordBytesV0 = 25u;
constexpr uint32_t KadNodesDatRecordBytesV1 = 25u;
constexpr uint32_t KadNodesDatRecordBytesV2 = 34u;
constexpr uint32_t KadNodesDatRecordBytesBootstrap = 25u;

enum class KadNodesDatStatus
{
	Ok = 0,
	Truncated,
	UnknownVersion,
	InvalidEdition,
	SizeLimit,
	CountMismatch,
	Empty
};

enum class KadNodesDatKind
{
	LegacyV0 = 0,
	Version1,
	Version2,
	Version3Normal,
	Version3Bootstrap
};

struct KadNodesDatContact
{
	uint8_t id[16];
	uint8_t ip[4];    // network-order octets
	uint16_t udpPort; // host order
	uint16_t tcpPort; // host order
	uint8_t contactVersion;
	uint8_t type;    // v0 type byte; 0 on versioned files
	uint32_t udpKey; // parsed then discarded at runtime
	uint32_t udpKeyIp;
	uint8_t verified; // parsed; never treated as ping/pong trust
};

struct KadNodesDatResult
{
	KadNodesDatStatus status;
	KadNodesDatKind kind;
	uint32_t fileVersion;
	uint32_t edition;
	bool bootstrapEdition;
	uint32_t declaredCount;
	uint32_t acceptedCount;
};

inline uint16_t KadNodesDatReadU16LE(const uint8_t* p)
{
	return static_cast<uint16_t>(p[0] | (static_cast<uint16_t>(p[1]) << 8));
}

inline uint32_t KadNodesDatReadU32LE(const uint8_t* p)
{
	return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) | (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

inline bool KadNodesDatCountFits(uint32_t nCount, uint32_t nRecordBytes, size_t nRemaining)
{
	if (nRecordBytes == 0)
		return false;
	return nCount <= (nRemaining / nRecordBytes);
}

inline bool KadNodesDatIdIsZero(const uint8_t* pId)
{
	for (int i = 0; i < 16; ++i)
	{
		if (pId[i] != 0)
			return false;
	}
	return true;
}

// Parser-layer IPv4 policy. Rejects unspecified, loopback, RFC1918, link-local,
// and multicast/Class-E. TEST-NET-2/3 (198.51.100/24, 203.0.113/24) are allowed
// so fixtures need no live public addresses. HostCache::Add still applies
// Network.IsReserved / Security.IsDenied on the live import path.
inline bool KadNodesDatIpIsAcceptable(const uint8_t ip[4])
{
	const uint8_t a = ip[0];
	const uint8_t b = ip[1];
	if (a == 0)
		return false;
	if (a == 127)
		return false;
	if (a == 10)
		return false;
	if (a == 169 && b == 254)
		return false;
	if (a == 172 && b >= 16 && b <= 31)
		return false;
	if (a == 192 && b == 168)
		return false;
	if (a >= 224)
		return false;
	return true;
}

inline uint32_t KadNodesDatSlash24Key(const uint8_t ip[4])
{
	return (static_cast<uint32_t>(ip[0]) << 16) | (static_cast<uint32_t>(ip[1]) << 8) | static_cast<uint32_t>(ip[2]);
}

inline bool KadNodesDatContactValid(const KadNodesDatContact& c, bool bVersioned)
{
	if (KadNodesDatIdIsZero(c.id))
		return false;
	if (!KadNodesDatIpIsAcceptable(c.ip))
		return false;
	if (c.udpPort == 0)
		return false;
	if (bVersioned)
	{
		if (c.contactVersion < KadNodesDatMinKad2Version)
			return false;
		if (c.udpPort == KadNodesDatDnsUdpPort && c.contactVersion <= KadNodesDatDnsPortEncVersion)
			return false;
	}
	else
	{
		// Legacy v0 stores a type byte, not a Kad protocol version. aMule no
		// longer reads v0. ENVY still parses each record so a truncated file
		// fails closed, then drops every contact: Kad2 bootstrap requires a
		// version nibble that v0 does not carry. Do not import type < 4 as
		// Kad2 contacts.
		return false;
	}
	return true;
}

inline int KadNodesDatXorCmp(
    const uint8_t ownId[16],
    const uint8_t a[16],
    const uint8_t b[16])
{
	for (int i = 0; i < 16; ++i)
	{
		const uint8_t da = static_cast<uint8_t>(ownId[i] ^ a[i]);
		const uint8_t db = static_cast<uint8_t>(ownId[i] ^ b[i]);
		if (da < db)
			return -1;
		if (da > db)
			return 1;
	}
	return 0;
}

inline bool KadNodesDatSameEndpoint(const KadNodesDatContact& a, const KadNodesDatContact& b)
{
	return std::memcmp(a.ip, b.ip, 4) == 0 && a.udpPort == b.udpPort;
}

inline bool KadNodesDatSameId(const KadNodesDatContact& a, const KadNodesDatContact& b)
{
	return std::memcmp(a.id, b.id, 16) == 0;
}

inline uint32_t KadNodesDatCountSlash24(
    const KadNodesDatContact* pContacts,
    uint32_t nCount,
    uint32_t nKey)
{
	uint32_t n = 0;
	for (uint32_t i = 0; i < nCount; ++i)
	{
		if (KadNodesDatSlash24Key(pContacts[i].ip) == nKey)
			++n;
	}
	return n;
}

inline bool KadNodesDatAlreadyPresent(
    const KadNodesDatContact* pContacts,
    uint32_t nCount,
    const KadNodesDatContact& c)
{
	for (uint32_t i = 0; i < nCount; ++i)
	{
		if (KadNodesDatSameId(pContacts[i], c))
			return true;
		if (KadNodesDatSameEndpoint(pContacts[i], c))
			return true;
	}
	return false;
}

inline bool KadNodesDatTryAppend(
    KadNodesDatContact* pOut,
    uint32_t* pCount,
    uint32_t nMaxOut,
    const KadNodesDatContact& c)
{
	if (*pCount >= nMaxOut)
		return false;
	if (KadNodesDatAlreadyPresent(pOut, *pCount, c))
		return false;
	if (KadNodesDatCountSlash24(pOut, *pCount, KadNodesDatSlash24Key(c.ip)) >= KadNodesDatMaxPerSlash24)
		return false;
	pOut[*pCount] = c;
	++(*pCount);
	return true;
}

// Keep at most nMaxOut contacts closest to ownId (aMule bootstrap list).
inline void KadNodesDatInsertClosest(
    KadNodesDatContact* pOut,
    uint32_t* pCount,
    uint32_t nMaxOut,
    const KadNodesDatContact& c,
    const uint8_t ownId[16])
{
	if (nMaxOut == 0)
		return;
	if (KadNodesDatAlreadyPresent(pOut, *pCount, c))
		return;
	if (KadNodesDatCountSlash24(pOut, *pCount, KadNodesDatSlash24Key(c.ip)) >= KadNodesDatMaxPerSlash24)
		return;

	if (*pCount == nMaxOut && KadNodesDatXorCmp(ownId, pOut[*pCount - 1].id, c.id) <= 0)
		return;

	uint32_t nInsert = 0;
	while (nInsert < *pCount && KadNodesDatXorCmp(ownId, c.id, pOut[nInsert].id) >= 0)
		++nInsert;
	// Full lists only reach here when c is closer than the farthest entry, so
	// nInsert is in [0, nMaxOut). Bound it anyway so a 1-slot caller cannot
	// write past the output array.
	if (nInsert >= nMaxOut)
		return;

	uint32_t nKeep = *pCount;
	if (nKeep < nMaxOut)
		++nKeep;
	for (uint32_t i = nKeep; i > nInsert + 1; --i)
		pOut[i - 1] = pOut[i - 2];
	pOut[nInsert] = c;
	*pCount = nKeep;
}

struct KadNodesDatCursor
{
	const uint8_t* p;
	size_t n;
	size_t i;
};

inline bool KadNodesDatTake(KadNodesDatCursor& c, size_t nNeed, const uint8_t** pp)
{
	if (nNeed > c.n - c.i)
		return false;
	if (pp)
		*pp = c.p + c.i;
	c.i += nNeed;
	return true;
}

inline bool KadNodesDatTakeU16(KadNodesDatCursor& c, uint16_t* pValue)
{
	const uint8_t* p = nullptr;
	if (!KadNodesDatTake(c, 2, &p))
		return false;
	*pValue = KadNodesDatReadU16LE(p);
	return true;
}

inline bool KadNodesDatTakeU32(KadNodesDatCursor& c, uint32_t* pValue)
{
	const uint8_t* p = nullptr;
	if (!KadNodesDatTake(c, 4, &p))
		return false;
	*pValue = KadNodesDatReadU32LE(p);
	return true;
}

inline bool KadNodesDatTakeU8(KadNodesDatCursor& c, uint8_t* pValue)
{
	const uint8_t* p = nullptr;
	if (!KadNodesDatTake(c, 1, &p))
		return false;
	*pValue = p[0];
	return true;
}

inline uint32_t KadNodesDatRecordBytes(KadNodesDatKind kind)
{
	switch (kind)
	{
	case KadNodesDatKind::Version2:
	case KadNodesDatKind::Version3Normal:
		return KadNodesDatRecordBytesV2;
	case KadNodesDatKind::LegacyV0:
		return KadNodesDatRecordBytesV0;
	default:
		return KadNodesDatRecordBytesV1;
	}
}

inline KadNodesDatResult KadNodesDatMakeResult(
    KadNodesDatStatus status,
    KadNodesDatKind kind = KadNodesDatKind::LegacyV0,
    uint32_t nVersion = 0,
    uint32_t nEdition = 0,
    uint32_t nDeclared = 0,
    uint32_t nAccepted = 0)
{
	KadNodesDatResult r = {};
	r.status = status;
	r.kind = kind;
	r.fileVersion = nVersion;
	r.edition = nEdition;
	r.bootstrapEdition = (kind == KadNodesDatKind::Version3Bootstrap);
	r.declaredCount = nDeclared;
	r.acceptedCount = nAccepted;
	return r;
}

inline bool KadNodesDatReadOneContact(
    KadNodesDatCursor& cur,
    KadNodesDatKind kind,
    KadNodesDatContact* pOut)
{
	KadNodesDatContact c = {};
	const uint8_t* pId = nullptr;
	if (!KadNodesDatTake(cur, 16, &pId))
		return false;
	std::memcpy(c.id, pId, 16);

	const uint8_t* pIp = nullptr;
	if (!KadNodesDatTake(cur, 4, &pIp))
		return false;
	std::memcpy(c.ip, pIp, 4);

	if (!KadNodesDatTakeU16(cur, &c.udpPort))
		return false;
	if (!KadNodesDatTakeU16(cur, &c.tcpPort))
		return false;

	const bool bWide = (kind == KadNodesDatKind::Version2 || kind == KadNodesDatKind::Version3Normal);

	if (kind == KadNodesDatKind::LegacyV0)
	{
		if (!KadNodesDatTakeU8(cur, &c.type))
			return false;
	}
	else
	{
		if (!KadNodesDatTakeU8(cur, &c.contactVersion))
			return false;
	}

	if (bWide)
	{
		if (!KadNodesDatTakeU32(cur, &c.udpKey))
			return false;
		if (!KadNodesDatTakeU32(cur, &c.udpKeyIp))
			return false;
		if (!KadNodesDatTakeU8(cur, &c.verified))
			return false;
	}

	*pOut = c;
	return true;
}

inline KadNodesDatResult KadNodesDatParse(
    const uint8_t* pData,
    size_t nSize,
    KadNodesDatContact* pOut,
    uint32_t nMaxOut,
    const uint8_t ownId[16])
{
	uint8_t zeroId[16] = {};
	const uint8_t* pOwn = ownId ? ownId : zeroId;

	if (pData == nullptr && nSize != 0)
		return KadNodesDatMakeResult(KadNodesDatStatus::Truncated);
	if (nSize > KadNodesDatMaxFileBytes)
		return KadNodesDatMakeResult(KadNodesDatStatus::SizeLimit);
	if (nSize < 4)
		return KadNodesDatMakeResult(KadNodesDatStatus::Truncated);

	KadNodesDatCursor cur = { pData, nSize, 0 };
	uint32_t nFirst = 0;
	if (!KadNodesDatTakeU32(cur, &nFirst))
		return KadNodesDatMakeResult(KadNodesDatStatus::Truncated);

	KadNodesDatKind kind = KadNodesDatKind::LegacyV0;
	uint32_t nVersion = 0;
	uint32_t nEdition = 0;
	uint32_t nCount = 0;

	if (nFirst != 0)
	{
		kind = KadNodesDatKind::LegacyV0;
		nCount = nFirst;
	}
	else
	{
		if (!KadNodesDatTakeU32(cur, &nVersion))
			return KadNodesDatMakeResult(KadNodesDatStatus::Truncated);
		if (nVersion < 1 || nVersion > 3)
			return KadNodesDatMakeResult(KadNodesDatStatus::UnknownVersion, kind, nVersion);
		if (nVersion == 3)
		{
			if (!KadNodesDatTakeU32(cur, &nEdition))
				return KadNodesDatMakeResult(KadNodesDatStatus::Truncated, kind, nVersion);
			if (nEdition == 1)
				kind = KadNodesDatKind::Version3Bootstrap;
			else if (nEdition == 0)
				kind = KadNodesDatKind::Version3Normal;
			else
				return KadNodesDatMakeResult(
				    KadNodesDatStatus::InvalidEdition, kind, nVersion, nEdition);
		}
		else if (nVersion == 2)
		{
			kind = KadNodesDatKind::Version2;
		}
		else
		{
			kind = KadNodesDatKind::Version1;
		}
		if (!KadNodesDatTakeU32(cur, &nCount))
			return KadNodesDatMakeResult(KadNodesDatStatus::Truncated, kind, nVersion, nEdition);
	}

	if (nCount == 0)
		return KadNodesDatMakeResult(KadNodesDatStatus::Empty, kind, nVersion, nEdition, 0, 0);

	if (nCount > KadNodesDatMaxContacts)
		return KadNodesDatMakeResult(
		    KadNodesDatStatus::CountMismatch, kind, nVersion, nEdition, nCount, 0);

	const uint32_t nRec = KadNodesDatRecordBytes(kind);
	const size_t nRemain = cur.n - cur.i;
	if (!KadNodesDatCountFits(nCount, nRec, nRemain))
		return KadNodesDatMakeResult(
		    KadNodesDatStatus::CountMismatch, kind, nVersion, nEdition, nCount, 0);
	if (nRemain != static_cast<size_t>(nCount) * nRec)
		return KadNodesDatMakeResult(
		    KadNodesDatStatus::CountMismatch, kind, nVersion, nEdition, nCount, 0);

	const bool bVersioned = (kind != KadNodesDatKind::LegacyV0);
	const bool bBootstrap = (kind == KadNodesDatKind::Version3Bootstrap);
	uint32_t nCap = nMaxOut;
	if (bBootstrap && nCap > KadNodesDatBootstrapSelect)
		nCap = KadNodesDatBootstrapSelect;
	uint32_t nAccepted = 0;

	for (uint32_t i = 0; i < nCount; ++i)
	{
		KadNodesDatContact c = {};
		if (!KadNodesDatReadOneContact(cur, kind, &c))
			return KadNodesDatMakeResult(
			    KadNodesDatStatus::Truncated, kind, nVersion, nEdition, nCount, 0);
		if (!KadNodesDatContactValid(c, bVersioned))
			continue;
		if (bBootstrap)
			KadNodesDatInsertClosest(pOut, &nAccepted, nCap, c, pOwn);
		else
			KadNodesDatTryAppend(pOut, &nAccepted, nCap, c);
	}

	if (cur.i != cur.n)
		return KadNodesDatMakeResult(
		    KadNodesDatStatus::CountMismatch, kind, nVersion, nEdition, nCount, 0);

	return KadNodesDatMakeResult(KadNodesDatStatus::Ok, kind, nVersion, nEdition, nCount, nAccepted);
}
