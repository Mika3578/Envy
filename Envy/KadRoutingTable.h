//
// KadRoutingTable.h
//
// Kad2 routing-table maintenance (eMule/aMule semantics).
// Pure helpers shared by CKademlia and EnvyTests. No MFC/UI, no wire codecs.
//
// Zone model (aMule CRoutingZone / eMule Community RoutingZone.cpp):
//   * Binary tree of zones over 128-bit XOR distance from the local Kad ID.
//   * Leaves hold a routing bin of at most KAD_K (10) contacts.
//   * CanSplit: level < 127 AND size == K AND (prefixInteger < KK OR level < KBASE).
//   * Zone identity is a 128-bit XOR prefix (not a uint32 zoneIndex) so depth >= 32
//     never shifts a 32-bit index (UB). prefixInteger saturates at UINT32_MAX.
//   * Unsplittable full leaves use LRU + bounded replacement (1 slot).
//   * Subnet caps: 2 contacts per /24 per bin, 10 per /24 globally, 1 Kad ID per IP
//     (LAN excepted when allowLan is set). aMule CRoutingBin::AddContact /
//     CheckGlobalIPLimits / MAX_CONTACTS_IP / MAX_CONTACTS_SUBNET.
//
// verified: set only after protocol evidence equivalent to a HELLO_RES from that
// endpoint (KadContactSource::Observed + markVerified). nodes.dat "verified"
// bytes are not treated as live-verified here.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <vector>

#ifndef KAD_ID_SIZE
#define KAD_ID_SIZE 16
#endif

typedef unsigned char KadId[KAD_ID_SIZE];

// --- Kad2 routing constants (aMule Defines.h / eMule Defines.h) ---
constexpr int KAD_K = 10;
constexpr int KAD_ID_BITS = 128;
constexpr unsigned KAD_KBASE = 4; // aMule KBASE
constexpr unsigned KAD_KK = 5;    // aMule KK
constexpr unsigned KAD_MAX_LEVEL = 127;
constexpr size_t KAD_MAX_CONTACTS = 2048;
constexpr size_t KAD_MAX_ZONES = 1024;
constexpr size_t KAD_REPLACEMENT_CACHE = 1;
constexpr unsigned KAD_MAX_CONTACTS_PER_IP = 1;
constexpr unsigned KAD_MAX_CONTACTS_SUBNET_BIN = 2;
constexpr unsigned KAD_MAX_CONTACTS_SUBNET_GLOBAL = 10;
constexpr uint8_t KAD_CONTACT_TYPE_NEW = 3;
constexpr uint8_t KAD_CONTACT_TYPE_DEAD = 4;
constexpr uint8_t KAD_MIN_VERSION_NO_DNS_PORT = 6;

// Timing (aMule Contact.cpp / RoutingZone.cpp / Kademlia.cpp Process)
constexpr uint64_t KAD_MS_PER_SECOND = 1000;
constexpr uint64_t KAD_MS_PER_MINUTE = 60 * KAD_MS_PER_SECOND;
constexpr uint64_t KAD_MS_PER_HOUR = 60 * KAD_MS_PER_MINUTE;
constexpr uint64_t KAD_CONTACT_TYPE_CHECK_MIN_MS = 10 * KAD_MS_PER_SECOND;
constexpr uint64_t KAD_CONTACT_CHECKING_EXPIRE_MS = 2 * KAD_MS_PER_MINUTE;
constexpr uint64_t KAD_CONTACT_TYPE2_EXPIRE_MS = 1 * KAD_MS_PER_HOUR;
constexpr uint64_t KAD_CONTACT_TYPE1_EXPIRE_MS = 90 * KAD_MS_PER_MINUTE;
constexpr uint64_t KAD_CONTACT_TYPE0_EXPIRE_MS = 2 * KAD_MS_PER_HOUR;
constexpr uint64_t KAD_ZONE_REFRESH_INTERVAL_MS = 1 * KAD_MS_PER_HOUR;
constexpr uint64_t KAD_ZONE_REFRESH_MIN_GAP_MS = 10 * KAD_MS_PER_SECOND;
constexpr uint64_t KAD_ZONE_REFRESH_START_MS = 10 * KAD_MS_PER_SECOND;
constexpr uint64_t KAD_SMALL_TIMER_MS = 1 * KAD_MS_PER_MINUTE;
constexpr size_t KAD_MAINT_MAX_DEAD_PER_TICK = 8;
constexpr size_t KAD_MAINT_MAX_PING_PER_TICK = 1;
constexpr size_t KAD_MAINT_MAX_REFRESH_PER_TICK = 1;

// How a contact was learned. AddContact does not infer trust from incomplete data.
enum class KadContactSource
{
	Candidate = 0, // Listed by a third party (bootstrap/FIND_NODE contacts)
	Observed = 1   // Directly observed responding peer
};

struct KadContactUpdate
{
	KadContactSource source = KadContactSource::Candidate;
	bool markVerified = false; // HELLO_RES (or equivalent) only
	bool markAlive = false;    // Valid protocol traffic from this identity
	uint64_t nowMs = 0;
	bool allowLan = false;
};

struct KadContact
{
	KadId id;
	uint32_t ip; // IPv4, host order (first octet in the high byte)
	uint16_t udpPort;
	uint16_t tcpPort;
	uint64_t lastSeen; // Monotonic milliseconds (injected)
	uint8_t version;
	bool verified; // IP/ID confirmed by HELLO_RES (not a generic trust bit)
	uint8_t type;  // 0 live-old .. 3 new .. 4 dead (aMule CContact)
	uint64_t created;
	uint64_t expires;
	uint64_t lastTypeSet;
	bool receivedHello;

	KadContact()
	{
		std::memset(this, 0, sizeof(KadContact));
		type = KAD_CONTACT_TYPE_NEW;
	}

	KadContact(const KadId& nodeId, uint32_t nodeIp, uint16_t nodeUdpPort, uint16_t nodeTcpPort = 0)
	{
		std::memset(this, 0, sizeof(KadContact));
		std::memcpy(id, nodeId, KAD_ID_SIZE);
		ip = nodeIp;
		udpPort = nodeUdpPort;
		tcpPort = nodeTcpPort ? nodeTcpPort : nodeUdpPort;
		version = 0;
		verified = false;
		type = KAD_CONTACT_TYPE_NEW;
	}
};

struct KadLeafInfo
{
	uint32_t level = 0;
	uint32_t zoneIndex = 0;
	size_t contacts = 0;
	size_t replacement = 0;
	uint64_t lastRefresh = 0;
	uint64_t nextBigTimer = 0;
};

struct KadMaintenanceAction
{
	bool ping = false;
	KadContact pingContact;
	bool refresh = false;
	KadId refreshTarget;
	KadContact refreshPeer;
	size_t deadRemoved = 0;
};

// --- ID / XOR helpers (full 128-bit, MSB-first byte 0) ---

inline void KadIdCopy(KadId& dst, const KadId& src)
{
	std::memcpy(dst, src, KAD_ID_SIZE);
}

inline bool KadIdEqual(const KadId& a, const KadId& b)
{
	return std::memcmp(a, b, KAD_ID_SIZE) == 0;
}

inline bool KadIdIsZero(const KadId& id)
{
	for (int i = 0; i < KAD_ID_SIZE; ++i)
	{
		if (id[i] != 0)
			return false;
	}
	return true;
}

inline void KadIdXor(KadId& out, const KadId& a, const KadId& b)
{
	for (int i = 0; i < KAD_ID_SIZE; ++i)
		out[i] = static_cast<unsigned char>(a[i] ^ b[i]);
}

inline int KadIdCompare(const KadId& a, const KadId& b)
{
	return std::memcmp(a, b, KAD_ID_SIZE);
}

// Bit 0 is the highest XOR-distance bit (byte 0, 0x80).
inline int KadDistanceBit(const KadId& distance, unsigned level)
{
	if (level >= static_cast<unsigned>(KAD_ID_BITS))
		return 0;
	const unsigned byte = level / 8;
	const unsigned mask = 0x80u >> (level % 8);
	return (distance[byte] & mask) ? 1 : 0;
}

inline void KadIdSetBit(KadId& id, unsigned level, int bit)
{
	if (level >= static_cast<unsigned>(KAD_ID_BITS))
		return;
	const unsigned byte = level / 8;
	const unsigned mask = 0x80u >> (level % 8);
	if (bit)
		id[byte] = static_cast<unsigned char>(id[byte] | mask);
	else
		id[byte] = static_cast<unsigned char>(id[byte] & ~mask);
}

inline bool KadElapsedAtLeast(uint64_t nowMs, uint64_t thenMs, uint64_t intervalMs)
{
	if (nowMs < thenMs)
		return false;
	return (nowMs - thenMs) >= intervalMs;
}

inline uint32_t KadIpv4Subnet24(uint32_t hostOrderIp)
{
	return hostOrderIp & 0xFFFFFF00u;
}

inline bool KadIpIsLan(uint32_t hostOrderIp)
{
	const uint32_t b1 = hostOrderIp >> 24;
	const uint32_t b2 = (hostOrderIp >> 16) & 0xFFu;
	if (b1 == 10 || b1 == 127)
		return true;
	if (b1 == 172 && b2 >= 16 && b2 <= 31)
		return true;
	if (b1 == 192 && b2 == 168)
		return true;
	if (b1 == 169 && b2 == 254)
		return true;
	return false;
}

inline bool KadEndpointAcceptable(uint32_t hostOrderIp, uint16_t udpPort, bool allowLan)
{
	if (hostOrderIp == 0 || hostOrderIp == 0xFFFFFFFFu)
		return false;
	if (udpPort == 0)
		return false;
	if ((hostOrderIp >> 24) >= 224) // multicast 224-239 and 240-255 reserved/broadcast
		return false;
	if (!allowLan && KadIpIsLan(hostOrderIp))
		return false;
	return true;
}

inline bool KadContactRejectDnsPort(uint8_t version, uint16_t udpPort)
{
	return udpPort == 53 && version < KAD_MIN_VERSION_NO_DNS_PORT;
}

inline void KadContactUpdateType(KadContact& c, uint64_t nowMs)
{
	uint32_t hours = 0;
	if (nowMs >= c.created)
		hours = static_cast<uint32_t>((nowMs - c.created) / KAD_MS_PER_HOUR);
	if (hours == 0)
	{
		c.type = 2;
		c.expires = nowMs + KAD_CONTACT_TYPE2_EXPIRE_MS;
	}
	else if (hours == 1)
	{
		c.type = 1;
		c.expires = nowMs + KAD_CONTACT_TYPE1_EXPIRE_MS;
	}
	else
	{
		c.type = 0;
		c.expires = nowMs + KAD_CONTACT_TYPE0_EXPIRE_MS;
	}
	c.lastTypeSet = nowMs;
	c.lastSeen = nowMs;
}

inline bool KadContactCheckingType(KadContact& c, uint64_t nowMs)
{
	if (c.type >= KAD_CONTACT_TYPE_DEAD)
		return false;
	if (c.lastTypeSet != 0 && !KadElapsedAtLeast(nowMs, c.lastTypeSet, KAD_CONTACT_TYPE_CHECK_MIN_MS))
		return false;
	c.lastTypeSet = nowMs;
	c.expires = nowMs + KAD_CONTACT_CHECKING_EXPIRE_MS;
	if (c.type < KAD_CONTACT_TYPE_DEAD)
		++c.type;
	return true;
}

inline bool KadContactIsDead(const KadContact& c, uint64_t nowMs)
{
	if (c.type != KAD_CONTACT_TYPE_DEAD)
		return false;
	if (c.expires == 0)
		return false;
	return nowMs >= c.expires;
}

inline bool KadContactIsReplaceable(const KadContact& c, uint64_t nowMs)
{
	if (KadContactIsDead(c, nowMs))
		return true;
	if (c.type >= KAD_CONTACT_TYPE_NEW && c.expires != 0 && nowMs >= c.expires)
		return true;
	return false;
}

inline bool KadContactIsHealthyVerified(const KadContact& c, uint64_t nowMs)
{
	if (!c.verified || c.type >= KAD_CONTACT_TYPE_NEW)
		return false;
	if (c.expires != 0 && nowMs >= c.expires)
		return false;
	return true;
}

// Integer value of the first `level` XOR-prefix bits (MSB first). Saturates at UINT32_MAX
// if the value does not fit in 32 bits. Never shifts a uint32 by >= 32 (UB).
inline uint32_t KadPrefixInteger(const KadId& prefix, uint32_t level)
{
	if (level == 0)
		return 0;
	uint32_t got = 0;
	for (uint32_t i = 0; i < level && i < static_cast<uint32_t>(KAD_ID_BITS); ++i)
	{
		const uint32_t remain = level - 1 - i;
		if (KadDistanceBit(prefix, i) == 0)
			continue;
		if (remain >= 32)
			return 0xFFFFFFFFu;
		const uint32_t add = 1u << remain;
		if (got > 0xFFFFFFFFu - add)
			return 0xFFFFFFFFu;
		got += add;
	}
	return got;
}

inline void KadIndexToPrefix(KadId& prefix, uint32_t level, uint32_t zoneIndex)
{
	std::memset(prefix, 0, KAD_ID_SIZE);
	for (uint32_t i = 0; i < level && i < static_cast<uint32_t>(KAD_ID_BITS); ++i)
	{
		const uint32_t remain = level - 1 - i;
		const int bit = (remain < 32) ? static_cast<int>((zoneIndex >> remain) & 1u) : 0;
		KadIdSetBit(prefix, i, bit);
	}
}

// Fill XOR-distance prefix from the zone's 128-bit prefix (top `level` bits) and suffix for the rest.
inline void KadMakeZoneDistance(KadId& distance, uint32_t level, const KadId& prefix, const KadId& suffix)
{
	KadIdCopy(distance, suffix);
	for (uint32_t i = 0; i < level && i < static_cast<uint32_t>(KAD_ID_BITS); ++i)
		KadIdSetBit(distance, i, KadDistanceBit(prefix, i));
}

inline void KadMakeZoneDistance(KadId& distance, uint32_t level, uint32_t zoneIndex, const KadId& suffix)
{
	KadId prefix{};
	KadIndexToPrefix(prefix, level, zoneIndex);
	KadMakeZoneDistance(distance, level, prefix, suffix);
}

inline void KadMakeRefreshTarget(KadId& out, const KadId& localId, uint32_t level, const KadId& prefix, const KadId& suffix)
{
	KadId distance;
	KadMakeZoneDistance(distance, level, prefix, suffix);
	KadIdXor(out, localId, distance);
	if (KadIdEqual(out, localId))
	{
		KadId tweaked;
		KadIdCopy(tweaked, suffix);
		tweaked[KAD_ID_SIZE - 1] = static_cast<unsigned char>(tweaked[KAD_ID_SIZE - 1] ^ 0x01);
		KadMakeZoneDistance(distance, level, prefix, tweaked);
		KadIdXor(out, localId, distance);
	}
}

inline void KadMakeRefreshTarget(KadId& out, const KadId& localId, uint32_t level, uint32_t zoneIndex, const KadId& suffix)
{
	KadId prefix{};
	KadIndexToPrefix(prefix, level, zoneIndex);
	KadMakeRefreshTarget(out, localId, level, prefix, suffix);
}

inline bool KadIdInZone(const KadId& localId, const KadId& contactId, uint32_t level, const KadId& prefix)
{
	KadId distance;
	KadIdXor(distance, localId, contactId);
	for (uint32_t i = 0; i < level && i < static_cast<uint32_t>(KAD_ID_BITS); ++i)
	{
		if (KadDistanceBit(distance, i) != KadDistanceBit(prefix, i))
			return false;
	}
	return true;
}

inline bool KadIdInZone(const KadId& localId, const KadId& contactId, uint32_t level, uint32_t zoneIndex)
{
	KadId prefix{};
	KadIndexToPrefix(prefix, level, zoneIndex);
	return KadIdInZone(localId, contactId, level, prefix);
}

struct KadRoutingBin
{
	std::list<KadContact> contacts;        // front = oldest (LRU)
	std::optional<KadContact> replacement; // cap KAD_REPLACEMENT_CACHE
	uint64_t lastRefresh = 0;
	uint64_t nextSmallTimer = 0;
	uint64_t nextBigTimer = 0;

	bool IsFull() const { return contacts.size() >= static_cast<size_t>(KAD_K); }
	size_t Remaining() const { return contacts.size() >= static_cast<size_t>(KAD_K) ? 0 : (static_cast<size_t>(KAD_K) - contacts.size()); }
};

struct KadRoutingZone
{
	uint32_t level = 0;
	KadId zonePrefix{};
	std::unique_ptr<KadRoutingBin> bin;
	std::unique_ptr<KadRoutingZone> children[2];

	bool IsLeaf() const { return bin != nullptr; }
};

class Kad2RoutingTable
{
public:
	Kad2RoutingTable()
	{
		std::memset(ownId, 0, KAD_ID_SIZE);
		ResetTree();
	}

	bool Initialize(const KadId& nodeId)
	{
		KadIdCopy(ownId, nodeId);
		ResetTree();
		return true;
	}

	bool AddContact(const KadContact& contact)
	{
		KadContactUpdate upd;
		return AddContact(contact, upd);
	}

	bool AddContact(const KadContact& incoming, const KadContactUpdate& upd)
	{
		if (KadIdEqual(incoming.id, ownId) || KadIdIsZero(incoming.id))
			return false;
		if (!KadEndpointAcceptable(incoming.ip, incoming.udpPort, upd.allowLan))
			return false;
		if (KadContactRejectDnsPort(incoming.version, incoming.udpPort))
			return false;

		KadContact candidate = incoming;
		if (candidate.type == 0 && !candidate.verified)
			candidate.type = KAD_CONTACT_TYPE_NEW;
		if (candidate.created == 0)
			candidate.created = upd.nowMs;
		if (upd.markAlive)
			KadContactUpdateType(candidate, upd.nowMs);
		if (upd.markVerified && upd.source == KadContactSource::Observed)
		{
			candidate.verified = true;
			candidate.receivedHello = true;
		}
		else if (upd.source != KadContactSource::Observed)
		{
			// Discovered contacts never enter as live-verified.
			candidate.verified = false;
			candidate.receivedHello = false;
		}

		for (int guard = 0; guard <= KAD_ID_BITS; ++guard)
		{
			KadRoutingZone* leaf = FindLeaf(candidate.id);
			if (!leaf || !leaf->IsLeaf())
				return false;

			KadContact* existing = FindInBin(*leaf->bin, candidate.id);
			if (existing)
				return UpdateExisting(*leaf, *existing, candidate, upd);

			if (FindByEndpoint(candidate.ip, candidate.udpPort, nullptr))
				return false; // different Kad ID, same endpoint (MAX_CONTACTS_IP)

			if (!PassesDiversity(candidate.ip, leaf, upd.allowLan, nullptr))
				return false;

			if (leaf->bin->Remaining() > 0)
			{
				if (GetTotalContacts() >= KAD_MAX_CONTACTS)
					return false;
				PushNew(*leaf->bin, candidate);
				return true;
			}

			if (CanSplit(*leaf))
			{
				if (!Split(*leaf))
					return false;
				continue;
			}

			return ReplaceOrCache(*leaf, candidate, upd);
		}
		return false;
	}

	bool RemoveContact(const KadId& id)
	{
		KadRoutingZone* leaf = FindLeaf(id);
		if (!leaf || !leaf->IsLeaf())
			return false;
		return RemoveFromBin(*leaf->bin, id);
	}

	bool FindContact(const KadId& id, KadContact& out) const
	{
		const KadRoutingZone* leaf = FindLeaf(id);
		if (!leaf || !leaf->IsLeaf())
			return false;
		const KadContact* found = FindInBin(*leaf->bin, id);
		if (!found)
			return false;
		out = *found;
		return true;
	}

	void MarkContactVerified(const KadId& id, uint64_t nowMs)
	{
		KadRoutingZone* leaf = FindLeaf(id);
		if (!leaf || !leaf->IsLeaf())
			return;
		KadContact* found = FindInBin(*leaf->bin, id);
		if (!found)
			return;
		found->verified = true;
		found->receivedHello = true;
		KadContactUpdateType(*found, nowMs);
		PushToBottom(*leaf->bin, id);
	}

	void ObserveAlive(const KadId& id, uint64_t nowMs)
	{
		KadRoutingZone* leaf = FindLeaf(id);
		if (!leaf || !leaf->IsLeaf())
			return;
		KadContact* found = FindInBin(*leaf->bin, id);
		if (!found)
			return;
		KadContactUpdateType(*found, nowMs);
		PushToBottom(*leaf->bin, id);
	}

	// Valid protocol traffic from a known endpoint (FIND_NODE/PONG). Does not set verified.
	bool ObserveAliveByEndpoint(uint32_t ip, uint16_t udpPort, uint64_t nowMs)
	{
		KadContact found;
		if (!FindByEndpoint(ip, udpPort, &found))
			return false;
		ObserveAlive(found.id, nowMs);
		return true;
	}

	void FindClosestContacts(const KadId& targetId, std::vector<KadContact>& results, int maxCount = KAD_K) const
	{
		results.clear();
		if (maxCount <= 0)
			return;

		std::vector<std::pair<std::array<unsigned char, KAD_ID_SIZE>, KadContact>> candidates;
		ForEachContact([&](const KadContact& c)
		               {
			if (c.type >= KAD_CONTACT_TYPE_DEAD)
				return;
			std::array<unsigned char, KAD_ID_SIZE> distance{};
			for (int j = 0; j < KAD_ID_SIZE; ++j)
				distance[static_cast<size_t>(j)] = static_cast<unsigned char>(targetId[j] ^ c.id[j]);
			candidates.emplace_back(distance, c); });

		std::sort(candidates.begin(), candidates.end(),
		          [](const auto& a, const auto& b)
		          {
			          return std::memcmp(a.first.data(), b.first.data(), KAD_ID_SIZE) < 0;
		          });

		for (size_t i = 0; i < candidates.size() && results.size() < static_cast<size_t>(maxCount); ++i)
		{
			bool dup = false;
			for (const auto& existing : results)
			{
				if (KadIdEqual(existing.id, candidates[i].second.id))
				{
					dup = true;
					break;
				}
			}
			if (!dup)
				results.push_back(candidates[i].second);
		}
	}

	size_t GetTotalContacts() const
	{
		size_t total = 0;
		ForEachContact([&](const KadContact&)
		               { ++total; });
		return total;
	}

	size_t GetContactCount() const { return GetTotalContacts(); }

	void GetContactsForBootstrap(std::vector<KadContact>& results, int maxCount = 20) const
	{
		results.clear();
		ForEachContact([&](const KadContact& c)
		               {
			if (static_cast<int>(results.size()) >= maxCount)
				return;
			if (c.type < KAD_CONTACT_TYPE_DEAD)
				results.push_back(c); });
	}

	size_t GetZoneCount() const { return m_zoneCount; }
	size_t GetLeafCount() const
	{
		size_t n = 0;
		ForEachLeaf([&](const KadRoutingZone&)
		            { ++n; });
		return n;
	}

	size_t GetReplacementCount() const
	{
		size_t n = 0;
		ForEachLeaf([&](const KadRoutingZone& z)
		            {
			if (z.bin && z.bin->replacement)
				++n; });
		return n;
	}

	uint32_t GetMaxDepth() const { return MaxDepth(*m_root); }

	void GetLeaves(std::vector<KadLeafInfo>& out) const
	{
		out.clear();
		ForEachLeaf([&](const KadRoutingZone& z)
		            {
			KadLeafInfo info;
			info.level = z.level;
			info.zoneIndex = KadPrefixInteger(z.zonePrefix, z.level);
			info.contacts = z.bin->contacts.size();
			info.replacement = z.bin->replacement ? 1 : 0;
			info.lastRefresh = z.bin->lastRefresh;
			info.nextBigTimer = z.bin->nextBigTimer;
			out.push_back(info); });
	}

	uint32_t CountSubnet(uint32_t hostOrderIp) const
	{
		const uint32_t net = KadIpv4Subnet24(hostOrderIp);
		auto it = m_globalSubnets.find(net);
		return it == m_globalSubnets.end() ? 0 : it->second;
	}

	uint32_t CountIp(uint32_t hostOrderIp) const
	{
		auto it = m_globalIps.find(hostOrderIp);
		return it == m_globalIps.end() ? 0 : it->second;
	}

	void CollectMaintenance(uint64_t nowMs, const KadId& entropy, KadMaintenanceAction& action)
	{
		action = KadMaintenanceAction{};
		bool pingTaken = false;
		bool refreshTaken = false;

		RemoveDeadContacts(nowMs, action, KAD_MAINT_MAX_DEAD_PER_TICK);

		std::vector<KadRoutingZone*> leaves;
		CollectLeaves(leaves);

		for (KadRoutingZone* leaf : leaves)
		{
			if (pingTaken)
				break;
			if (!leaf || !leaf->IsLeaf())
				continue;
			if (leaf->bin->nextSmallTimer != 0 && nowMs < leaf->bin->nextSmallTimer)
				continue;
			leaf->bin->nextSmallTimer = nowMs + KAD_SMALL_TIMER_MS;

			if (leaf->bin->contacts.empty())
				continue;
			for (auto& c : leaf->bin->contacts)
			{
				if (c.expires == 0)
					c.expires = nowMs;
			}
			KadContact& oldest = leaf->bin->contacts.front();
			if (oldest.expires >= nowMs || oldest.type >= KAD_CONTACT_TYPE_DEAD)
			{
				PushToBottom(*leaf->bin, oldest.id);
				continue;
			}
			if (KadContactCheckingType(oldest, nowMs))
			{
				action.ping = true;
				action.pingContact = oldest;
				pingTaken = true;
				PushToBottom(*leaf->bin, oldest.id);
			}
		}

		// aMule StartTimer: arm even when the global refresh gap has not elapsed.
		for (KadRoutingZone* leaf : leaves)
		{
			if (!leaf || !leaf->IsLeaf())
				continue;
			if (leaf->bin->nextBigTimer == 0)
				leaf->bin->nextBigTimer = nowMs + KAD_ZONE_REFRESH_START_MS;
		}

		if (!refreshTaken && KadElapsedAtLeast(nowMs, m_lastGlobalRefresh, KAD_ZONE_REFRESH_MIN_GAP_MS))
		{
			for (KadRoutingZone* leaf : leaves)
			{
				if (!leaf || !leaf->IsLeaf())
					continue;
				if (!BigTimerDue(*leaf, nowMs))
					continue;
				if (!ShouldRandomLookup(*leaf))
					continue;

				KadMakeRefreshTarget(action.refreshTarget, ownId, leaf->level, leaf->zonePrefix, entropy);
				if (!KadIdInZone(ownId, action.refreshTarget, leaf->level, leaf->zonePrefix))
					continue;

				KadContact peer;
				if (!PickRefreshPeer(*leaf, peer))
				{
					std::vector<KadContact> closest;
					FindClosestContacts(action.refreshTarget, closest, 1);
					if (closest.empty())
						continue;
					peer = closest[0];
				}

				action.refresh = true;
				action.refreshPeer = peer;
				leaf->bin->lastRefresh = nowMs;
				leaf->bin->nextBigTimer = nowMs + KAD_ZONE_REFRESH_INTERVAL_MS;
				m_lastGlobalRefresh = nowMs;
				refreshTaken = true;
				break;
			}
		}
	}

	KadId ownId;

private:
	std::unique_ptr<KadRoutingZone> m_root;
	size_t m_zoneCount = 0;
	uint64_t m_lastGlobalRefresh = 0;
	std::map<uint32_t, uint32_t> m_globalIps;
	std::map<uint32_t, uint32_t> m_globalSubnets;

	void ResetTree()
	{
		m_root = std::make_unique<KadRoutingZone>();
		m_root->level = 0;
		std::memset(m_root->zonePrefix, 0, KAD_ID_SIZE);
		m_root->bin = std::make_unique<KadRoutingBin>();
		m_zoneCount = 1;
		m_lastGlobalRefresh = 0;
		m_globalIps.clear();
		m_globalSubnets.clear();
	}

	KadRoutingZone* FindLeaf(const KadId& id)
	{
		return const_cast<KadRoutingZone*>(static_cast<const Kad2RoutingTable*>(this)->FindLeaf(id));
	}

	const KadRoutingZone* FindLeaf(const KadId& id) const
	{
		KadId distance;
		KadIdXor(distance, ownId, id);
		const KadRoutingZone* z = m_root.get();
		unsigned guard = 0;
		while (z && !z->IsLeaf() && guard++ <= KAD_MAX_LEVEL)
		{
			const int bit = KadDistanceBit(distance, z->level);
			z = z->children[bit].get();
		}
		return z;
	}

	static KadContact* FindInBin(KadRoutingBin& bin, const KadId& id)
	{
		for (auto& c : bin.contacts)
		{
			if (KadIdEqual(c.id, id))
				return &c;
		}
		return nullptr;
	}

	static const KadContact* FindInBin(const KadRoutingBin& bin, const KadId& id)
	{
		for (const auto& c : bin.contacts)
		{
			if (KadIdEqual(c.id, id))
				return &c;
		}
		return nullptr;
	}

	bool FindByEndpoint(uint32_t ip, uint16_t udpPort, KadContact* out) const
	{
		bool found = false;
		ForEachContact([&](const KadContact& c)
		               {
			if (found)
				return;
			if (c.ip == ip && c.udpPort == udpPort)
			{
				if (out)
					*out = c;
				found = true;
			} });
		return found;
	}

	bool CanSplit(const KadRoutingZone& zone) const
	{
		if (!zone.IsLeaf())
			return false;
		if (zone.level >= KAD_MAX_LEVEL)
			return false;
		if (m_zoneCount + 2 > KAD_MAX_ZONES)
			return false;
		if (zone.bin->contacts.size() != static_cast<size_t>(KAD_K))
			return false;
		return (KadPrefixInteger(zone.zonePrefix, zone.level) < KAD_KK || zone.level < KAD_KBASE);
	}

	bool Split(KadRoutingZone& zone)
	{
		if (!CanSplit(zone))
			return false;

		auto left = std::make_unique<KadRoutingZone>();
		auto right = std::make_unique<KadRoutingZone>();
		left->level = zone.level + 1;
		right->level = zone.level + 1;
		KadIdCopy(left->zonePrefix, zone.zonePrefix);
		KadIdCopy(right->zonePrefix, zone.zonePrefix);
		KadIdSetBit(left->zonePrefix, zone.level, 0);
		KadIdSetBit(right->zonePrefix, zone.level, 1);
		left->bin = std::make_unique<KadRoutingBin>();
		right->bin = std::make_unique<KadRoutingBin>();
		left->bin->lastRefresh = zone.bin->lastRefresh;
		right->bin->lastRefresh = zone.bin->lastRefresh;
		left->bin->nextBigTimer = zone.bin->nextBigTimer;
		right->bin->nextBigTimer = zone.bin->nextBigTimer;
		left->bin->nextSmallTimer = zone.bin->nextSmallTimer;
		right->bin->nextSmallTimer = zone.bin->nextSmallTimer;

		KadId distance;
		for (const auto& c : zone.bin->contacts)
		{
			KadIdXor(distance, ownId, c.id);
			const int bit = KadDistanceBit(distance, zone.level);
			KadRoutingBin& dest = bit ? *right->bin : *left->bin;
			if (dest.contacts.size() < static_cast<size_t>(KAD_K))
				dest.contacts.push_back(c);
			else
			{
				Untrack(c);
				if (!dest.replacement)
					dest.replacement = c;
			}
		}
		if (zone.bin->replacement)
		{
			KadIdXor(distance, ownId, zone.bin->replacement->id);
			const int bit = KadDistanceBit(distance, zone.level);
			KadRoutingBin& dest = bit ? *right->bin : *left->bin;
			if (dest.contacts.size() < static_cast<size_t>(KAD_K))
			{
				dest.contacts.push_back(*zone.bin->replacement);
				Track(zone.bin->replacement->ip);
			}
			else if (!dest.replacement)
				dest.replacement = *zone.bin->replacement;
		}

		zone.bin.reset();
		zone.children[0] = std::move(left);
		zone.children[1] = std::move(right);
		m_zoneCount += 2;
		return true;
	}

	bool PassesDiversity(uint32_t ip, const KadRoutingZone* leaf, bool allowLan, const KadContact* ignore) const
	{
		const bool lan = allowLan && KadIpIsLan(ip);
		uint32_t sameIp = CountIp(ip);
		if (ignore && ignore->ip == ip && sameIp > 0)
			--sameIp;
		if (sameIp >= KAD_MAX_CONTACTS_PER_IP)
			return false;

		const uint32_t net = KadIpv4Subnet24(ip);
		uint32_t sameNet = CountSubnet(ip);
		if (ignore && KadIpv4Subnet24(ignore->ip) == net && sameNet > 0)
			--sameNet;
		if (!lan && sameNet >= KAD_MAX_CONTACTS_SUBNET_GLOBAL)
			return false;

		if (leaf && leaf->IsLeaf() && !lan)
		{
			unsigned binNet = 0;
			for (const auto& c : leaf->bin->contacts)
			{
				if (ignore && KadIdEqual(c.id, ignore->id))
					continue;
				if (KadIpv4Subnet24(c.ip) == net)
					++binNet;
			}
			if (binNet >= KAD_MAX_CONTACTS_SUBNET_BIN)
				return false;
		}
		return true;
	}

	void Track(uint32_t ip)
	{
		m_globalIps[ip] += 1;
		m_globalSubnets[KadIpv4Subnet24(ip)] += 1;
	}

	void Untrack(uint32_t ip)
	{
		auto ipIt = m_globalIps.find(ip);
		if (ipIt != m_globalIps.end())
		{
			if (ipIt->second <= 1)
				m_globalIps.erase(ipIt);
			else
				--ipIt->second;
		}
		const uint32_t net = KadIpv4Subnet24(ip);
		auto netIt = m_globalSubnets.find(net);
		if (netIt != m_globalSubnets.end())
		{
			if (netIt->second <= 1)
				m_globalSubnets.erase(netIt);
			else
				--netIt->second;
		}
	}

	void Untrack(const KadContact& c)
	{
		Untrack(c.ip);
	}

	void PushNew(KadRoutingBin& bin, const KadContact& c)
	{
		bin.contacts.push_back(c);
		Track(c.ip);
	}

	bool RemoveFromBin(KadRoutingBin& bin, const KadId& id)
	{
		for (auto it = bin.contacts.begin(); it != bin.contacts.end(); ++it)
		{
			if (KadIdEqual(it->id, id))
			{
				Untrack(*it);
				bin.contacts.erase(it);
				if (bin.replacement)
				{
					KadContact cached = *bin.replacement;
					bin.replacement.reset();
					if (bin.contacts.size() < static_cast<size_t>(KAD_K))
						PushNew(bin, cached);
				}
				return true;
			}
		}
		if (bin.replacement && KadIdEqual(bin.replacement->id, id))
		{
			bin.replacement.reset();
			return true;
		}
		return false;
	}

	static void PushToBottom(KadRoutingBin& bin, const KadId& id)
	{
		for (auto it = bin.contacts.begin(); it != bin.contacts.end(); ++it)
		{
			if (KadIdEqual(it->id, id))
			{
				KadContact c = *it;
				bin.contacts.erase(it);
				bin.contacts.push_back(c);
				return;
			}
		}
	}

	bool UpdateExisting(KadRoutingZone& leaf, KadContact& existing, const KadContact& candidate, const KadContactUpdate& upd)
	{
		const bool sameEndpoint = existing.ip == candidate.ip && existing.udpPort == candidate.udpPort;
		if (!sameEndpoint)
		{
			if (existing.verified && upd.source != KadContactSource::Observed)
				return false;
			if (!PassesDiversity(candidate.ip, &leaf, upd.allowLan, &existing))
				return false;
			Untrack(existing.ip);
			existing.ip = candidate.ip;
			existing.udpPort = candidate.udpPort;
			existing.tcpPort = candidate.tcpPort;
			existing.verified = false;
			Track(existing.ip);
		}
		if (candidate.version >= existing.version)
			existing.version = candidate.version;
		if (candidate.tcpPort)
			existing.tcpPort = candidate.tcpPort;
		if (upd.markAlive || upd.source == KadContactSource::Observed)
			KadContactUpdateType(existing, upd.nowMs);
		else
			existing.lastSeen = upd.nowMs != 0 ? upd.nowMs : existing.lastSeen;
		if (upd.markVerified && upd.source == KadContactSource::Observed)
		{
			existing.verified = true;
			existing.receivedHello = true;
		}
		PushToBottom(*leaf.bin, existing.id);
		return true;
	}

	bool ReplaceOrCache(KadRoutingZone& leaf, const KadContact& candidate, const KadContactUpdate& upd)
	{
		if (leaf.bin->contacts.empty())
			return false;

		KadContact& oldest = leaf.bin->contacts.front();
		const bool candidateUnverified = !candidate.verified && upd.source != KadContactSource::Observed;
		if (KadContactIsHealthyVerified(oldest, upd.nowMs) && candidateUnverified)
		{
			CacheReplacement(*leaf.bin, candidate);
			return false;
		}

		if (KadContactIsReplaceable(oldest, upd.nowMs) || (!oldest.verified && candidate.verified))
		{
			if (!PassesDiversity(candidate.ip, &leaf, upd.allowLan, &oldest))
			{
				CacheReplacement(*leaf.bin, candidate);
				return false;
			}
			Untrack(oldest);
			oldest = candidate;
			Track(oldest.ip);
			PushToBottom(*leaf.bin, oldest.id);
			return true;
		}

		CacheReplacement(*leaf.bin, candidate);
		return false;
	}

	static void CacheReplacement(KadRoutingBin& bin, const KadContact& candidate)
	{
		if (!bin.replacement)
		{
			bin.replacement = candidate;
			return;
		}
		const bool better = (candidate.verified && !bin.replacement->verified) ||
		                    (candidate.verified == bin.replacement->verified && candidate.lastSeen >= bin.replacement->lastSeen);
		if (better)
			bin.replacement = candidate;
	}

	bool BigTimerDue(const KadRoutingZone& zone, uint64_t nowMs) const
	{
		if (zone.bin->nextBigTimer == 0)
			return false;
		return nowMs >= zone.bin->nextBigTimer;
	}

	static bool ShouldRandomLookup(const KadRoutingZone& zone)
	{
		if (KadPrefixInteger(zone.zonePrefix, zone.level) < KAD_KK || zone.level < KAD_KBASE)
			return true;
		return zone.bin->Remaining() >= static_cast<size_t>(KAD_K * 4 / 5);
	}

	static bool PickRefreshPeer(const KadRoutingZone& zone, KadContact& out)
	{
		for (const auto& c : zone.bin->contacts)
		{
			if (c.type < KAD_CONTACT_TYPE_DEAD && c.udpPort != 0)
			{
				out = c;
				return true;
			}
		}
		return false;
	}

	void RemoveDeadContacts(uint64_t nowMs, KadMaintenanceAction& action, size_t budget)
	{
		std::vector<KadRoutingZone*> leaves;
		CollectLeaves(leaves);
		for (KadRoutingZone* leaf : leaves)
		{
			if (budget == 0)
				return;
			if (!leaf || !leaf->IsLeaf())
				continue;
			auto it = leaf->bin->contacts.begin();
			while (it != leaf->bin->contacts.end() && budget > 0)
			{
				if (KadContactIsDead(*it, nowMs))
				{
					Untrack(*it);
					it = leaf->bin->contacts.erase(it);
					++action.deadRemoved;
					--budget;
					if (leaf->bin->replacement && leaf->bin->contacts.size() < static_cast<size_t>(KAD_K))
					{
						KadContact cached = *leaf->bin->replacement;
						leaf->bin->replacement.reset();
						if (PassesDiversity(cached.ip, leaf, KadIpIsLan(cached.ip), nullptr))
							PushNew(*leaf->bin, cached);
					}
					continue;
				}
				++it;
			}
		}
	}

	template<typename Fn>
	void ForEachLeaf(Fn&& fn) const
	{
		std::vector<const KadRoutingZone*> stack;
		stack.push_back(m_root.get());
		while (!stack.empty())
		{
			const KadRoutingZone* z = stack.back();
			stack.pop_back();
			if (!z)
				continue;
			if (z->IsLeaf())
			{
				fn(*z);
				continue;
			}
			stack.push_back(z->children[1].get());
			stack.push_back(z->children[0].get());
		}
	}

	template<typename Fn>
	void ForEachContact(Fn&& fn) const
	{
		ForEachLeaf([&](const KadRoutingZone& z)
		            {
			for (const auto& c : z.bin->contacts)
				fn(c); });
	}

	void CollectLeaves(std::vector<KadRoutingZone*>& out)
	{
		out.clear();
		std::vector<KadRoutingZone*> stack;
		stack.push_back(m_root.get());
		while (!stack.empty())
		{
			KadRoutingZone* z = stack.back();
			stack.pop_back();
			if (!z)
				continue;
			if (z->IsLeaf())
			{
				out.push_back(z);
				continue;
			}
			stack.push_back(z->children[1].get());
			stack.push_back(z->children[0].get());
		}
	}

	static uint32_t MaxDepth(const KadRoutingZone& z)
	{
		if (z.IsLeaf())
			return 0;
		uint32_t a = z.children[0] ? MaxDepth(*z.children[0]) : 0;
		uint32_t b = z.children[1] ? MaxDepth(*z.children[1]) : 0;
		return 1 + (a > b ? a : b);
	}
};
