//
// test_kad_routing_table.cpp
//
// Deterministic Kad2 routing-table tests (#86): XOR distance, zone split,
// LRU/replacement, refresh scheduling, /24 diversity, adversarial bounds.
// No MFC, no sleeps, injected timestamps only.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/KadRoutingTable.h"

#include <cstring>
#include <vector>

static void ZeroId(KadId& id)
{
	std::memset(id, 0, KAD_ID_SIZE);
}

static void FillId(KadId& id, unsigned char value)
{
	std::memset(id, value, KAD_ID_SIZE);
}

static void IdWithBit(KadId& id, unsigned bit)
{
	ZeroId(id);
	KadIdSetBit(id, bit, 1);
}

static uint32_t Ip88(unsigned third, unsigned fourth)
{
	return 0x08080000u | ((third & 0xFFu) << 8) | (fourth & 0xFFu);
}

static KadContact MakeContact(const KadId& id, uint32_t ip, uint16_t port = 4662)
{
	KadContact c(id, ip, port, port);
	c.version = 8;
	return c;
}

static KadContactUpdate AsCandidate(uint64_t nowMs)
{
	KadContactUpdate u;
	u.source = KadContactSource::Candidate;
	u.nowMs = nowMs;
	return u;
}

static KadContactUpdate AsVerified(uint64_t nowMs)
{
	KadContactUpdate u;
	u.source = KadContactSource::Observed;
	u.markVerified = true;
	u.markAlive = true;
	u.nowMs = nowMs;
	return u;
}

static Kad2RoutingTable TableWithLocalZero()
{
	Kad2RoutingTable table;
	KadId local;
	ZeroId(local);
	table.Initialize(local);
	return table;
}

static bool InsertN(Kad2RoutingTable& table, int n, unsigned idByte, uint64_t nowMs, bool verified)
{
	for (int i = 0; i < n; ++i)
	{
		KadId id;
		ZeroId(id);
		id[0] = static_cast<unsigned char>(idByte);
		id[15] = static_cast<unsigned char>(i + 1);
		KadContact c = MakeContact(id, Ip88(static_cast<unsigned>(i + 1), 1));
		if (verified)
		{
			if (!table.AddContact(c, AsVerified(nowMs)))
				return false;
		}
		else if (!table.AddContact(c, AsCandidate(nowMs)))
			return false;
	}
	return true;
}

static bool test_xor_identical_zero()
{
	KadId a, b, d;
	FillId(a, 0xAB);
	FillId(b, 0xAB);
	KadIdXor(d, a, b);
	return KadIdIsZero(d) && KadIdCompare(a, b) == 0;
}

static bool test_xor_one_bit()
{
	KadId a, b, d;
	ZeroId(a);
	ZeroId(b);
	b[15] = 0x01;
	KadIdXor(d, a, b);
	return d[15] == 0x01 && KadDistanceBit(d, 127) == 1 && KadDistanceBit(d, 0) == 0;
}

static bool test_xor_highest_bit()
{
	KadId a, b, d;
	ZeroId(a);
	ZeroId(b);
	b[0] = 0x80;
	KadIdXor(d, a, b);
	return KadDistanceBit(d, 0) == 1 && KadDistanceBit(d, 1) == 0;
}

static bool test_xor_lowest_bit()
{
	KadId a;
	ZeroId(a);
	KadId b;
	IdWithBit(b, 127);
	KadId d;
	KadIdXor(d, a, b);
	return KadDistanceBit(d, 127) == 1 && d[15] == 0x01;
}

static bool test_xor_ordering_crafted()
{
	KadId target;
	ZeroId(target);
	KadId near, far;
	ZeroId(near);
	near[15] = 0x01;
	ZeroId(far);
	far[0] = 0x80;
	KadId dn, df;
	KadIdXor(dn, target, near);
	KadIdXor(df, target, far);
	return KadIdCompare(dn, df) < 0;
}

static bool test_closest_contact_order()
{
	Kad2RoutingTable table = TableWithLocalZero();
	KadId a, b, c;
	ZeroId(a);
	a[15] = 0x01;
	ZeroId(b);
	b[15] = 0x03;
	ZeroId(c);
	c[0] = 0x80;
	if (!table.AddContact(MakeContact(c, Ip88(1, 1)), AsCandidate(1)))
		return false;
	if (!table.AddContact(MakeContact(b, Ip88(2, 1)), AsCandidate(1)))
		return false;
	if (!table.AddContact(MakeContact(a, Ip88(3, 1)), AsCandidate(1)))
		return false;

	KadId target;
	ZeroId(target);
	std::vector<KadContact> closest;
	table.FindClosestContacts(target, closest, 3);
	if (closest.size() != 3)
		return false;
	return KadIdEqual(closest[0].id, a) && KadIdEqual(closest[1].id, b) && KadIdEqual(closest[2].id, c);
}

static bool test_insert_non_full()
{
	Kad2RoutingTable table = TableWithLocalZero();
	KadId id;
	ZeroId(id);
	id[15] = 1;
	return table.AddContact(MakeContact(id, Ip88(1, 1)), AsCandidate(1)) && table.GetTotalContacts() == 1 && table.GetLeafCount() == 1;
}

static bool test_fill_exactly_k()
{
	Kad2RoutingTable table = TableWithLocalZero();
	if (!InsertN(table, KAD_K, 0x10, 1, false))
		return false;
	return table.GetTotalContacts() == static_cast<size_t>(KAD_K) && table.GetLeafCount() == 1;
}

static bool test_k_plus_one_splits()
{
	Kad2RoutingTable table = TableWithLocalZero();
	if (!InsertN(table, KAD_K, 0x10, 1, false))
		return false;
	KadId extra;
	ZeroId(extra);
	extra[0] = 0x80;
	extra[15] = 0x22;
	if (!table.AddContact(MakeContact(extra, Ip88(20, 1)), AsCandidate(1)))
		return false;
	return table.GetTotalContacts() == static_cast<size_t>(KAD_K) + 1 && table.GetLeafCount() == 2 && table.GetMaxDepth() >= 1;
}

static bool test_split_redistribute_and_boundary()
{
	Kad2RoutingTable table = TableWithLocalZero();
	if (!InsertN(table, KAD_K, 0x10, 1, false))
		return false;
	const size_t before = table.GetTotalContacts();
	KadId extra;
	ZeroId(extra);
	extra[0] = 0x80;
	if (!table.AddContact(MakeContact(extra, Ip88(30, 1)), AsCandidate(1)))
		return false;
	if (table.GetTotalContacts() != before + 1)
		return false;

	std::vector<KadLeafInfo> leaves;
	table.GetLeaves(leaves);
	if (leaves.size() != 2)
		return false;
	bool sawClose = false, sawFar = false;
	for (const auto& leaf : leaves)
	{
		if (leaf.level == 1 && leaf.zoneIndex == 0)
			sawClose = leaf.contacts == static_cast<size_t>(KAD_K);
		if (leaf.level == 1 && leaf.zoneIndex == 1)
			sawFar = leaf.contacts == 1;
	}
	return sawClose && sawFar;
}

static bool test_local_id_never_inserted()
{
	Kad2RoutingTable table = TableWithLocalZero();
	KadId local;
	ZeroId(local);
	return !table.AddContact(MakeContact(local, Ip88(1, 1)), AsCandidate(1)) && table.GetTotalContacts() == 0;
}

static bool test_zero_id_rejected()
{
	Kad2RoutingTable table;
	KadId local;
	FillId(local, 0x11);
	table.Initialize(local);
	KadId zero;
	ZeroId(zero);
	return !table.AddContact(MakeContact(zero, Ip88(1, 1)), AsCandidate(1));
}

static bool FillUnsplittableFar(Kad2RoutingTable& table, uint64_t nowMs, bool verified)
{
	for (int i = 0; i < KAD_K; ++i)
	{
		KadId id;
		ZeroId(id);
		id[0] = static_cast<unsigned char>(0xE0 + i);
		KadContact c = MakeContact(id, Ip88(static_cast<unsigned>(40 + i), 1));
		if (verified)
		{
			if (!table.AddContact(c, AsVerified(nowMs)))
				return false;
		}
		else if (!table.AddContact(c, AsCandidate(nowMs)))
			return false;
	}
	return true;
}

static bool test_unsplittable_full_uses_replacement()
{
	Kad2RoutingTable table = TableWithLocalZero();
	if (!FillUnsplittableFar(table, 1, false))
		return false;
	const uint32_t depth = table.GetMaxDepth();
	KadId extra;
	ZeroId(extra);
	extra[0] = 0xEA;
	const bool added = table.AddContact(MakeContact(extra, Ip88(90, 1)), AsCandidate(2));
	std::vector<KadLeafInfo> leaves;
	table.GetLeaves(leaves);
	bool unsplittableFull = false;
	for (const auto& leaf : leaves)
	{
		if (leaf.level >= KAD_KBASE && leaf.zoneIndex >= KAD_KK && leaf.contacts == static_cast<size_t>(KAD_K))
			unsplittableFull = true;
	}
	return unsplittableFull && depth <= KAD_MAX_LEVEL && (added || table.GetReplacementCount() == 1);
}

static bool test_verified_not_evicted_by_unverified()
{
	Kad2RoutingTable table = TableWithLocalZero();
	if (!FillUnsplittableFar(table, 1, true))
		return false;
	const size_t before = table.GetTotalContacts();
	KadId extra;
	ZeroId(extra);
	extra[0] = 0xEA;
	table.AddContact(MakeContact(extra, Ip88(90, 1)), AsCandidate(2));
	KadContact found;
	ZeroId(extra);
	extra[0] = 0xE0;
	if (!table.FindContact(extra, found) || !found.verified)
		return false;
	return table.GetTotalContacts() == before && table.GetReplacementCount() <= KAD_REPLACEMENT_CACHE;
}

static bool test_stale_replaced()
{
	Kad2RoutingTable table = TableWithLocalZero();
	for (int i = 0; i < KAD_K; ++i)
	{
		KadId id;
		ZeroId(id);
		id[0] = static_cast<unsigned char>(0xE0 + i);
		KadContact c = MakeContact(id, Ip88(static_cast<unsigned>(40 + i), 1));
		c.type = KAD_CONTACT_TYPE_DEAD;
		c.expires = 1;
		if (!table.AddContact(c, AsCandidate(10)))
			return false;
	}
	KadId extra;
	ZeroId(extra);
	extra[0] = 0xEA;
	KadContact neu = MakeContact(extra, Ip88(90, 1));
	if (!table.AddContact(neu, AsVerified(20)))
		return false;
	KadContact found;
	return table.FindContact(extra, found) && KadIdEqual(found.id, extra);
}

static bool test_duplicate_id_updates()
{
	Kad2RoutingTable table = TableWithLocalZero();
	KadId id;
	ZeroId(id);
	id[15] = 9;
	KadContact c = MakeContact(id, Ip88(1, 1));
	if (!table.AddContact(c, AsCandidate(1)))
		return false;
	c.tcpPort = 5000;
	c.version = 8;
	if (!table.AddContact(c, AsCandidate(5)))
		return false;
	KadContact found;
	if (!table.FindContact(id, found))
		return false;
	return table.GetTotalContacts() == 1 && found.tcpPort == 5000 && found.version == 8;
}

static bool test_same_id_different_endpoint_verified_wins()
{
	Kad2RoutingTable table = TableWithLocalZero();
	KadId id;
	ZeroId(id);
	id[15] = 4;
	KadContact first = MakeContact(id, Ip88(1, 1), 4662);
	if (!table.AddContact(first, AsVerified(1)))
		return false;
	KadContact hijack = MakeContact(id, Ip88(2, 1), 4662);
	table.AddContact(hijack, AsCandidate(2));
	KadContact found;
	if (!table.FindContact(id, found))
		return false;
	return found.ip == first.ip && table.GetTotalContacts() == 1;
}

static bool test_different_id_same_endpoint_rejected()
{
	Kad2RoutingTable table = TableWithLocalZero();
	KadId a, b;
	ZeroId(a);
	a[15] = 1;
	ZeroId(b);
	b[15] = 2;
	if (!table.AddContact(MakeContact(a, Ip88(1, 1), 4662), AsCandidate(1)))
		return false;
	return !table.AddContact(MakeContact(b, Ip88(1, 1), 4662), AsCandidate(1)) && table.GetTotalContacts() == 1;
}

static bool test_lru_observe_moves_to_bottom()
{
	Kad2RoutingTable table = TableWithLocalZero();
	KadId firstId;
	ZeroId(firstId);
	firstId[15] = 1;
	if (!table.AddContact(MakeContact(firstId, Ip88(1, 1)), AsVerified(1)))
		return false;
	KadId second;
	ZeroId(second);
	second[15] = 2;
	if (!table.AddContact(MakeContact(second, Ip88(2, 1)), AsVerified(2)))
		return false;
	table.ObserveAlive(firstId, 50);
	KadContact found;
	return table.FindContact(firstId, found) && found.lastSeen == 50 && found.verified;
}

static bool test_observe_alive_by_endpoint()
{
	Kad2RoutingTable table = TableWithLocalZero();
	KadId id;
	ZeroId(id);
	id[15] = 1;
	const uint32_t ip = Ip88(1, 1);
	if (!table.AddContact(MakeContact(id, ip, 4662), AsCandidate(1)))
		return false;
	if (!table.ObserveAliveByEndpoint(ip, 4662, 77))
		return false;
	if (table.ObserveAliveByEndpoint(Ip88(9, 9), 4662, 88))
		return false;
	KadContact found;
	if (!table.FindContact(id, found))
		return false;
	return found.lastSeen == 77 && !found.verified;
}

static bool test_refresh_fresh_leaf_skipped()
{
	Kad2RoutingTable table = TableWithLocalZero();
	KadId id;
	ZeroId(id);
	id[15] = 1;
	if (!table.AddContact(MakeContact(id, Ip88(1, 1)), AsCandidate(1)))
		return false;
	KadId entropy;
	ZeroId(entropy);
	KadMaintenanceAction action;
	table.CollectMaintenance(1000, entropy, action);
	return !action.refresh;
}

static bool test_refresh_stale_leaf_target_in_zone()
{
	Kad2RoutingTable table = TableWithLocalZero();
	KadId id;
	ZeroId(id);
	id[15] = 1;
	if (!table.AddContact(MakeContact(id, Ip88(1, 1)), AsCandidate(1)))
		return false;
	KadId entropy;
	FillId(entropy, 0x3C);
	KadMaintenanceAction action;
	table.CollectMaintenance(KAD_ZONE_REFRESH_INTERVAL_MS, entropy, action);
	if (!action.refresh)
		return false;
	KadId local;
	ZeroId(local);
	return KadIdInZone(local, action.refreshTarget, 0, 0) && !KadIdEqual(action.refreshTarget, local);
}

static bool test_refresh_timestamp_and_bound()
{
	Kad2RoutingTable table = TableWithLocalZero();
	if (!InsertN(table, 3, 0x20, 1, false))
		return false;
	KadId entropy;
	ZeroId(entropy);
	KadMaintenanceAction first;
	table.CollectMaintenance(KAD_ZONE_REFRESH_INTERVAL_MS, entropy, first);
	if (!first.refresh)
		return false;
	std::vector<KadLeafInfo> leaves;
	table.GetLeaves(leaves);
	if (leaves.empty() || leaves[0].lastRefresh != KAD_ZONE_REFRESH_INTERVAL_MS)
		return false;
	KadMaintenanceAction second;
	table.CollectMaintenance(KAD_ZONE_REFRESH_INTERVAL_MS + 1000, entropy, second);
	return !second.refresh;
}

static bool test_refresh_second_zone_later()
{
	Kad2RoutingTable table = TableWithLocalZero();
	if (!InsertN(table, KAD_K, 0x10, 1, false))
		return false;
	KadId extra;
	ZeroId(extra);
	extra[0] = 0x80;
	if (!table.AddContact(MakeContact(extra, Ip88(20, 1)), AsCandidate(1)))
		return false;
	KadId entropy;
	ZeroId(entropy);
	KadMaintenanceAction a;
	table.CollectMaintenance(KAD_ZONE_REFRESH_INTERVAL_MS, entropy, a);
	KadMaintenanceAction b;
	table.CollectMaintenance(KAD_ZONE_REFRESH_INTERVAL_MS + KAD_ZONE_REFRESH_MIN_GAP_MS, entropy, b);
	return a.refresh && b.refresh;
}

static bool test_subnet_two_ok_third_rejected()
{
	Kad2RoutingTable table = TableWithLocalZero();
	KadId a, b, c;
	ZeroId(a);
	a[15] = 1;
	ZeroId(b);
	b[15] = 2;
	ZeroId(c);
	c[15] = 3;
	const uint32_t net = Ip88(5, 1);
	if (!table.AddContact(MakeContact(a, net), AsCandidate(1)))
		return false;
	if (!table.AddContact(MakeContact(b, Ip88(5, 2)), AsCandidate(1)))
		return false;
	if (table.AddContact(MakeContact(c, Ip88(5, 3)), AsCandidate(1)))
		return false;
	return table.GetTotalContacts() == 2 && table.CountSubnet(net) == 2;
}

static bool test_subnet_other_slash24_accepted()
{
	Kad2RoutingTable table = TableWithLocalZero();
	KadId a, b;
	ZeroId(a);
	a[15] = 1;
	ZeroId(b);
	b[15] = 2;
	if (!table.AddContact(MakeContact(a, Ip88(5, 1)), AsCandidate(1)))
		return false;
	return table.AddContact(MakeContact(b, Ip88(6, 1)), AsCandidate(1)) && table.GetTotalContacts() == 2;
}

static bool test_subnet_duplicate_id_does_not_inflate()
{
	Kad2RoutingTable table = TableWithLocalZero();
	KadId id;
	ZeroId(id);
	id[15] = 1;
	const uint32_t ip = Ip88(7, 1);
	if (!table.AddContact(MakeContact(id, ip), AsCandidate(1)))
		return false;
	if (!table.AddContact(MakeContact(id, ip), AsCandidate(2)))
		return false;
	return table.GetTotalContacts() == 1 && table.CountSubnet(ip) == 1;
}

static bool test_subnet_remove_decrements()
{
	Kad2RoutingTable table = TableWithLocalZero();
	KadId id;
	ZeroId(id);
	id[15] = 1;
	const uint32_t ip = Ip88(8, 1);
	if (!table.AddContact(MakeContact(id, ip), AsCandidate(1)))
		return false;
	if (!table.RemoveContact(id))
		return false;
	return table.CountSubnet(ip) == 0 && table.GetTotalContacts() == 0;
}

static bool test_subnet_byte_order()
{
	const uint32_t a = 0x08080808u; // 8.8.8.8 host-order (first octet high)
	const uint32_t b = 0x08080801u;
	const uint32_t c = 0x08080901u;
	return KadIpv4Subnet24(a) == KadIpv4Subnet24(b) && KadIpv4Subnet24(a) != KadIpv4Subnet24(c) && KadIpv4Subnet24(a) == 0x08080800u;
}

static bool test_lan_exception()
{
	Kad2RoutingTable table = TableWithLocalZero();
	KadContactUpdate lan = AsCandidate(1);
	lan.allowLan = true;
	for (int i = 0; i < 3; ++i)
	{
		KadId id;
		ZeroId(id);
		id[15] = static_cast<unsigned char>(i + 1);
		KadContact c = MakeContact(id, 0x0A000001u + static_cast<uint32_t>(i)); // 10.0.0.x
		if (!table.AddContact(c, lan))
			return false;
	}
	return table.GetTotalContacts() == 3;
}

static bool test_endpoint_rejects()
{
	Kad2RoutingTable table = TableWithLocalZero();
	KadId id;
	ZeroId(id);
	id[15] = 1;
	if (table.AddContact(MakeContact(id, 0), AsCandidate(1)))
		return false;
	if (table.AddContact(MakeContact(id, 0xE0000001u), AsCandidate(1))) // 224.0.0.1 multicast
		return false;
	KadContact c = MakeContact(id, Ip88(1, 1), 0);
	if (table.AddContact(c, AsCandidate(1)))
		return false;
	return true;
}

static bool test_adversarial_one_slash24()
{
	Kad2RoutingTable table = TableWithLocalZero();
	int accepted = 0;
	for (int i = 0; i < 200; ++i)
	{
		KadId id;
		ZeroId(id);
		id[14] = static_cast<unsigned char>(i >> 8);
		id[15] = static_cast<unsigned char>(i);
		if (table.AddContact(MakeContact(id, Ip88(9, static_cast<unsigned>(i + 1))), AsCandidate(1)))
			++accepted;
	}
	return accepted <= static_cast<int>(KAD_MAX_CONTACTS_SUBNET_GLOBAL) && table.GetTotalContacts() <= KAD_MAX_CONTACTS && table.GetZoneCount() <= KAD_MAX_ZONES;
}

static bool test_adversarial_max_depth()
{
	Kad2RoutingTable table = TableWithLocalZero();
	for (int i = 0; i < 40; ++i)
	{
		KadId id;
		ZeroId(id);
		id[15] = static_cast<unsigned char>(i + 1);
		table.AddContact(MakeContact(id, Ip88(static_cast<unsigned>(i + 1), 1)), AsCandidate(1));
	}
	return table.GetMaxDepth() <= KAD_MAX_LEVEL && table.GetZoneCount() <= KAD_MAX_ZONES && table.GetTotalContacts() <= KAD_MAX_CONTACTS;
}

static bool test_reinsert_after_remove()
{
	Kad2RoutingTable table = TableWithLocalZero();
	KadId id;
	ZeroId(id);
	id[15] = 7;
	KadContact c = MakeContact(id, Ip88(1, 1));
	if (!table.AddContact(c, AsCandidate(1)))
		return false;
	if (!table.RemoveContact(id))
		return false;
	return table.AddContact(c, AsCandidate(2)) && table.GetTotalContacts() == 1;
}

static bool test_replacement_bounded()
{
	Kad2RoutingTable table = TableWithLocalZero();
	if (!FillUnsplittableFar(table, 1, true))
		return false;
	for (int i = 0; i < 30; ++i)
	{
		KadId id;
		ZeroId(id);
		id[0] = 0xEA;
		id[15] = static_cast<unsigned char>(i + 1);
		table.AddContact(MakeContact(id, Ip88(static_cast<unsigned>(100 + i), 1)), AsCandidate(static_cast<uint64_t>(i + 2)));
	}
	return table.GetReplacementCount() <= table.GetLeafCount() && table.GetTotalContacts() <= KAD_MAX_CONTACTS;
}

static bool test_verified_event_is_hello_res()
{
	Kad2RoutingTable table = TableWithLocalZero();
	KadId id;
	ZeroId(id);
	id[15] = 1;
	KadContact c = MakeContact(id, Ip88(1, 1));
	c.verified = true;
	if (!table.AddContact(c, AsCandidate(1)))
		return false;
	KadContact found;
	if (!table.FindContact(id, found) || found.verified)
		return false;
	table.MarkContactVerified(id, 9);
	return table.FindContact(id, found) && found.verified && found.receivedHello;
}

void register_kad_routing_table_tests(TestSuite& suite)
{
	suite.add_test("kad_xor_identical_zero", test_xor_identical_zero);
	suite.add_test("kad_xor_one_bit", test_xor_one_bit);
	suite.add_test("kad_xor_highest_bit", test_xor_highest_bit);
	suite.add_test("kad_xor_lowest_bit", test_xor_lowest_bit);
	suite.add_test("kad_xor_ordering_crafted", test_xor_ordering_crafted);
	suite.add_test("kad_closest_contact_order", test_closest_contact_order);
	suite.add_test("kad_insert_non_full", test_insert_non_full);
	suite.add_test("kad_fill_exactly_k", test_fill_exactly_k);
	suite.add_test("kad_k_plus_one_splits", test_k_plus_one_splits);
	suite.add_test("kad_split_redistribute_boundary", test_split_redistribute_and_boundary);
	suite.add_test("kad_local_id_never_inserted", test_local_id_never_inserted);
	suite.add_test("kad_zero_id_rejected", test_zero_id_rejected);
	suite.add_test("kad_unsplittable_replacement", test_unsplittable_full_uses_replacement);
	suite.add_test("kad_verified_not_evicted", test_verified_not_evicted_by_unverified);
	suite.add_test("kad_stale_replaced", test_stale_replaced);
	suite.add_test("kad_duplicate_id_updates", test_duplicate_id_updates);
	suite.add_test("kad_same_id_different_endpoint", test_same_id_different_endpoint_verified_wins);
	suite.add_test("kad_different_id_same_endpoint", test_different_id_same_endpoint_rejected);
	suite.add_test("kad_lru_observe_alive", test_lru_observe_moves_to_bottom);
	suite.add_test("kad_observe_alive_by_endpoint", test_observe_alive_by_endpoint);
	suite.add_test("kad_refresh_fresh_skipped", test_refresh_fresh_leaf_skipped);
	suite.add_test("kad_refresh_stale_target_in_zone", test_refresh_stale_leaf_target_in_zone);
	suite.add_test("kad_refresh_timestamp_bound", test_refresh_timestamp_and_bound);
	suite.add_test("kad_refresh_second_zone_later", test_refresh_second_zone_later);
	suite.add_test("kad_subnet_two_ok_third_rejected", test_subnet_two_ok_third_rejected);
	suite.add_test("kad_subnet_other_slash24", test_subnet_other_slash24_accepted);
	suite.add_test("kad_subnet_duplicate_id", test_subnet_duplicate_id_does_not_inflate);
	suite.add_test("kad_subnet_remove_decrements", test_subnet_remove_decrements);
	suite.add_test("kad_subnet_byte_order", test_subnet_byte_order);
	suite.add_test("kad_lan_exception", test_lan_exception);
	suite.add_test("kad_endpoint_rejects", test_endpoint_rejects);
	suite.add_test("kad_adversarial_one_slash24", test_adversarial_one_slash24);
	suite.add_test("kad_adversarial_max_depth", test_adversarial_max_depth);
	suite.add_test("kad_reinsert_after_remove", test_reinsert_after_remove);
	suite.add_test("kad_replacement_bounded", test_replacement_bounded);
	suite.add_test("kad_verified_hello_res_only", test_verified_event_is_hello_res);
}

#ifdef ENVY_KAD_ROUTING_STANDALONE
int main()
{
	TestSuite suite;
	register_kad_routing_table_tests(suite);
	return suite.run_all_tests() == 0 ? 0 : 1;
}
#endif
