//
// test_kad_search_res_delivery_smoke.cpp
//
// Deterministic smoke tests for Kad2 SEARCH_RES → ED2K source mapping (#86).
// Pure helpers only — no CKademlia instantiation, no live network.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/KadSearchResDelivery.h"

#include <cstring>
#include <vector>

static bool test_classify_source_delivers()
{
	return KadClassifySearchResponse(true, false, true, KadSearchKind::Source) == KadSearchResDisposition::DeliverSources;
}

static bool test_classify_keyword_ignored()
{
	return KadClassifySearchResponse(true, false, true, KadSearchKind::Keyword) == KadSearchResDisposition::IgnoreKeywordResults;
}

static bool test_classify_unsolicited()
{
	return KadClassifySearchResponse(false, false, false, KadSearchKind::None) == KadSearchResDisposition::RejectUnsolicited;
}

static bool test_classify_expired()
{
	return KadClassifySearchResponse(true, true, true, KadSearchKind::Source) == KadSearchResDisposition::RejectExpired;
}

static bool test_classify_mismatched_target()
{
	return KadClassifySearchResponse(true, false, false, KadSearchKind::Source) == KadSearchResDisposition::RejectMismatchedTarget;
}

static bool test_map_valid_highid()
{
	KadSourceCandidate cand{};
	cand.sawSourceType = true;
	cand.sourceType = KAD_SOURCE_TYPE_HIGHID;
	cand.sawSourceIp = true;
	cand.sourceIp = 0x01020304; // 4.3.2.1 on LE — first octet non-zero
	cand.sawTcpPort = true;
	cand.tcpPort = 4662;
	memset(cand.contactId, 0xAB, KAD_ID_SIZE);

	KadEd2kSourceParams params;
	if (!KadMapSourceCandidateToEd2k(cand, params) || !params.deliverable)
		return false;
	return params.nClientID == 0x01020304 && params.nClientPort == 4662 && params.nServerIP == 0 && params.nServerPort == 0 && params.oGUID[0] == 0xAB;
}

static bool test_map_zero_port_rejected()
{
	KadSourceCandidate cand{};
	cand.sawSourceType = true;
	cand.sourceType = KAD_SOURCE_TYPE_HIGHID;
	cand.sawSourceIp = true;
	cand.sourceIp = 0x01020304;
	cand.sawTcpPort = true;
	cand.tcpPort = 0;

	KadEd2kSourceParams params;
	return !KadMapSourceCandidateToEd2k(cand, params);
}

static bool test_map_missing_ip_rejected()
{
	KadSourceCandidate cand{};
	cand.sawSourceType = true;
	cand.sourceType = KAD_SOURCE_TYPE_HIGHID;
	cand.sawTcpPort = true;
	cand.tcpPort = 4662;

	KadEd2kSourceParams params;
	return !KadMapSourceCandidateToEd2k(cand, params);
}

static bool test_map_zero_octet_ip_rejected()
{
	KadSourceCandidate cand{};
	cand.sawSourceType = true;
	cand.sourceType = KAD_SOURCE_TYPE_HIGHID;
	cand.sawSourceIp = true;
	// IN_ADDR first octet is the low byte of the LE DWORD (AddSourceInternal s_b1).
	cand.sourceIp = 0x04030200; // 0.2.3.4
	cand.sawTcpPort = true;
	cand.tcpPort = 4662;

	KadEd2kSourceParams params;
	return !KadMapSourceCandidateToEd2k(cand, params);
}

static bool test_map_buddy_type_not_deliverable()
{
	KadSourceCandidate cand{};
	cand.sawSourceType = true;
	cand.sourceType = 3; // firewalled + buddy
	cand.sawSourceIp = true;
	cand.sourceIp = 0x01020304;
	cand.sawTcpPort = true;
	cand.tcpPort = 4662;
	cand.serverOrBuddyIp = 0x08080808;
	cand.serverOrBuddyPort = 4672;

	KadEd2kSourceParams params;
	return !KadMapSourceCandidateToEd2k(cand, params);
}

static bool test_map_type6_not_deliverable()
{
	KadSourceCandidate cand{};
	cand.sawSourceType = true;
	cand.sourceType = 6;
	cand.sawSourceIp = true;
	cand.sourceIp = 0x01020304;
	cand.sawTcpPort = true;
	cand.tcpPort = 4662;

	KadEd2kSourceParams params;
	return !KadMapSourceCandidateToEd2k(cand, params);
}

static std::vector<BYTE> BuildSearchRes(
    BYTE targetFill,
    WORD nCount,
    const std::vector<BYTE>& entries)
{
	std::vector<BYTE> body;
	KadAppendId(body, 0x11);       // sender
	KadAppendId(body, targetFill); // target
	KadAppendWordLE(body, nCount);
	body.insert(body.end(), entries.begin(), entries.end());
	return body;
}

static bool test_parse_valid_single_source()
{
	std::vector<BYTE> entries;
	KadAppendHighIdSourceEntry(entries, 0xCD, 0x01020304, 4662);

	const auto body = BuildSearchRes(0xAA, 1, entries);
	BYTE target[KAD_ID_SIZE];
	WORD count = 0;
	std::vector<KadSourceCandidate> out;
	if (!KadParseSearchResBody(body.data(), body.size(), nullptr, target, count, &out))
		return false;
	if (count != 1 || out.size() != 1)
		return false;
	if (target[0] != 0xAA)
		return false;

	KadEd2kSourceParams params;
	return KadMapSourceCandidateToEd2k(out[0], params) && params.deliverable && params.nClientPort == 4662;
}

static bool test_parse_zero_results()
{
	const auto body = BuildSearchRes(0xAA, 0, {});
	WORD count = 99;
	std::vector<KadSourceCandidate> out;
	if (!KadParseSearchResBody(body.data(), body.size(), nullptr, nullptr, count, &out))
		return false;
	return count == 0 && out.empty();
}

static bool test_parse_multiple_sources()
{
	std::vector<BYTE> entries;
	KadAppendHighIdSourceEntry(entries, 0x01, 0x01020304, 4662);
	KadAppendHighIdSourceEntry(entries, 0x02, 0x05060708, 4663);

	const auto body = BuildSearchRes(0xAA, 2, entries);
	WORD count = 0;
	std::vector<KadSourceCandidate> out;
	if (!KadParseSearchResBody(body.data(), body.size(), nullptr, nullptr, count, &out))
		return false;
	if (count != 2 || out.size() != 2)
		return false;

	KadEd2kSourceParams a, b;
	return KadMapSourceCandidateToEd2k(out[0], a) && KadMapSourceCandidateToEd2k(out[1], b) && a.nClientPort == 4662 && b.nClientPort == 4663 && a.nClientID != b.nClientID;
}

static bool test_parse_duplicate_sources_both_map()
{
	// Dedup is AddSourceED2K's job — both candidates must map successfully.
	std::vector<BYTE> entries;
	KadAppendHighIdSourceEntry(entries, 0x01, 0x01020304, 4662);
	KadAppendHighIdSourceEntry(entries, 0x01, 0x01020304, 4662);

	const auto body = BuildSearchRes(0xAA, 2, entries);
	WORD count = 0;
	std::vector<KadSourceCandidate> out;
	if (!KadParseSearchResBody(body.data(), body.size(), nullptr, nullptr, count, &out))
		return false;
	if (out.size() != 2)
		return false;
	KadEd2kSourceParams a, b;
	return KadMapSourceCandidateToEd2k(out[0], a) && KadMapSourceCandidateToEd2k(out[1], b) && a.nClientID == b.nClientID && a.nClientPort == b.nClientPort;
}

static bool test_parse_truncated_entry()
{
	std::vector<BYTE> body;
	KadAppendId(body, 0x11);
	KadAppendId(body, 0xAA);
	KadAppendWordLE(body, 1);
	// Answer ID only — missing tag count / tags.
	KadAppendId(body, 0xCD);

	WORD count = 0;
	return !KadParseSearchResBody(body.data(), body.size(), nullptr, nullptr, count, nullptr);
}

static bool test_parse_count_larger_than_bytes()
{
	std::vector<BYTE> entries;
	KadAppendHighIdSourceEntry(entries, 0x01, 0x01020304, 4662);
	// Claim 2 results but only serialize one.
	const auto body = BuildSearchRes(0xAA, 2, entries);
	WORD count = 0;
	return !KadParseSearchResBody(body.data(), body.size(), nullptr, nullptr, count, nullptr);
}

static bool test_parse_overflowing_tag_length()
{
	std::vector<BYTE> body;
	KadAppendId(body, 0x11);
	KadAppendId(body, 0xAA);
	KadAppendWordLE(body, 1);
	KadAppendId(body, 0xCD);
	body.push_back(1); // one tag
	// Non-compact STRING type with name len 1 + key, then STRING value len = 0xFFFF.
	body.push_back(KAD_ED2K_TAG_STRING);
	KadAppendWordLE(body, 1);
	body.push_back(KAD_TAG_SOURCETYPE);
	KadAppendWordLE(body, 0xFFFF); // claimed string length

	WORD count = 0;
	return !KadParseSearchResBody(body.data(), body.size(), nullptr, nullptr, count, nullptr);
}

static bool test_parse_unknown_optional_tag_ok()
{
	std::vector<BYTE> entries;
	KadAppendHighIdSourceEntry(entries, 0xCD, 0x01020304, 4662, KAD_SOURCE_TYPE_HIGHID, true);

	const auto body = BuildSearchRes(0xAA, 1, entries);
	WORD count = 0;
	std::vector<KadSourceCandidate> out;
	if (!KadParseSearchResBody(body.data(), body.size(), nullptr, nullptr, count, &out))
		return false;
	KadEd2kSourceParams params;
	return out.size() == 1 && KadMapSourceCandidateToEd2k(out[0], params) && params.deliverable;
}

static bool test_parse_missing_mandatory_endpoint()
{
	// Source type only — no IP/port tags.
	std::vector<BYTE> entries;
	KadAppendId(entries, 0xCD);
	entries.push_back(1);
	KadAppendCompactIntTag(entries, KAD_ED2K_TAG_UINT8, KAD_TAG_SOURCETYPE, KAD_SOURCE_TYPE_HIGHID);

	const auto body = BuildSearchRes(0xAA, 1, entries);
	WORD count = 0;
	std::vector<KadSourceCandidate> out;
	if (!KadParseSearchResBody(body.data(), body.size(), nullptr, nullptr, count, &out))
		return false;
	KadEd2kSourceParams params;
	return out.size() == 1 && !KadMapSourceCandidateToEd2k(out[0], params);
}

static bool test_parse_header_too_short()
{
	BYTE tiny[10] = {};
	WORD count = 0;
	return !KadParseSearchResBody(tiny, sizeof(tiny), nullptr, nullptr, count, nullptr);
}

static bool test_outstanding_register_lookup_expire()
{
	KadOutstandingSearchMap map;
	BYTE target[KAD_ID_SIZE];
	memset(target, 0x42, KAD_ID_SIZE);

	const DWORD t0 = 1000;
	if (!map.Register(KadSearchKind::Source, target, t0))
		return false;

	KadOutstandingSearch ctx;
	bool expired = true;
	if (!map.Lookup(target, t0 + 1000, ctx, expired))
		return false;
	if (expired || ctx.kind != KadSearchKind::Source)
		return false;

	expired = false;
	if (!map.Lookup(target, t0 + KAD_SEARCH_CONTEXT_LIFETIME_MS + 1, ctx, expired))
		return false;
	if (!expired)
		return false;

	map.Expire(t0 + KAD_SEARCH_CONTEXT_LIFETIME_MS + 1);
	return map.Size() == 0;
}

static bool test_outstanding_keyword_vs_source()
{
	KadOutstandingSearchMap map;
	BYTE target[KAD_ID_SIZE];
	memset(target, 0x55, KAD_ID_SIZE);

	if (!map.Register(KadSearchKind::Keyword, target, 1))
		return false;

	KadOutstandingSearch ctx;
	bool expired = false;
	if (!map.Lookup(target, 1, ctx, expired))
		return false;
	if (ctx.kind != KadSearchKind::Keyword)
		return false;

	// Re-register as source for same target refreshes kind.
	if (!map.Register(KadSearchKind::Source, target, 1))
		return false;
	if (!map.Lookup(target, 1, ctx, expired))
		return false;
	return ctx.kind == KadSearchKind::Source && map.Size() == 1;
}

static bool test_outstanding_map_bounded()
{
	KadOutstandingSearchMap map;
	BYTE target[KAD_ID_SIZE];
	memset(target, 0, KAD_ID_SIZE);

	for (size_t i = 0; i < KAD_OUTSTANDING_SEARCH_MAX + 8; ++i)
	{
		target[0] = static_cast<BYTE>(i & 0xFF);
		target[1] = static_cast<BYTE>((i >> 8) & 0xFF);
		if (!map.Register(KadSearchKind::Source, target, static_cast<DWORD>(1000 + i)))
			return false;
	}
	return map.Size() <= KAD_OUTSTANDING_SEARCH_MAX;
}

static bool test_outstanding_unknown_target()
{
	KadOutstandingSearchMap map;
	BYTE target[KAD_ID_SIZE];
	memset(target, 0x99, KAD_ID_SIZE);
	KadOutstandingSearch ctx;
	bool expired = false;
	return !map.Lookup(target, 1, ctx, expired);
}

static bool test_keyword_disposition_never_maps_to_delivery()
{
	// Even with perfectly valid source-shaped tags, keyword disposition must not deliver.
	return KadClassifySearchResponse(true, false, true, KadSearchKind::Keyword) != KadSearchResDisposition::DeliverSources;
}

void register_kad_search_res_delivery_smoke_tests(TestSuite& suite)
{
	suite.add_test("kad_classify_source_delivers", test_classify_source_delivers);
	suite.add_test("kad_classify_keyword_ignored", test_classify_keyword_ignored);
	suite.add_test("kad_classify_unsolicited", test_classify_unsolicited);
	suite.add_test("kad_classify_expired", test_classify_expired);
	suite.add_test("kad_classify_mismatched_target", test_classify_mismatched_target);
	suite.add_test("kad_map_valid_highid", test_map_valid_highid);
	suite.add_test("kad_map_zero_port_rejected", test_map_zero_port_rejected);
	suite.add_test("kad_map_missing_ip_rejected", test_map_missing_ip_rejected);
	suite.add_test("kad_map_zero_octet_ip_rejected", test_map_zero_octet_ip_rejected);
	suite.add_test("kad_map_buddy_type_not_deliverable", test_map_buddy_type_not_deliverable);
	suite.add_test("kad_map_type6_not_deliverable", test_map_type6_not_deliverable);
	suite.add_test("kad_parse_valid_single_source", test_parse_valid_single_source);
	suite.add_test("kad_parse_zero_results", test_parse_zero_results);
	suite.add_test("kad_parse_multiple_sources", test_parse_multiple_sources);
	suite.add_test("kad_parse_duplicate_sources_both_map", test_parse_duplicate_sources_both_map);
	suite.add_test("kad_parse_truncated_entry", test_parse_truncated_entry);
	suite.add_test("kad_parse_count_larger_than_bytes", test_parse_count_larger_than_bytes);
	suite.add_test("kad_parse_overflowing_tag_length", test_parse_overflowing_tag_length);
	suite.add_test("kad_parse_unknown_optional_tag_ok", test_parse_unknown_optional_tag_ok);
	suite.add_test("kad_parse_missing_mandatory_endpoint", test_parse_missing_mandatory_endpoint);
	suite.add_test("kad_parse_header_too_short", test_parse_header_too_short);
	suite.add_test("kad_outstanding_register_lookup_expire", test_outstanding_register_lookup_expire);
	suite.add_test("kad_outstanding_keyword_vs_source", test_outstanding_keyword_vs_source);
	suite.add_test("kad_outstanding_map_bounded", test_outstanding_map_bounded);
	suite.add_test("kad_outstanding_unknown_target", test_outstanding_unknown_target);
	suite.add_test("kad_keyword_never_delivery_disposition", test_keyword_disposition_never_maps_to_delivery);
}
