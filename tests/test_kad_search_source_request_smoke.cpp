//
// test_kad_search_source_request_smoke.cpp
//
// Deterministic smoke tests for Kad2 SEARCH_SOURCE_REQ framing and the
// app-trigger policy (#86). Pure helpers only — no CKademlia, no live network.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/KadSearchSourceRequest.h"

#include <array>
#include <cstring>

static bool test_encode_body_size()
{
	std::array<uint8_t, 32> buf{};
	std::array<uint8_t, KAD_ID_SIZE> hash{};
	for (size_t i = 0; i < hash.size(); ++i)
		hash[i] = static_cast<uint8_t>(i + 1);

	const size_t n = KadEncodeSearchSourceRequest(
		buf.data(), buf.size(), hash.data(), 0x1122334455667788ull);
	if (n != KAD_SEARCH_SOURCE_REQ_BODY_SIZE)
		return false;
	if (std::memcmp(buf.data(), hash.data(), KAD_ID_SIZE) != 0)
		return false;

	uint64_t decoded = 0;
	if (!KadDecodeSearchSourceFileSize(buf.data() + KAD_ID_SIZE, 8, decoded))
		return false;
	return decoded == 0x1122334455667788ull;
}

static bool test_encode_rejects_short_buffer()
{
	std::array<uint8_t, 8> tiny{};
	std::array<uint8_t, KAD_ID_SIZE> hash{};
	return KadEncodeSearchSourceRequest(tiny.data(), tiny.size(), hash.data(), 1) == 0;
}

static bool test_decode_legacy_hash_only()
{
	uint64_t n = 99;
	return !KadDecodeSearchSourceFileSize(nullptr, 0, n) && n == 0;
}

static bool test_policy_requires_kad_and_hash_and_size()
{
	if (KadMayTriggerSourceSearch(false, true, true, true, 1000, 0, 100))
		return false;
	if (KadMayTriggerSourceSearch(true, false, true, true, 1000, 0, 100))
		return false;
	if (KadMayTriggerSourceSearch(true, true, false, true, 1000, 0, 100))
		return false;
	if (KadMayTriggerSourceSearch(true, true, true, false, 1000, 0, 100))
		return false;
	return KadMayTriggerSourceSearch(true, true, true, true, 1000, 0, 100);
}

static bool test_policy_period_throttle()
{
	if (!KadMayTriggerSourceSearch(true, true, true, true, 5000, 0, 1000))
		return false;
	if (KadMayTriggerSourceSearch(true, true, true, true, 5500, 5000, 1000))
		return false;
	return KadMayTriggerSourceSearch(true, true, true, true, 6000, 5000, 1000);
}

void register_kad_search_source_request_smoke_tests(TestSuite& suite)
{
	suite.add_test("Kad SEARCH_SOURCE_REQ encode/decode FileSize", test_encode_body_size);
	suite.add_test("Kad SEARCH_SOURCE_REQ rejects short buffer", test_encode_rejects_short_buffer);
	suite.add_test("Kad SEARCH_SOURCE_REQ legacy hash-only decode", test_decode_legacy_hash_only);
	suite.add_test("Kad SearchSource app-trigger policy gates", test_policy_requires_kad_and_hash_and_size);
	suite.add_test("Kad SearchSource app-trigger period throttle", test_policy_period_throttle);
}
