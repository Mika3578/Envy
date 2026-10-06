//
// test_kad_search_source_request_smoke.cpp
//
// Deterministic smoke tests for Kad2 SEARCH_SOURCE_REQ framing and the
// app-trigger policy (#86/#372). Pure helpers only — no live network.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/KadSearchSourceRequest.h"

#include <array>
#include <cstring>

static bool test_encode_kad2_golden_vector()
{
	std::array<uint8_t, KAD_SEARCH_SOURCE_REQ_BODY_SIZE> buf{};
	std::array<uint8_t, KAD_ID_SIZE> hash{};
	for (size_t i = 0; i < hash.size(); ++i)
		hash[i] = static_cast<uint8_t>(i + 1);

	const size_t n = KadEncodeSearchSourceRequest(
		buf.data(), buf.size(), hash.data(), 0x1234u, 0x1122334455667788ull);
	if (n != KAD_SEARCH_SOURCE_REQ_BODY_SIZE)
		return false;
	if (std::memcmp(buf.data(), hash.data(), KAD_ID_SIZE) != 0)
		return false;

	const std::array<uint8_t, KAD_SEARCH_SOURCE_REQ_TAIL_SIZE> expectedTail = {
		0x34, 0x12,
		0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
	};
	if (std::memcmp(
			buf.data() + KAD_ID_SIZE, expectedTail.data(), expectedTail.size()) != 0)
		return false;

	uint16_t startPosition = 0;
	uint64_t fileSize = 0;
	if (!KadDecodeSearchSourceRequestTail(
			buf.data() + KAD_ID_SIZE,
			KAD_SEARCH_SOURCE_REQ_TAIL_SIZE,
			startPosition,
			fileSize))
		return false;
	return startPosition == 0x1234u && fileSize == 0x1122334455667788ull;
}

static bool test_encode_masks_start_position_high_bit()
{
	std::array<uint8_t, KAD_SEARCH_SOURCE_REQ_BODY_SIZE> buf{};
	std::array<uint8_t, KAD_ID_SIZE> hash{};
	if (KadEncodeSearchSourceRequest(
			buf.data(), buf.size(), hash.data(), 0x9234u, 1) != buf.size())
		return false;
	return buf[KAD_ID_SIZE] == 0x34 && buf[KAD_ID_SIZE + 1] == 0x12;
}

static bool test_encode_rejects_short_buffer()
{
	std::array<uint8_t, KAD_SEARCH_SOURCE_REQ_BODY_SIZE - 1> tiny{};
	std::array<uint8_t, KAD_ID_SIZE> hash{};
	return KadEncodeSearchSourceRequest(
		tiny.data(), tiny.size(), hash.data(), 0, 1) == 0;
}

static bool test_decode_legacy_hash_only()
{
	uint16_t startPosition = 99;
	uint64_t fileSize = 99;
	return KadDecodeSearchSourceRequestTail(
		nullptr, 0, startPosition, fileSize) &&
		startPosition == 0 && fileSize == 0;
}

static bool test_decode_legacy_size_only()
{
	const std::array<uint8_t, sizeof(uint64_t)> tail = {
		0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
	};
	uint16_t startPosition = 99;
	uint64_t fileSize = 0;
	if (!KadDecodeSearchSourceRequestTail(
			tail.data(), tail.size(), startPosition, fileSize))
		return false;
	return startPosition == 0 && fileSize == 0x1122334455667788ull;
}

static bool test_decode_rejects_malformed_tail_lengths()
{
	std::array<uint8_t, KAD_SEARCH_SOURCE_REQ_TAIL_SIZE + 1> tail{};
	uint16_t startPosition = 0;
	uint64_t fileSize = 0;

	const size_t invalidLengths[] = { 1, sizeof(uint64_t) - 1,
		sizeof(uint64_t) + 1, KAD_SEARCH_SOURCE_REQ_TAIL_SIZE + 1 };
	for (const size_t length : invalidLengths)
	{
		if (KadDecodeSearchSourceRequestTail(
				tail.data(), length, startPosition, fileSize))
			return false;
	}
	return true;
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
	suite.add_test("Kad SEARCH_SOURCE_REQ Kad2 golden vector", test_encode_kad2_golden_vector);
	suite.add_test("Kad SEARCH_SOURCE_REQ masks start position", test_encode_masks_start_position_high_bit);
	suite.add_test("Kad SEARCH_SOURCE_REQ rejects short buffer", test_encode_rejects_short_buffer);
	suite.add_test("Kad SEARCH_SOURCE_REQ legacy hash-only decode", test_decode_legacy_hash_only);
	suite.add_test("Kad SEARCH_SOURCE_REQ legacy size-only decode", test_decode_legacy_size_only);
	suite.add_test("Kad SEARCH_SOURCE_REQ malformed tail lengths", test_decode_rejects_malformed_tail_lengths);
	suite.add_test("Kad SearchSource app-trigger policy gates", test_policy_requires_kad_and_hash_and_size);
	suite.add_test("Kad SearchSource app-trigger period throttle", test_policy_period_throttle);
}
