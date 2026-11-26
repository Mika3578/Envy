//
// test_kad_publish_wire_smoke.cpp
//
// Golden vectors for Kad2 PUBLISH_SOURCE_REQ / PUBLISH_KEY_REQ framing (#428).
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include "test_framework.h"
#include "../Envy/KadPublishWire.h"

#include <cstring>
#include <vector>

static void FillId(BYTE* p, BYTE b)
{
	memset(p, b, KAD_ID_SIZE);
}

static bool test_publish_source_golden_roundtrip()
{
	BYTE fileHash[KAD_ID_SIZE];
	BYTE sourceId[KAD_ID_SIZE];
	FillId(fileHash, 0x11);
	FillId(sourceId, 0x22);

	std::vector<BYTE> body;
	KadBuildPublishSourceReqBody(body, fileHash, sourceId, KAD_SOURCE_TYPE_HIGHID, 4662, 4672);

	// Literal wire bytes from KadBuildPublishSourceReqBody — independent check that
	// tag encodings match compact INT name-ID form used by aMule publish.
	const BYTE kExpected[] = {
		// file hash
		0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
		0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
		// source id
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		3,       // tag count
		0x89, 0xFF, 0x01,                // UINT8 TAG_SOURCETYPE = HighID
		0x88, 0xFD, 0x36, 0x12,          // UINT16 TAG_SOURCEPORT = 4662
		0x88, 0xFC, 0x40, 0x12           // UINT16 TAG_SOURCEUPORT = 4672
	};

	if (body.size() != sizeof(kExpected))
		return false;
	if (memcmp(body.data(), kExpected, sizeof(kExpected)) != 0)
		return false;

	KadPublishSourceReq parsed{};
	if (!KadParsePublishSourceReqBody(body.data(), body.size(), parsed))
		return false;
	if (memcmp(parsed.fileHash, fileHash, KAD_ID_SIZE) != 0)
		return false;
	if (memcmp(parsed.sourceId, sourceId, KAD_ID_SIZE) != 0)
		return false;
	if (!parsed.tags.sawSourceType || parsed.tags.sourceType != KAD_SOURCE_TYPE_HIGHID)
		return false;
	if (parsed.tags.tcpPort != 4662 || parsed.tags.udpPort != 4672)
		return false;
	return true;
}

static bool test_publish_source_rejects_legacy_entry_slice()
{
	// Emulate old Envy WriteEntryTags prefix glued after a file hash + source ID.
	std::vector<BYTE> body;
	for (int i = 0; i < KAD_ID_SIZE; ++i)
		body.push_back(0xAA);
	for (int i = 0; i < KAD_ID_SIZE; ++i)
		body.push_back(0xBB);
	// Legacy: IP + UDP + TCP before tag list.
	body.push_back(0x04);
	body.push_back(0x03);
	body.push_back(0x02);
	body.push_back(0x01);
	body.push_back(0x40);
	body.push_back(0x12); // udp 4672
	body.push_back(0x36);
	body.push_back(0x12); // tcp 4662
	body.push_back(1);    // tag count
	body.push_back(0x89);
	body.push_back(0xFF);
	body.push_back(0x01);

	KadPublishSourceReq parsed{};
	return !KadParsePublishSourceReqBody(body.data(), body.size(), parsed);
}

static bool test_publish_source_missing_sourcetype()
{
	BYTE ids[KAD_ID_SIZE]{};
	std::vector<BYTE> body;
	KadAppendIdBytes(body, ids);
	KadAppendIdBytes(body, ids);
	body.push_back(1);
	// TCP port only — no sourcetype.
	KadAppendCompactIntTag(body, KAD_ED2K_TAG_UINT16, KAD_TAG_SOURCEPORT, 4662);

	KadPublishSourceReq parsed{};
	return !KadParsePublishSourceReqBody(body.data(), body.size(), parsed);
}

static bool test_publish_key_two_entries()
{
	BYTE keyword[KAD_ID_SIZE];
	FillId(keyword, 0x33);

	std::vector<BYTE> body;
	KadAppendIdBytes(body, keyword);
	KadAppendWordLE(body, 2);

	for (BYTE fill : { 0x44, 0x55 })
	{
		KadAppendId(body, fill);
		KadAppendPublishSourceOutboundTags(body, KAD_SOURCE_TYPE_HIGHID, 4662, 4672);
	}

	WORD count = 0;
	std::vector<KadPublishKeyEntry> entries;
	if (!KadParsePublishKeyReqBody(body.data(), body.size(), nullptr, count, &entries))
		return false;
	if (count != 2 || entries.size() != 2)
		return false;
	return entries[0].tags.sawSourceType && entries[1].tags.sawSourceType;
}

static bool test_publish_key_count_bounds()
{
	BYTE keyword[KAD_ID_SIZE];
	FillId(keyword, 0x77);
	std::vector<BYTE> body;
	KadAppendIdBytes(body, keyword);
	KadAppendWordLE(body, KAD_PUBLISH_KEY_MAX_ENTRIES + 1);

	WORD count = 0;
	return !KadParsePublishKeyReqBody(body.data(), body.size(), nullptr, count, nullptr);
}

void register_kad_publish_wire_smoke_tests(TestSuite& suite)
{
	suite.add_test("publish_source_golden_roundtrip", test_publish_source_golden_roundtrip);
	suite.add_test("publish_source_rejects_legacy_slice", test_publish_source_rejects_legacy_entry_slice);
	suite.add_test("publish_source_missing_sourcetype", test_publish_source_missing_sourcetype);
	suite.add_test("publish_key_two_entries", test_publish_key_two_entries);
	suite.add_test("publish_key_count_bounds", test_publish_key_count_bounds);
}