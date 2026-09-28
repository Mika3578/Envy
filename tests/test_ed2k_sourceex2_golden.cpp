//
// test_ed2k_sourceex2_golden.cpp
//
// Golden / wire tests for ED2K Source Exchange v2 (REQUESTSOURCES2 / ANSWERSOURCES2).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/Ed2kSourceEx2Wire.h"

#include <array>
#include <cstring>
#include <vector>

static void fill_synthetic_hash(BYTE* pHash)
{
	for (int i = 0; i < 16; ++i)
		pHash[i] = (BYTE)(0xA0 + i);
}

static DWORD build_answer_packet(
    BYTE* pOut, DWORD nCapacity, BYTE nVersion, const BYTE* pHash16, WORD nCount, const BYTE* pRecords, DWORD nRecordsLen)
{
	const DWORD nHeader = Ed2kSourceEx2AnswerHeaderMinBytes();
	if (pOut == NULL || pHash16 == NULL || nCapacity < nHeader + nRecordsLen)
		return 0;

	pOut[0] = nVersion;
	memcpy(pOut + 1, pHash16, 16);
	pOut[17] = (BYTE)(nCount & 0xFF);
	pOut[18] = (BYTE)((nCount >> 8) & 0xFF);
	if (nRecordsLen > 0 && pRecords != NULL)
		memcpy(pOut + nHeader, pRecords, nRecordsLen);

	return nHeader + nRecordsLen;
}

static bool test_request_v4_roundtrip()
{
	BYTE hash[16];
	fill_synthetic_hash(hash);

	std::array<BYTE, 32> buf = {};
	const DWORD nLen = Ed2kSourceEx2WriteRequest(buf.data(), (DWORD)buf.size(), 4, 0, hash);
	if (nLen != Ed2kSourceEx2RequestMinBytes())
		return false;

	BYTE outHash[16] = {};
	BYTE ver = 0;
	WORD opt = 0;
	return Ed2kSourceEx2ParseRequest(buf.data(), nLen, outHash, &ver, &opt) == Ed2kSourceEx2ParseOk && ver == 4 && opt == 0 && memcmp(outHash, hash, 16) == 0;
}

static bool test_request_versions_1_to_4()
{
	BYTE hash[16];
	fill_synthetic_hash(hash);
	std::array<BYTE, 32> buf = {};

	for (BYTE v = 1; v <= 4; ++v)
	{
		const DWORD nLen = Ed2kSourceEx2WriteRequest(buf.data(), (DWORD)buf.size(), v, 0, hash);
		BYTE ver = 0;
		WORD opt = 0;
		BYTE outHash[16] = {};
		if (nLen != Ed2kSourceEx2RequestMinBytes())
			return false;
		if (Ed2kSourceEx2ParseRequest(buf.data(), nLen, outHash, &ver, &opt) != Ed2kSourceEx2ParseOk)
			return false;
		if (ver != v)
			return false;
	}
	return true;
}

static bool test_request_preferred_version()
{
	return Ed2kSourceEx2PreferredRequestVersion() == ED2K_SOURCEEXCHANGE2_VERSION && ED2K_SOURCEEXCHANGE2_VERSION == 4;
}

static bool test_request_version_zero()
{
	std::array<BYTE, 19> buf = {};
	BYTE hash[16] = {};
	BYTE ver = 0;
	WORD opt = 0;
	buf[0] = 0;
	return Ed2kSourceEx2ParseRequest(buf.data(), (DWORD)buf.size(), hash, &ver, &opt) == Ed2kSourceEx2ParseVersionZero;
}

static bool test_request_unsupported_version()
{
	std::array<BYTE, 19> buf = {};
	BYTE hash[16] = {};
	BYTE ver = 0;
	WORD opt = 0;
	buf[0] = 9;
	return Ed2kSourceEx2ParseRequest(buf.data(), (DWORD)buf.size(), hash, &ver, &opt) == Ed2kSourceEx2ParseUnsupportedVersion;
}

static bool test_request_truncated_empty()
{
	BYTE hash[16] = {};
	BYTE ver = 0;
	WORD opt = 0;
	return Ed2kSourceEx2ParseRequest(NULL, 0, hash, &ver, &opt) == Ed2kSourceEx2ParseTruncated;
}

static bool test_request_truncated_before_version()
{
	std::array<BYTE, 18> buf = {};
	BYTE hash[16] = {};
	BYTE ver = 0;
	WORD opt = 0;
	buf[0] = 4;
	return Ed2kSourceEx2ParseRequest(buf.data(), (DWORD)buf.size(), hash, &ver, &opt) == Ed2kSourceEx2ParseTruncated;
}

static bool test_request_truncated_options()
{
	std::array<BYTE, 2> buf = {};
	BYTE hash[16] = {};
	BYTE ver = 0;
	WORD opt = 0;
	buf[0] = 4;
	return Ed2kSourceEx2ParseRequest(buf.data(), (DWORD)buf.size(), hash, &ver, &opt) == Ed2kSourceEx2ParseTruncated;
}

static bool test_request_truncated_hash()
{
	std::array<BYTE, 18> buf = {};
	BYTE hash[16] = {};
	BYTE ver = 0;
	WORD opt = 0;
	buf[0] = 4;
	return Ed2kSourceEx2ParseRequest(buf.data(), (DWORD)buf.size(), hash, &ver, &opt) == Ed2kSourceEx2ParseTruncated;
}

static bool test_request_trailing_bytes_policy()
{
	BYTE hash[16];
	fill_synthetic_hash(hash);
	std::array<BYTE, 24> buf = {};
	const DWORD nLen = Ed2kSourceEx2WriteRequest(buf.data(), 19, 4, 0, hash);
	buf[19] = 0xFF;
	buf[20] = 0xFE;
	BYTE ver = 0;
	WORD opt = 0;
	BYTE outHash[16] = {};
	return nLen == 19 && Ed2kSourceEx2ParseRequest(buf.data(), 19, outHash, &ver, &opt) == Ed2kSourceEx2ParseOk && Ed2kSourceEx2ParseRequest(buf.data(), 21, outHash, &ver, &opt) == Ed2kSourceEx2ParseTrailingBytes;
}

static bool test_legacy_envy_request_detected_22()
{
	std::array<BYTE, 22> legacy = {};
	fill_synthetic_hash(legacy.data());
	return Ed2kSourceEx2LooksLikeLegacyEnvyRequest(legacy.data(), 22) == TRUE;
}

static bool test_legacy_envy_request_detected_26()
{
	std::array<BYTE, 26> legacy = {};
	fill_synthetic_hash(legacy.data());
	return Ed2kSourceEx2LooksLikeLegacyEnvyRequest(legacy.data(), 26) == TRUE;
}

static bool test_standard_request_not_legacy_hash_byte16()
{
	BYTE hash[16];
	fill_synthetic_hash(hash);
	std::array<BYTE, 19> buf = {};
	const DWORD nLen = Ed2kSourceEx2WriteRequest(buf.data(), (DWORD)buf.size(), 4, 0, hash);
	if (nLen != 19)
		return false;

	static const BYTE kHashByte16Cases[] = { 1, 2, 3, 4, 0xAB };
	for (size_t i = 0; i < sizeof(kHashByte16Cases); ++i)
	{
		buf[16] = kHashByte16Cases[i];
		if (Ed2kSourceEx2LooksLikeLegacyEnvyRequest(buf.data(), nLen) == TRUE)
			return false;
	}
	return true;
}

static bool test_request_exact_length_18_rejected()
{
	std::array<BYTE, 18> buf = {};
	buf[0] = 4;
	BYTE hash[16] = {};
	BYTE ver = 0;
	WORD opt = 0;
	return Ed2kSourceEx2ParseRequest(buf.data(), 18, hash, &ver, &opt) == Ed2kSourceEx2ParseTruncated;
}

static bool test_request_exact_length_20_rejected()
{
	BYTE hash[16];
	fill_synthetic_hash(hash);
	std::array<BYTE, 20> buf = {};
	Ed2kSourceEx2WriteRequest(buf.data(), 19, 4, 0, hash);
	buf[19] = 0xFF;
	BYTE ver = 0;
	WORD opt = 0;
	BYTE outHash[16] = {};
	return Ed2kSourceEx2ParseRequest(buf.data(), 20, outHash, &ver, &opt) == Ed2kSourceEx2ParseTrailingBytes;
}

static bool test_request_version_negotiation()
{
	BYTE hash[16];
	fill_synthetic_hash(hash);
	std::array<BYTE, 32> buf = {};

	static const BYTE kUnsupportedVersions[] = { 0, 5, 255 };
	for (size_t i = 0; i < sizeof(kUnsupportedVersions); ++i)
	{
		if (Ed2kSourceEx2WriteRequest(buf.data(), (DWORD)buf.size(), kUnsupportedVersions[i], 0, hash) != 0)
			return false;
	}

	for (BYTE v = 1; v <= 4; ++v)
	{
		if (Ed2kSourceEx2NegotiatedAnswerVersion(v) != v)
			return false;
	}

	return Ed2kSourceEx2NegotiatedAnswerVersion(0) == 0 && Ed2kSourceEx2NegotiatedAnswerVersion(5) == 0 && Ed2kSourceEx2NegotiatedAnswerVersion(255) == 0;
}

// eMule DownloadClient.cpp standalone layout: version @0, options @1..2, hash @3..18
static bool test_emule_standalone_golden_request()
{
	static const BYTE kEmuleHash[16] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
	};
	static const BYTE kExpected[19] = {
		4, 0, 0,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
	};

	std::array<BYTE, 19> built = {};
	const DWORD nLen = Ed2kSourceEx2WriteRequest(built.data(), (DWORD)built.size(), 4, 0, kEmuleHash);
	if (nLen != 19 || memcmp(built.data(), kExpected, 19) != 0)
		return false;

	BYTE outHash[16] = {};
	BYTE ver = 0;
	WORD opt = 0;
	return Ed2kSourceEx2ParseRequest(built.data(), nLen, outHash, &ver, &opt) == Ed2kSourceEx2ParseOk && ver == 4 && opt == 0 && memcmp(outHash, kEmuleHash, 16) == 0;
}

static bool test_answer_v1_single_source()
{
	BYTE hash[16];
	fill_synthetic_hash(hash);
	std::array<BYTE, 12> rec = {};
	rec[0] = 0x0A;
	rec[1] = 0x0B;
	rec[2] = 0x50;
	rec[3] = 0xC3;
	rec[4] = 0x7F;
	rec[5] = 0x00;
	rec[6] = 0x01;
	rec[7] = 0xBB;
	rec[8] = 0x01;
	rec[9] = 0x90;
	rec[10] = 0xC0;
	rec[11] = 0x00;

	std::array<BYTE, 64> pkt = {};
	const DWORD nLen = build_answer_packet(pkt.data(), (DWORD)pkt.size(), 1, hash, 1, rec.data(), 12);

	BYTE ver = 0;
	BYTE outHash[16] = {};
	WORD count = 0;
	DWORD recLen = 0;
	return nLen == 31 && Ed2kSourceEx2ParseAnswerHeader(pkt.data(), nLen, &ver, outHash, &count, &recLen) == Ed2kSourceEx2ParseOk && ver == 1 && count == 1 && recLen == 12;
}

static bool test_answer_v2_single_source()
{
	BYTE hash[16];
	fill_synthetic_hash(hash);
	std::array<BYTE, 28> rec = {};
	memset(rec.data(), 0x33, 28);

	std::array<BYTE, 64> pkt = {};
	const DWORD nLen = build_answer_packet(pkt.data(), (DWORD)pkt.size(), 2, hash, 1, rec.data(), 28);

	BYTE ver = 0;
	WORD count = 0;
	DWORD recLen = 0;
	return Ed2kSourceEx2ParseAnswerHeader(pkt.data(), nLen, &ver, hash, &count, &recLen) == Ed2kSourceEx2ParseOk && ver == 2 && recLen == 28;
}

static bool test_answer_v3_single_source()
{
	BYTE hash[16];
	fill_synthetic_hash(hash);
	std::array<BYTE, 28> rec = {};
	memset(rec.data(), 0x44, 28);

	std::array<BYTE, 64> pkt = {};
	const DWORD nLen = build_answer_packet(pkt.data(), (DWORD)pkt.size(), 3, hash, 1, rec.data(), 28);

	BYTE ver = 0;
	WORD count = 0;
	DWORD recLen = 0;
	return Ed2kSourceEx2ParseAnswerHeader(pkt.data(), nLen, &ver, hash, &count, &recLen) == Ed2kSourceEx2ParseOk && ver == 3 && recLen == 28;
}

static bool test_answer_v4_crypt_byte()
{
	BYTE hash[16];
	fill_synthetic_hash(hash);
	const DWORD nRecord = Ed2kSourceEx2AnswerRecordBytes(4);
	std::array<BYTE, 29> rec = {};
	memset(rec.data(), 0x55, nRecord);
	rec[nRecord - 1] = 0x07;

	std::array<BYTE, 64> pkt = {};
	const DWORD nLen = build_answer_packet(pkt.data(), (DWORD)pkt.size(), 4, hash, 1, rec.data(), nRecord);

	BYTE ver = 0;
	WORD count = 0;
	DWORD recLen = 0;
	return Ed2kSourceEx2ParseAnswerHeader(pkt.data(), nLen, &ver, hash, &count, &recLen) == Ed2kSourceEx2ParseOk && ver == 4 && recLen == nRecord;
}

static bool test_answer_v4_crypt_reserved_bits_parsed_only()
{
	BYTE hash[16];
	fill_synthetic_hash(hash);
	std::array<BYTE, 29> rec = {};
	memset(rec.data(), 0, 28);
	rec[28] = 0xF8;

	std::array<BYTE, 64> pkt = {};
	const DWORD nLen = build_answer_packet(pkt.data(), (DWORD)pkt.size(), 4, hash, 1, rec.data(), 29);
	BYTE ver = 0;
	WORD count = 0;
	DWORD recLen = 0;
	return Ed2kSourceEx2ParseAnswerHeader(pkt.data(), nLen, &ver, hash, &count, &recLen) == Ed2kSourceEx2ParseOk;
}

static bool test_answer_zero_sources()
{
	BYTE hash[16];
	fill_synthetic_hash(hash);
	std::array<BYTE, 19> pkt = {};
	const DWORD nLen = build_answer_packet(pkt.data(), (DWORD)pkt.size(), 2, hash, 0, NULL, 0);

	BYTE ver = 0;
	WORD count = 99;
	DWORD recLen = 0;
	return nLen == 19 && Ed2kSourceEx2ParseAnswerHeader(pkt.data(), nLen, &ver, hash, &count, &recLen) == Ed2kSourceEx2ParseOk && count == 0 && recLen == 0;
}

static bool test_answer_multiple_sources_v2()
{
	BYTE hash[16];
	fill_synthetic_hash(hash);
	std::array<BYTE, 56> rec = {};
	memset(rec.data(), 0x66, 56);

	std::array<BYTE, 128> pkt = {};
	const DWORD nLen = build_answer_packet(pkt.data(), (DWORD)pkt.size(), 2, hash, 2, rec.data(), 56);

	BYTE ver = 0;
	WORD count = 0;
	DWORD recLen = 0;
	return Ed2kSourceEx2ParseAnswerHeader(pkt.data(), nLen, &ver, hash, &count, &recLen) == Ed2kSourceEx2ParseOk && count == 2 && recLen == 56;
}

static bool test_answer_count_overflow()
{
	BYTE hash[16];
	fill_synthetic_hash(hash);
	std::array<BYTE, 12> rec = {};
	std::array<BYTE, 64> pkt = {};
	const DWORD nLen = build_answer_packet(pkt.data(), (DWORD)pkt.size(), 1, hash, 2, rec.data(), 12);

	BYTE ver = 0;
	WORD count = 0;
	DWORD recLen = 0;
	return Ed2kSourceEx2ParseAnswerHeader(pkt.data(), nLen, &ver, hash, &count, &recLen) == Ed2kSourceEx2ParseRecordTruncated;
}

static bool test_answer_count_mul_overflow()
{
	std::array<BYTE, 32> pkt = {};
	pkt[0] = 4;
	fill_synthetic_hash(pkt.data() + 1);
	pkt[17] = 0xFF;
	pkt[18] = 0xFF;

	BYTE ver = 0;
	WORD count = 0;
	DWORD recLen = 0;
	return Ed2kSourceEx2ParseAnswerHeader(pkt.data(), (DWORD)pkt.size(), &ver, pkt.data() + 1, &count, &recLen) == Ed2kSourceEx2ParseRecordTruncated;
}

static bool test_answer_count_mul_guard()
{
	DWORD nTotal = 0;
	return Ed2kSourceEx2MulRecordBytes(2, MAXDWORD / 2u + 1u, &nTotal) == FALSE;
}

static bool test_answer_truncated_header()
{
	std::array<BYTE, 18> pkt = {};
	pkt[0] = 2;
	BYTE ver = 0;
	WORD count = 0;
	DWORD recLen = 0;
	return Ed2kSourceEx2ParseAnswerHeader(pkt.data(), (DWORD)pkt.size(), &ver, pkt.data(), &count, &recLen) == Ed2kSourceEx2ParseTruncated;
}

static bool test_answer_unsupported_version()
{
	std::array<BYTE, 19> pkt = {};
	pkt[0] = 9;
	BYTE ver = 0;
	WORD count = 0;
	DWORD recLen = 0;
	return Ed2kSourceEx2ParseAnswerHeader(pkt.data(), (DWORD)pkt.size(), &ver, pkt.data() + 1, &count, &recLen) == Ed2kSourceEx2ParseUnsupportedVersion;
}

static bool test_answer_trailing_bytes_rejected()
{
	BYTE hash[16];
	fill_synthetic_hash(hash);
	std::array<BYTE, 20> pkt = {};
	build_answer_packet(pkt.data(), 19, 2, hash, 0, NULL, 0);
	pkt[19] = 0xFF;

	BYTE ver = 0;
	WORD count = 0;
	DWORD recLen = 0;
	return Ed2kSourceEx2ParseAnswerHeader(pkt.data(), (DWORD)pkt.size(), &ver, hash, &count, &recLen) == Ed2kSourceEx2ParseTrailingBytes;
}

static bool test_record_sizes()
{
	return Ed2kSourceEx2AnswerRecordBytes(1) == 12u && Ed2kSourceEx2AnswerRecordBytes(2) == 28u && Ed2kSourceEx2AnswerRecordBytes(3) == 28u && Ed2kSourceEx2AnswerRecordBytes(4) == 29u && Ed2kSourceEx2AnswerRecordBytes(0) == 0u && Ed2kSourceEx2AnswerRecordBytes(9) == 0u;
}

static bool test_opcode_0x83_request_length()
{
	BYTE hash[16];
	fill_synthetic_hash(hash);
	std::array<BYTE, 19> buf = {};
	return Ed2kSourceEx2WriteRequest(buf.data(), (DWORD)buf.size(), ED2K_SOURCEEXCHANGE2_VERSION, 0, hash) == 19u;
}

static bool test_answer_golden_header_layout_v2()
{
	static const BYTE kHash[16] = {
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
	};
	static const BYTE kExpectedPrefix[19] = {
		2,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
		0x01, 0x00
	};

	std::array<BYTE, 28> rec = {};
	memset(rec.data(), 0xAA, 28);
	std::array<BYTE, 64> pkt = {};
	const DWORD nLen = build_answer_packet(pkt.data(), (DWORD)pkt.size(), 2, kHash, 1, rec.data(), 28);
	return nLen == 47 && memcmp(pkt.data(), kExpectedPrefix, 19) == 0;
}

// Exercises the shared production header writer after records-first prefix insertion.
static bool test_answer_edclient_safe_prefix_insert()
{
	std::array<BYTE, 512> records = {};
	const WORD nSources = 15;
	const DWORD nRecordBytes = 12u;
	memset(records.data(), 0xCC, nSources * nRecordBytes);

	std::vector<BYTE> body(records.begin(), records.begin() + nSources * nRecordBytes);
	const DWORD nPrefix = Ed2kSourceEx2AnswerHeaderMinBytes();
	body.insert(body.begin(), nPrefix, 0);

	BYTE hash[16];
	fill_synthetic_hash(hash);
	if (!Ed2kSourceEx2WriteAnswerHeader(
			body.data(), nPrefix, 1, hash, nSources))
		return false;

	BYTE ver = 0;
	WORD count = 0;
	DWORD recLen = 0;
	return Ed2kSourceEx2ParseAnswerHeader(body.data(), (DWORD)body.size(), &ver, hash, &count, &recLen) == Ed2kSourceEx2ParseOk && ver == 1 && count == nSources && recLen == nSources * nRecordBytes && body[0] == 1;
}

static bool test_validate_source_body_overflow()
{
	return Ed2kValidateSourcePacketBody(100, 20, 12) == FALSE;
}

void register_ed2k_sourceex2_golden_tests(TestSuite& suite)
{
	suite.add_test("ed2k_sx2_request_v4_roundtrip", test_request_v4_roundtrip);
	suite.add_test("ed2k_sx2_request_versions_1_4", test_request_versions_1_to_4);
	suite.add_test("ed2k_sx2_request_preferred_v4", test_request_preferred_version);
	suite.add_test("ed2k_sx2_request_version_zero", test_request_version_zero);
	suite.add_test("ed2k_sx2_request_unsupported_version", test_request_unsupported_version);
	suite.add_test("ed2k_sx2_request_truncated_empty", test_request_truncated_empty);
	suite.add_test("ed2k_sx2_request_truncated_options", test_request_truncated_options);
	suite.add_test("ed2k_sx2_request_truncated_hash", test_request_truncated_hash);
	suite.add_test("ed2k_sx2_request_trailing_policy", test_request_trailing_bytes_policy);
	suite.add_test("ed2k_sx2_legacy_envy_22", test_legacy_envy_request_detected_22);
	suite.add_test("ed2k_sx2_legacy_envy_26", test_legacy_envy_request_detected_26);
	suite.add_test("ed2k_sx2_standard_not_legacy", test_standard_request_not_legacy_hash_byte16);
	suite.add_test("ed2k_sx2_request_len_18_reject", test_request_exact_length_18_rejected);
	suite.add_test("ed2k_sx2_request_len_20_reject", test_request_exact_length_20_rejected);
	suite.add_test("ed2k_sx2_version_negotiation", test_request_version_negotiation);
	suite.add_test("ed2k_sx2_emule_golden_request", test_emule_standalone_golden_request);
	suite.add_test("ed2k_sx2_answer_v1_source", test_answer_v1_single_source);
	suite.add_test("ed2k_sx2_answer_v2_source", test_answer_v2_single_source);
	suite.add_test("ed2k_sx2_answer_v3_source", test_answer_v3_single_source);
	suite.add_test("ed2k_sx2_answer_v4_crypt", test_answer_v4_crypt_byte);
	suite.add_test("ed2k_sx2_answer_v4_crypt_reserved", test_answer_v4_crypt_reserved_bits_parsed_only);
	suite.add_test("ed2k_sx2_answer_zero_sources", test_answer_zero_sources);
	suite.add_test("ed2k_sx2_answer_multi_v2", test_answer_multiple_sources_v2);
	suite.add_test("ed2k_sx2_answer_count_overflow", test_answer_count_overflow);
	suite.add_test("ed2k_sx2_answer_golden_header_v2", test_answer_golden_header_layout_v2);
	suite.add_test("ed2k_sx2_answer_safe_prefix_insert", test_answer_edclient_safe_prefix_insert);
	suite.add_test("ed2k_sx2_answer_count_mul_overflow", test_answer_count_mul_overflow);
	suite.add_test("ed2k_sx2_answer_count_mul_guard", test_answer_count_mul_guard);
	suite.add_test("ed2k_sx2_answer_truncated_header", test_answer_truncated_header);
	suite.add_test("ed2k_sx2_answer_unsupported_version", test_answer_unsupported_version);
	suite.add_test("ed2k_sx2_answer_trailing_rejected", test_answer_trailing_bytes_rejected);
	suite.add_test("ed2k_sx2_record_sizes", test_record_sizes);
	suite.add_test("ed2k_sx2_opcode_0x83_length_19", test_opcode_0x83_request_length);
	suite.add_test("ed2k_sx2_validate_body_overflow", test_validate_source_body_overflow);
}
