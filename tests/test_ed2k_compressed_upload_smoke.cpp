//
// test_ed2k_compressed_upload_smoke.cpp
//
// Deterministic regression tests for ED2K COMPRESSEDPART send-side helpers
// (#87 compressed upload). No live network / MFC upload path.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/Ed2kCompressedUpload.h"
#include "../Envy/PacketLengthValidate.h"

#include <array>
#include <cstring>
#include <vector>

static bool test_peer_without_compression()
{
	return Ed2kPeerSupportsCompressedUpload(0) == FALSE && Ed2kShouldAttemptCompressedUpload(0, 0, 1024) == FALSE && Ed2kUncompressedUploadOpcode(FALSE) == ED2K_C2C_SENDINGPART;
}

static bool test_peer_with_compression_version()
{
	return Ed2kPeerSupportsCompressedUpload(1) == TRUE && Ed2kPeerSupportsCompressedUpload(2) == FALSE && Ed2kShouldAttemptCompressedUpload(1, 0, 1024) == TRUE;
}

static bool test_zero_length_rejected()
{
	return Ed2kCompressedUploadSourceRangeOk(0, 0) == FALSE && Ed2kShouldAttemptCompressedUpload(1, 100, 0) == FALSE && Ed2kCompressedUploadEndOk(0, 0, nullptr) == FALSE;
}

static bool test_offset_plus_length_overflow()
{
	Ed2kUploadOffset nEnd = 0;
	const Ed2kUploadOffset nStart = ~Ed2kUploadOffset(0) - 10ull;
	return Ed2kCompressedUploadEndOk(nStart, 20, &nEnd) == FALSE && Ed2kCompressedUploadSourceRangeOk(nStart, 20) == FALSE && Ed2kShouldAttemptCompressedUpload(1, nStart, 20) == FALSE;
}

static bool test_normal_32bit_offset()
{
	Ed2kUploadOffset nEnd = 0;
	const BOOL bOk = Ed2kCompressedUploadEndOk(0x1000, 0x200, &nEnd);
	return bOk && nEnd == 0x1200 && Ed2kCompressedUploadNeedsI64(0x1000, nEnd) == FALSE && Ed2kCompressedUploadOpcode(FALSE) == ED2K_C2C_COMPRESSEDPART;
}

static bool test_boundary_offset_near_4g()
{
	// Exclusive end == 0xFFFFFFFF does not need I64; crossing into bit33 does.
	Ed2kUploadOffset nEndFit = 0;
	const BOOL bFit = Ed2kCompressedUploadEndOk(0xFFFFFF00ull, 0xFFull, &nEndFit);
	Ed2kUploadOffset nEndCross = 0;
	const BOOL bCross = Ed2kCompressedUploadEndOk(0xFFFFFF00ull, 0x100ull, &nEndCross);
	return bFit && nEndFit == 0xFFFFFFFFull && Ed2kCompressedUploadNeedsI64(0xFFFFFF00ull, nEndFit) == FALSE && bCross && nEndCross == 0x100000000ull && Ed2kCompressedUploadNeedsI64(0xFFFFFF00ull, nEndCross) == TRUE && Ed2kCompressedUploadOpcode(TRUE) == ED2K_C2C_COMPRESSEDPART_I64;
}

static bool test_offset_requires_i64()
{
	Ed2kUploadOffset nEnd = 0;
	const Ed2kUploadOffset nStart = 0x100000000ull;
	return Ed2kCompressedUploadEndOk(nStart, 1024, &nEnd) && Ed2kCompressedUploadNeedsI64(nStart, nEnd) == TRUE && Ed2kCompressedUploadOpcode(TRUE) == ED2K_C2C_COMPRESSEDPART_I64 && Ed2kUncompressedUploadOpcode(TRUE) == ED2K_C2C_SENDINGPART_I64;
}

static bool test_no_accidental_i64_when_32bit_valid()
{
	Ed2kUploadOffset nEnd = 0;
	Ed2kCompressedUploadEndOk(0, 10240, &nEnd);
	return Ed2kCompressedUploadNeedsI64(0, nEnd) == FALSE && Ed2kCompressedUploadHeaderBytes(FALSE) == 24u && Ed2kCompressedUploadHeaderBytes(TRUE) == 28u;
}

static bool test_benefit_policy()
{
	// eMule/aMule: fallback when compressed size >= source size.
	return Ed2kCompressedUploadBeneficial(1000, 999) == TRUE && Ed2kCompressedUploadBeneficial(1000, 1000) == FALSE && Ed2kCompressedUploadBeneficial(1000, 1001) == FALSE && Ed2kCompressedUploadBeneficial(1000, 0) == FALSE;
}

static bool test_peer_support_plus_beneficial_uses_compressed_opcode()
{
	// Peer supports compression + beneficial sizes → COMPRESSEDPART framing.
	return Ed2kShouldAttemptCompressedUpload(1, 0, 4096) == TRUE && Ed2kCompressedUploadBeneficial(4096, 1200) == TRUE && Ed2kCompressedUploadOpcode(FALSE) == ED2K_C2C_COMPRESSEDPART;
}

static bool test_peer_support_incompressible_uses_sendingpart()
{
	// Peer supports compression but data not beneficial → SENDINGPART.
	return Ed2kShouldAttemptCompressedUpload(1, 0, 512) == TRUE && Ed2kCompressedUploadBeneficial(512, 520) == FALSE && Ed2kUncompressedUploadOpcode(FALSE) == ED2K_C2C_SENDINGPART;
}

static bool test_bound_overflow_and_cap()
{
	DWORD nOut = 0;
	return Ed2kCompressedUploadBoundOk(100, 0, &nOut) == FALSE && Ed2kCompressedUploadBoundOk(100, 0x100000000ull, &nOut) == FALSE && Ed2kCompressedUploadBoundOk(0, 400, &nOut) == FALSE && Ed2kCompressedUploadBoundOk(100, 400, &nOut) == TRUE && nOut == 400 && Ed2kCompressedUploadSuggestBound(100, 50, &nOut) == TRUE && nOut == 100 + ED2K_COMPRESSED_UPLOAD_BOUND_SLACK;
}

static bool test_body_size_overflow()
{
	DWORD nBody = 0;
	return Ed2kCompressedUploadBodySizeOk(FALSE, 0, &nBody) == FALSE && Ed2kCompressedUploadBodySizeOk(FALSE, 100, &nBody) == TRUE && nBody == 124 && Ed2kCompressedUploadBodySizeOk(TRUE, 100, &nBody) == TRUE && nBody == 128 && Ed2kCompressedUploadBodySizeOk(FALSE, 0xFFFFFFF0u, &nBody) == FALSE;
}

static bool test_filename_skip_policy()
{
	return Ed2kCompressedUploadFilenameAllows(L"movie.avi") == TRUE && Ed2kCompressedUploadFilenameAllows(L"archive.ZIP") == FALSE && Ed2kCompressedUploadFilenameAllows(L"a.rar") == FALSE && Ed2kCompressedUploadFilenameAllows(L"") == TRUE && Ed2kCompressedUploadFilenameAllows(nullptr) == TRUE;
}

static bool test_payload_credit_last_chunk()
{
	const DWORD nCredit1 = Ed2kCompressedUploadPayloadCredit(50, 100, 200, 0, FALSE);
	const DWORD nCredit2 = Ed2kCompressedUploadPayloadCredit(50, 100, 200, nCredit1, TRUE);
	return nCredit1 == 100 && (nCredit1 + nCredit2) == 200;
}

static bool test_logical_range_preserved_in_header()
{
	std::array<BYTE, 16> hash{};
	for (int i = 0; i < 16; ++i)
		hash[(size_t)i] = (BYTE)(i + 1);

	const BYTE payload[4] = { 0xAA, 0xBB, 0xCC, 0xDD };
	std::array<BYTE, 64> out{};
	const DWORD nWritten = Ed2kWriteCompressedPartBody(
	    out.data(), (DWORD)out.size(), hash.data(),
	    0x12345678ull, 4, payload, 4, FALSE);
	if (nWritten != 28)
		return false;

	DWORD nOff = 0;
	DWORD nComp = 0;
	std::memcpy(&nOff, out.data() + 16, 4);
	std::memcpy(&nComp, out.data() + 20, 4);
	return nOff == 0x12345678u && nComp == 4u && out[24] == 0xAA && std::memcmp(out.data(), hash.data(), 16) == 0;
}

static bool test_golden_wire_compressedpart_i64()
{
	std::array<BYTE, 16> hash{};
	hash.fill(0x11);

	const BYTE payload[3] = { 1, 2, 3 };
	std::array<BYTE, 64> out{};
	const Ed2kUploadOffset nStart = 0x100000005ull;
	const DWORD nWritten = Ed2kWriteCompressedPartBody(
	    out.data(), (DWORD)out.size(), hash.data(),
	    nStart, 3, payload, 3, TRUE);
	if (nWritten != 31)
		return false;

	DWORD nLo = 0, nHi = 0, nComp = 0;
	std::memcpy(&nLo, out.data() + 16, 4);
	std::memcpy(&nHi, out.data() + 20, 4);
	std::memcpy(&nComp, out.data() + 24, 4);
	const Ed2kUploadOffset nRoundTrip =
	    ((Ed2kUploadOffset)nHi << 32) | (Ed2kUploadOffset)nLo;
	return nRoundTrip == nStart && nComp == 3u && out[28] == 1 && Ed2kWriteCompressedPartBody(out.data(), (DWORD)out.size(), hash.data(), nStart, 3, payload, 3, FALSE) == 0; // must not truncate
}

static bool test_compression_failure_means_uncompressed_opcode()
{
	return Ed2kCompressedUploadBeneficial(100, 100) == FALSE && Ed2kUncompressedUploadOpcode(FALSE) == ED2K_C2C_SENDINGPART && Ed2kUncompressedUploadOpcode(TRUE) == ED2K_C2C_SENDINGPART_I64;
}

static bool test_oversized_source_rejected()
{
	const Ed2kUploadOffset nTooBig =
	    (Ed2kUploadOffset)ED2K_COMPRESSED_UPLOAD_SOURCE_MAX + 1ull;
	return Ed2kCompressedUploadSourceRangeOk(0, nTooBig) == FALSE && Ed2kShouldAttemptCompressedUpload(1, 0, nTooBig) == FALSE;
}

static bool test_receive_inflate_caps_intact()
{
	const std::uint64_t nPart = ED2K_COMPRESSEDPART_INFLATE_MAX;
	return Ed2kCompressedPartInflateOk(nPart, nPart) == TRUE && Ed2kCompressedPartInflateOk(nPart + 1, nPart) == FALSE;
}

static bool test_position_advances_by_uncompressed()
{
	// Documented contract: credit/source accounting uses uncompressed length,
	// not wire chunk size (eMule payloadSize approximation uses source total).
	const DWORD nSource = 10000;
	const DWORD nComp = 2000;
	const DWORD nWire1 = 1000;
	const DWORD nWire2 = 1000;
	const DWORD c1 = Ed2kCompressedUploadPayloadCredit(nWire1, nComp, nSource, 0, FALSE);
	const DWORD c2 = Ed2kCompressedUploadPayloadCredit(nWire2, nComp, nSource, c1, TRUE);
	return (c1 + c2) == nSource && c1 + c2 != nComp;
}

static bool test_wire_chunk_split_helper()
{
	return Ed2kCompressedUploadWireChunkSize(500) == 500 && Ed2kCompressedUploadWireChunkSize(0) == 0 && Ed2kCompressedUploadWireChunkSize(20480) == 10240;
}

void register_ed2k_compressed_upload_smoke_tests(TestSuite& suite)
{
	suite.add_test("ed2k_cpart_peer_without_comp", test_peer_without_compression);
	suite.add_test("ed2k_cpart_peer_with_comp", test_peer_with_compression_version);
	suite.add_test("ed2k_cpart_zero_length", test_zero_length_rejected);
	suite.add_test("ed2k_cpart_offset_overflow", test_offset_plus_length_overflow);
	suite.add_test("ed2k_cpart_32bit_offset", test_normal_32bit_offset);
	suite.add_test("ed2k_cpart_boundary_4g", test_boundary_offset_near_4g);
	suite.add_test("ed2k_cpart_i64_offset", test_offset_requires_i64);
	suite.add_test("ed2k_cpart_no_accidental_i64", test_no_accidental_i64_when_32bit_valid);
	suite.add_test("ed2k_cpart_benefit_policy", test_benefit_policy);
	suite.add_test("ed2k_cpart_beneficial_opcode", test_peer_support_plus_beneficial_uses_compressed_opcode);
	suite.add_test("ed2k_cpart_incompressible_opcode", test_peer_support_incompressible_uses_sendingpart);
	suite.add_test("ed2k_cpart_bound_overflow", test_bound_overflow_and_cap);
	suite.add_test("ed2k_cpart_body_size", test_body_size_overflow);
	suite.add_test("ed2k_cpart_filename_skip", test_filename_skip_policy);
	suite.add_test("ed2k_cpart_payload_credit", test_payload_credit_last_chunk);
	suite.add_test("ed2k_cpart_logical_range_header", test_logical_range_preserved_in_header);
	suite.add_test("ed2k_cpart_golden_i64_wire", test_golden_wire_compressedpart_i64);
	suite.add_test("ed2k_cpart_compress_fail_fallback", test_compression_failure_means_uncompressed_opcode);
	suite.add_test("ed2k_cpart_oversized_source", test_oversized_source_rejected);
	suite.add_test("ed2k_cpart_receive_caps_intact", test_receive_inflate_caps_intact);
	suite.add_test("ed2k_cpart_pos_uncompressed", test_position_advances_by_uncompressed);
	suite.add_test("ed2k_cpart_wire_chunk", test_wire_chunk_split_helper);
}
