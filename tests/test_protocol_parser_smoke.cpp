//
// test_protocol_parser_smoke.cpp
//
// In-memory smoke tests for ED2K Source Exchange packet boundary checks
// and inbound packet length / underflow guards. No live network.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/EDSourcePacketValidate.h"
#include "../Envy/PacketLengthValidate.h"

static bool test_source_body_valid_exact()
{
	const DWORD nSourceSize = Ed2kSourceEx2SourceRecordBytes();
	const DWORD nCount = 2;
	const DWORD nRemaining = nCount * nSourceSize;
	return Ed2kValidateSourcePacketBody( nRemaining, nCount, nSourceSize ) == TRUE;
}

static bool test_source_body_valid_empty()
{
	const DWORD nSourceSize = Ed2kSourceEx2SourceRecordBytes();
	return Ed2kValidateSourcePacketBody( 0, 0, nSourceSize ) == TRUE;
}

static bool test_source_body_truncated()
{
	const DWORD nSourceSize = Ed2kSourceEx2SourceRecordBytes();
	return Ed2kValidateSourcePacketBody( nSourceSize, 2, nSourceSize ) == FALSE;
}

static bool test_source_body_count_overflow()
{
	const DWORD nSourceSize = 12u;
	return Ed2kValidateSourcePacketBody( 100, 20, nSourceSize ) == FALSE;
}

static bool test_source_body_zero_record_size()
{
	return Ed2kValidateSourcePacketBody( 100, 1, 0 ) == FALSE;
}

static bool test_source_ex2_request_min_header()
{
	return Ed2kSourceEx2RequestMinBytes() == 22u;
}

static bool test_source_ex2_answer_min_header()
{
	return Ed2kSourceEx2AnswerMinBytes() == 18u;
}

static bool test_source_ex2_legacy_high32_consumed()
{
	const DWORD nRemainingAfterLow = 6;
	return Ed2kSourceEx2LegacyHigh32Bytes( 0, nRemainingAfterLow ) == 4u;
}

static bool test_source_ex2_legacy_high32_skipped_short()
{
	return Ed2kSourceEx2LegacyHigh32Bytes( 0, 5 ) == 0u;
}

static bool test_source_ex2_legacy_high32_skipped_nonzero_low()
{
	return Ed2kSourceEx2LegacyHigh32Bytes( 1024, 10 ) == 0u;
}

static bool test_source_ex2_options_tail_present()
{
	const DWORD nRemaining = 4 + 2;
	const DWORD nLegacy = Ed2kSourceEx2LegacyHigh32Bytes( 0, 6 );
	return Ed2kSourceEx2HasOptionsBytes( nRemaining - nLegacy ) == TRUE;
}

static bool test_source_ex2_options_tail_missing()
{
	return Ed2kSourceEx2HasOptionsBytes( 1 ) == FALSE;
}

static bool test_source_ex2_answer_malformed_count()
{
	const DWORD nSourceSize = Ed2kSourceEx2SourceRecordBytes();
	return Ed2kValidateSourcePacketBody( nSourceSize - 1, 1, nSourceSize ) == FALSE;
}

// --- Packet length / underflow guards (PR #69 restore) ---

static constexpr DWORD kEd2kTcpHeaderSize = 1u + 4u + 1u;	// protocol + length + type

static bool test_ed2k_readbuffer_length_zero()
{
	// nLength == 0 would make "nLength - 1" underflow before New()/Remove().
	return Ed2kTcpPacketLengthOk( kEd2kTcpHeaderSize, kEd2kTcpHeaderSize, 0 ) == FALSE;
}

static bool test_ed2k_readbuffer_length_one_empty_body()
{
	// nLength == 1 is type-only (valid minimal packet); no extra body bytes needed.
	return Ed2kTcpPacketLengthOk( kEd2kTcpHeaderSize, kEd2kTcpHeaderSize, 1 ) == TRUE;
}

static bool test_ed2k_readbuffer_length_exceeds_buffer()
{
	// Declares 10 body bytes beyond the type but buffer has none after the header.
	return Ed2kTcpPacketLengthOk( kEd2kTcpHeaderSize, kEd2kTcpHeaderSize, 11 ) == FALSE;
}

static bool test_ed2k_readbuffer_length_valid_body()
{
	const DWORD nBody = 4;
	const DWORD nBuf = kEd2kTcpHeaderSize + nBody;
	return Ed2kTcpPacketLengthOk( nBuf, kEd2kTcpHeaderSize, 1 + nBody ) == TRUE;
}

static bool test_bt_true_keepalive_length_zero()
{
	// Wire keep-alive is length-prefix 0 only — not an extension frame.
	return BtIsKeepAliveLength( 0 ) == TRUE
		&& BtExtensionPayloadLengthOk( 0 ) == FALSE;
}

static bool test_bt_extension_length_one_not_keepalive()
{
	// length 1 may be a normal single-id message, but as a BEP-10 extension
	// it is malformed (missing extended id). It must not be treated as keep-alive.
	return BtIsKeepAliveLength( 1 ) == FALSE
		&& BtExtensionPayloadLengthOk( 1 ) == FALSE;
}

static bool test_bt_extension_length_min_valid()
{
	// BT id + extension id; empty bencode payload is allowed (length 2).
	return BtIsKeepAliveLength( 2 ) == FALSE
		&& BtExtensionPayloadLengthOk( 2 ) == TRUE;
}

static bool test_bt_extension_length_with_bencode()
{
	return BtExtensionPayloadLengthOk( 2 + 5 ) == TRUE;	// e.g. "d1:ae"
}

static bool test_g1_deflate_truncated_marker_only()
{
	return G1QueryHitDeflateXmlLengthOk( 9 ) == FALSE;
}

static bool test_g1_deflate_marker_no_payload()
{
	// Exactly 10 bytes: marker + one trailing byte still fails "> 10".
	return G1QueryHitDeflateXmlLengthOk( 10 ) == FALSE;
}

static bool test_g1_deflate_min_compressed_byte()
{
	return G1QueryHitDeflateXmlLengthOk( 11 ) == TRUE;
}

static bool test_ggep_h_length_zero()
{
	return GgepItemHasTypeByte( nullptr, 0 ) == FALSE;
}

static bool test_ggep_m_length_zero()
{
	BYTE empty = 0;
	(void)empty;
	return GgepItemHasTypeByte( nullptr, 0 ) == FALSE;
}

static bool test_ggep_h_valid_type_byte()
{
	const BYTE type = 0x01;	// GGEP_H_SHA1 style type byte present
	return GgepItemHasTypeByte( &type, 1 ) == TRUE;
}

static bool test_ggep_h_valid_sha1_sized()
{
	BYTE buf[ 21 ] = {};
	buf[ 0 ] = 0x01;
	return GgepItemHasTypeByte( buf, 21 ) == TRUE;
}

static bool test_ed2k_preview_normal_frame()
{
	return Ed2kPreviewFrameFits( 100, 100 ) == TRUE;
}

static bool test_ed2k_preview_frame_exceeds_remaining()
{
	return Ed2kPreviewFrameFits( 101, 100 ) == FALSE;
}

static bool test_ed2k_preview_frame_high_bit()
{
	// Signed cast would make this negative and bypass a "< (int)" check.
	return Ed2kPreviewFrameFits( 0x80000000u, 64 ) == FALSE;
}

static bool test_ed2k_preview_frame_max_uint_vs_zero()
{
	return Ed2kPreviewFrameFits( 0xFFFFFFFFu, 0 ) == FALSE;
}

void register_protocol_parser_smoke_tests(TestSuite& suite)
{
	suite.add_test( "ed2k_source_body_exact_fit", test_source_body_valid_exact );
	suite.add_test( "ed2k_source_body_empty", test_source_body_valid_empty );
	suite.add_test( "ed2k_source_body_truncated", test_source_body_truncated );
	suite.add_test( "ed2k_source_body_count_overflow", test_source_body_count_overflow );
	suite.add_test( "ed2k_source_body_zero_record", test_source_body_zero_record_size );
	suite.add_test( "ed2k_source_ex2_request_min_header", test_source_ex2_request_min_header );
	suite.add_test( "ed2k_source_ex2_answer_min_header", test_source_ex2_answer_min_header );
	suite.add_test( "ed2k_source_ex2_legacy_high32", test_source_ex2_legacy_high32_consumed );
	suite.add_test( "ed2k_source_ex2_legacy_skip_short", test_source_ex2_legacy_high32_skipped_short );
	suite.add_test( "ed2k_source_ex2_legacy_skip_nonzero", test_source_ex2_legacy_high32_skipped_nonzero_low );
	suite.add_test( "ed2k_source_ex2_options_present", test_source_ex2_options_tail_present );
	suite.add_test( "ed2k_source_ex2_options_missing", test_source_ex2_options_tail_missing );
	suite.add_test( "ed2k_source_ex2_answer_truncated", test_source_ex2_answer_malformed_count );

	suite.add_test( "ed2k_readbuffer_length_zero", test_ed2k_readbuffer_length_zero );
	suite.add_test( "ed2k_readbuffer_length_one", test_ed2k_readbuffer_length_one_empty_body );
	suite.add_test( "ed2k_readbuffer_exceeds_buffer", test_ed2k_readbuffer_length_exceeds_buffer );
	suite.add_test( "ed2k_readbuffer_valid_body", test_ed2k_readbuffer_length_valid_body );

	suite.add_test( "bt_true_keepalive_length_zero", test_bt_true_keepalive_length_zero );
	suite.add_test( "bt_extension_length_one_not_keepalive", test_bt_extension_length_one_not_keepalive );
	suite.add_test( "bt_extension_length_min_valid", test_bt_extension_length_min_valid );
	suite.add_test( "bt_extension_length_bencode", test_bt_extension_length_with_bencode );

	suite.add_test( "g1_deflate_truncated_marker", test_g1_deflate_truncated_marker_only );
	suite.add_test( "g1_deflate_marker_no_payload", test_g1_deflate_marker_no_payload );
	suite.add_test( "g1_deflate_min_payload", test_g1_deflate_min_compressed_byte );

	suite.add_test( "ggep_h_length_zero", test_ggep_h_length_zero );
	suite.add_test( "ggep_m_length_zero", test_ggep_m_length_zero );
	suite.add_test( "ggep_h_type_byte_present", test_ggep_h_valid_type_byte );
	suite.add_test( "ggep_h_sha1_sized", test_ggep_h_valid_sha1_sized );

	suite.add_test( "ed2k_preview_frame_exact", test_ed2k_preview_normal_frame );
	suite.add_test( "ed2k_preview_frame_too_large", test_ed2k_preview_frame_exceeds_remaining );
	suite.add_test( "ed2k_preview_frame_high_bit", test_ed2k_preview_frame_high_bit );
	suite.add_test( "ed2k_preview_frame_max_uint", test_ed2k_preview_frame_max_uint_vs_zero );
}
