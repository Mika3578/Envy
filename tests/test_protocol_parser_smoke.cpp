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

#include <array>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>

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

static bool test_bt_packet_length_ok()
{
	return BtPacketLengthOk(1) == TRUE && BtPacketLengthOk(BT_PACKET_LENGTH_MAX) == TRUE && BtPacketLengthOk(0) == FALSE && BtPacketLengthOk(BT_PACKET_LENGTH_MAX + 1) == FALSE;
}

static bool test_g2_subpacket_payload_fits()
{
	return G2SubpacketPayloadFits(100, 50, 8) == TRUE && G2SubpacketPayloadFits(100, 100, 0) == TRUE && G2SubpacketPayloadFits(100, 101, 0) == FALSE && G2SubpacketPayloadFits(100, 50, 51) == FALSE && G2SubpacketPayloadFits(100, 0xFFFFFFFA, 8) == FALSE;
}

static bool test_g2_frame_length_fits()
{
	// Exact frame = body + nLenLen + nTypeLen + 2 (control + type-len adjust).
	return G2FrameLengthFits(64, 50, 1, 3) == TRUE && G2FrameLengthFits(106, 100, 1, 3) == TRUE &&
	       G2FrameLengthFits(105, 100, 1, 3) == FALSE && G2FrameLengthFits(10, 0xFFFFFFF0, 1, 3) == FALSE &&
	       G2FrameLengthFits(104, 100, 1, 3) == FALSE && G2FrameLengthFits(100, 50, 0xFFFFFFF0, 3) == FALSE;
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

static bool test_g1_deflate_xml_inflate_ok()
{
	return G1DeflateXmlInflateOk( 1 ) == TRUE
		&& G1DeflateXmlInflateOk( G1_DEFLATE_XML_INFLATE_MAX ) == TRUE
		&& G1DeflateXmlInflateOk( 0 ) == FALSE
		&& G1DeflateXmlInflateOk( G1_DEFLATE_XML_INFLATE_MAX + 1 ) == FALSE;
}

static bool test_g1_packet_total_length_ok()
{
	const DWORD nMax = 64u * 1024u;
	return G1PacketTotalLengthOk( 0, nMax ) == TRUE
		&& G1PacketTotalLengthOk( -1, nMax ) == FALSE
		&& G1PacketTotalLengthOk( -16, nMax ) == FALSE
		&& G1PacketTotalLengthOk( static_cast< LONG >( nMax - G1_PACKET_HEADER_BYTES - 1 ), nMax ) == TRUE
		&& G1PacketTotalLengthOk( static_cast< LONG >( nMax - G1_PACKET_HEADER_BYTES ), nMax ) == FALSE
		&& G1PacketTotalLengthOk( 1, G1_PACKET_HEADER_BYTES ) == FALSE
		&& G1PacketTotalLengthOk( 0x7FFFFFFFL, nMax ) == FALSE
		&& G1PacketTotalLength( 10 ) == G1_PACKET_HEADER_BYTES + 10;
}

static bool test_g1_queryhit_xml_fits_exact()
{
	static_assert(G1_QUERYHIT_GUID_BYTES == 16u, "G1 QueryHit trailer GUID is 16 bytes");
	return G1QueryHitXmlFits(10, 16u + 10) == TRUE;
}

static bool test_g1_queryhit_xml_fits_zero()
{
	// Zero-length XML still requires the trailing 16-byte GUID.
	return G1QueryHitXmlFits(0, 0) == FALSE && G1QueryHitXmlFits(0, 15u) == FALSE && G1QueryHitXmlFits(0, 16u) == TRUE;
}

static bool test_g1_queryhit_xml_oversized()
{
	return G1QueryHitXmlFits(10, 16u + 9) == FALSE && G1QueryHitXmlFits(1, 16u) == FALSE && G1QueryHitXmlFits(1, 15u) == FALSE;
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

static bool test_bencode_depth_ok_zero()
{
	return BencodeDepthOk( 0 ) == TRUE;
}

static bool test_bencode_depth_ok_max()
{
	return BencodeDepthOk( BENODE_MAX_DEPTH ) == TRUE;
}

static bool test_bencode_depth_over_max()
{
	return BencodeDepthOk( BENODE_MAX_DEPTH + 1 ) == FALSE;
}

static bool test_parse_int64_bounded_normal()
{
	__int64 n = 0;
	return ParseInt64Bounded( "12345", 5, n ) == TRUE && n == 12345;
}

static bool test_parse_int64_bounded_negative()
{
	__int64 n = 0;
	return ParseInt64Bounded( "-42", 3, n ) == TRUE && n == -42;
}

static bool test_parse_int64_bounded_overflow()
{
	__int64 n = 0;
	// 20 digits > INT64_MAX
	return ParseInt64Bounded( "99999999999999999999", 20, n ) == FALSE;
}

static bool test_parse_int64_bounded_min()
{
	__int64 n = 0;
	return ParseInt64Bounded( "-9223372036854775808", 20, n ) == TRUE && n == INT64_MIN;
}

static bool test_ed2k_preview_acceptable_normal()
{
	return Ed2kPreviewFrameAcceptable( 100, 100 ) == TRUE;
}

static bool test_ed2k_preview_acceptable_zero()
{
	return Ed2kPreviewFrameAcceptable( 0, 100 ) == FALSE;
}

static bool test_ed2k_preview_acceptable_over_cap()
{
	return Ed2kPreviewFrameAcceptable( ED2K_PREVIEW_FRAME_MAX + 1, ED2K_PREVIEW_FRAME_MAX + 1 ) == FALSE;
}

static bool test_ed2k_preview_acceptable_at_cap()
{
	return Ed2kPreviewFrameAcceptable( ED2K_PREVIEW_FRAME_MAX, ED2K_PREVIEW_FRAME_MAX ) == TRUE;
}

static bool test_ed2k_tag_blob_bounds()
{
	return Ed2kTagBlobLengthOk( 100, 100 ) == TRUE
		&& Ed2kTagBlobLengthOk( 101, 100 ) == FALSE
		&& Ed2kTagBlobLengthOk( ED2K_TAG_BLOB_MAX + 1, ED2K_TAG_BLOB_MAX + 1 ) == FALSE
		&& Ed2kTagBlobLengthOk( 0, 0 ) == TRUE;
}

static bool test_ed2k_tag_string_bounds()
{
	return Ed2kTagStringLengthOk( 100, 100 ) == TRUE
		&& Ed2kTagStringLengthOk( 101, 100 ) == FALSE
		&& Ed2kTagStringLengthOk( ED2K_TAG_STRING_MAX, ED2K_TAG_STRING_MAX ) == TRUE
		&& Ed2kTagStringLengthOk( ED2K_TAG_STRING_MAX + 1, ED2K_TAG_STRING_MAX + 1 ) == FALSE
		&& Ed2kTagStringLengthOk( 0, 0 ) == TRUE;
}

static bool test_ed2k_unknown_tag_string_skip()
{
	// MAX itself is a valid STRING skip when remaining fits; only MAX+1 falls to INT path.
	return Ed2kUnknownTagStringSkipOk( 100u, 100ull ) == TRUE
		&& Ed2kUnknownTagStringSkipOk( 0u, 0ull ) == TRUE
		&& Ed2kUnknownTagStringSkipOk( 101u, 100ull ) == FALSE
		&& Ed2kUnknownTagStringSkipOk( ED2K_UNKNOWN_TAG_STRING_SKIP_MAX, ED2K_UNKNOWN_TAG_STRING_SKIP_MAX ) == TRUE
		&& Ed2kUnknownTagStringSkipOk( ED2K_UNKNOWN_TAG_STRING_SKIP_MAX + 1u, ED2K_UNKNOWN_TAG_STRING_SKIP_MAX + 1ull ) == FALSE
		&& Ed2kUnknownTagStringSkipOk( ED2K_UNKNOWN_TAG_STRING_SKIP_MAX, ED2K_UNKNOWN_TAG_STRING_SKIP_MAX - 1ull ) == FALSE;
}

static bool test_ed2k_file_comment_bounds()
{
	return Ed2kFileCommentHeaderFits(5) == TRUE
		&& Ed2kFileCommentHeaderFits(4) == FALSE
		&& Ed2kFileCommentLengthOk(0, 0) == TRUE
		&& Ed2kFileCommentLengthOk(10, 10) == TRUE
		&& Ed2kFileCommentLengthOk(11, 10) == FALSE
		&& Ed2kFileCommentLengthOk(ED2K_FILE_COMMENT_MAX, ED2K_FILE_COMMENT_MAX) == TRUE
		&& Ed2kFileCommentLengthOk(ED2K_FILE_COMMENT_MAX + 1, ED2K_FILE_COMMENT_MAX + 1) == FALSE;
}

static bool test_ed2k_ed_string_header()
{
	return Ed2kEdStringHeaderOk(2) == TRUE && Ed2kEdStringHeaderOk(1) == FALSE && Ed2kEdStringHeaderOk(0) == FALSE;
}

static bool test_ed2k_ed_string_payload()
{
	// Mirrors ReadEDString after ReadShortLE: Ed2kEdStringPayloadOk(nLen, remaining).
	return Ed2kEdStringPayloadOk( 5, 5 ) == TRUE
		&& Ed2kEdStringPayloadOk( 0, 5 ) == TRUE
		&& Ed2kEdStringPayloadOk( 6, 5 ) == FALSE
		&& Ed2kEdStringPayloadOk( 0, 0 ) == TRUE
		&& Ed2kEdStringPayloadOk( 1, 0 ) == FALSE;
}

static bool test_ed2k_long_ed_string_payload()
{
	// Mirrors ReadLongEDString after ReadLongLE: Ed2kLongEdStringPayloadOk(nLen, remaining).
	return Ed2kLongEdStringPayloadOk( 100, 100 ) == TRUE
		&& Ed2kLongEdStringPayloadOk( 101, 100 ) == FALSE
		&& Ed2kLongEdStringPayloadOk( 0, 0 ) == TRUE
		&& Ed2kLongEdStringPayloadOk( 1, 0 ) == FALSE;
}

static bool test_ed2k_ed_string_truncated_prefix_gate()
{
	// Simulate a WORD-prefixed string claiming 4 bytes when only 3 remain after the prefix.
	const WORD nClaimed = 4;
	const DWORD nRemainingAfterPrefix = 3;
	const bool bWouldThrow = Ed2kEdStringPayloadOk( nClaimed, nRemainingAfterPrefix ) == FALSE;
	const bool bExactOk = Ed2kEdStringPayloadOk( 3, 3 ) == TRUE;
	const DWORD nLongClaimed = 8;
	const DWORD nLongRemaining = 7;
	const bool bLongWouldThrow = Ed2kLongEdStringPayloadOk( nLongClaimed, nLongRemaining ) == FALSE;
	return bWouldThrow && bExactOk && bLongWouldThrow;
}

static bool test_ed2k_server_message_length()
{
	return Ed2kServerMessageLengthOk(0) == TRUE && Ed2kServerMessageLengthOk(ED2K_SERVER_MESSAGE_MAX) == TRUE && Ed2kServerMessageLengthOk(static_cast<WORD>(ED2K_SERVER_MESSAGE_MAX + 1)) == FALSE;
}

static bool test_ed2k_tag_uint64_remaining()
{
	return Ed2kTagUint64RemainingOk( ED2K_TAG_UINT64_BYTES ) == TRUE
		&& Ed2kTagUint64RemainingOk( ED2K_TAG_UINT64_BYTES + 1 ) == TRUE
		&& Ed2kTagUint64RemainingOk( ED2K_TAG_UINT64_BYTES - 1 ) == FALSE
		&& Ed2kTagUint64RemainingOk( 0 ) == FALSE
		&& Ed2kTagUint64RemainingOk( 1 ) == FALSE;
}

static bool test_ed2k_hashset_payload_bounds()
{
	const DWORD nExact = 3 * ED2K_HASHSET_DIGEST_BYTES;
	return Ed2kHashsetPayloadFits( 3, nExact ) == TRUE
		&& Ed2kHashsetPayloadFits( 3, nExact - 1 ) == FALSE
		&& Ed2kHashsetPayloadFits( 3, nExact + 1 ) == FALSE;
}

static bool test_ed2k_chat_message_bounds()
{
	return Ed2kChatMessageLengthOk( 1, 1 ) == TRUE
		&& Ed2kChatMessageLengthOk( 0, 0 ) == FALSE
		&& Ed2kChatMessageLengthOk( ED2K_CHAT_MESSAGE_MAX, ED2K_CHAT_MESSAGE_MAX ) == TRUE
		&& Ed2kChatMessageLengthOk( ED2K_CHAT_MESSAGE_MAX + 1, ED2K_CHAT_MESSAGE_MAX + 1 ) == FALSE
		&& Ed2kChatMessageLengthOk( 10, 11 ) == FALSE
		&& Ed2kChatMessageLengthOk( 10, 9 ) == FALSE;
}


static bool test_bt_ut_metadata_size_ok()
{
	return BtUtMetadataSizeOk( 1024 ) == TRUE;
}

static bool test_bt_ut_metadata_size_zero()
{
	return BtUtMetadataSizeOk( 0 ) == FALSE;
}

static bool test_bt_ut_metadata_size_at_max()
{
	return BtUtMetadataSizeOk( BT_UT_METADATA_MAX ) == TRUE;
}

static bool test_bt_ut_metadata_size_over_max()
{
	return BtUtMetadataSizeOk(BT_UT_METADATA_MAX + 1) == FALSE;
}

static bool test_bt_mse_ia_length_ok()
{
	const BYTE abOk[2] = { 0x00, 0x60 };   // 96 BE
	const BYTE abOver[2] = { 0x00, 0x61 }; // 97 BE
	return BtMseIaLengthOk(0) == TRUE && BtMseIaLengthOk(BT_MSE_IA_MAX) == TRUE && BtMseIaLengthOk(static_cast<WORD>(BT_MSE_IA_MAX + 1)) == FALSE && BtMseBeWordFromWire(abOk) == BT_MSE_IA_MAX && BtMseIaLengthOk(BtMseBeWordFromWire(abOver)) == FALSE;
}


static bool test_kad_store_tag_length_ok()
{
	return KadStoreTagLengthOk(0) == TRUE && KadStoreTagLengthOk(static_cast<WORD>(KAD_STORE_TAG_MAX)) == TRUE && KadStoreTagLengthOk(static_cast<WORD>(KAD_STORE_TAG_MAX + 1)) == FALSE;
}

static bool test_bt_mse_pad_length_ok()
{
	const BYTE abOkMax[2] = { 0x02, 0x00 };    // 512 BE
	const BYTE abOver[2] = { 0x02, 0x01 };     // 513 BE
	const BYTE abHostTrap[2] = { 0x01, 0x02 }; // 258 BE; would be 513 if LE-decoded
	return BtMsePadLengthOk(0) == TRUE && BtMsePadLengthOk(BT_MSE_PAD_MAX) == TRUE && BtMsePadLengthOk(static_cast<WORD>(BT_MSE_PAD_MAX + 1)) == FALSE && BtMsePadWireLengthOk(abOkMax) == TRUE && BtMsePadWireLengthOk(abOver) == FALSE && BtMsePadWireLengthOk(abHostTrap) == TRUE && BtMseBeWordFromWire(abOver) == static_cast<WORD>(BT_MSE_PAD_MAX + 1);
}

static bool test_bt_source_response_no_delete_packet_owned_root()
{
	// Regression: OnSourceResponse must not delete pPacket->m_pNode (double-free),
	// and must null-check GetNode("peers") before IsType.
	const char* candidates[] = {
		"../Envy/DownloadTransferBT.cpp",
		"../../Envy/DownloadTransferBT.cpp",
		"Envy/DownloadTransferBT.cpp",
		"../../../Envy/DownloadTransferBT.cpp"
	};

	std::ifstream in;
	for (const char* path : candidates)
	{
		in.open(path, std::ios::in | std::ios::binary);
		if (in)
			break;
	}
	if (!in)
	{
		// Distinguish missing source from regression failure.
		std::fprintf(stderr, "bt_source_response_no_delete: DownloadTransferBT.cpp not found from CWD\n");
		return false;
	}

	std::string content((std::istreambuf_iterator<char>(in)),
		std::istreambuf_iterator<char>());

	const size_t nFn = content.find("OnSourceResponse");
	if (nFn == std::string::npos)
		return false;

	const size_t nNext = content.find("\nBOOL ", nFn + 1);
	const std::string body = content.substr(nFn,
		(nNext == std::string::npos ? content.size() : nNext) - nFn);

	const bool bNoDelete = body.find("delete pRoot") == std::string::npos;
	const bool bNullPeers = body.find("pPeers == NULL") != std::string::npos
		|| body.find("!pPeers") != std::string::npos;
	return bNoDelete && bNullPeers;
}


static bool test_cbuffer_unbzip_bounds()
{
	constexpr DWORD kMax = 32u * 1024u * 1024u;
	if (CBUFFER_UNBZIP_MAX != kMax)
		return false;
	// Predicates must reject empty, over-cap, and >4 GiB lengths that would
	// wrap if narrowed to DWORD/UINT before the check (loader regression).
	if (CBufferUnBZipOutputOk(1) != TRUE
		|| CBufferUnBZipOutputOk(kMax) != TRUE
		|| CBufferUnBZipOutputOk(kMax + 1) != FALSE
		|| CBufferUnBZipOutputOk(0) != FALSE
		|| CBufferUnBZipInputOk(1) != TRUE
		|| CBufferUnBZipInputOk(kMax) != TRUE
		|| CBufferUnBZipInputOk(kMax + 1) != FALSE
		|| CBufferUnBZipInputOk(0) != FALSE)
		return false;
	if (CBufferUnBZipInputOk(0x100000000ull) != FALSE) // 4 GiB
		return false;
	if (CBufferUnBZipInputOk(0x100000001ull) != FALSE) // would wrap to 1 as DWORD
		return false;
	return true;
}



static bool test_qht_patch_expected_bytes()
{
	return QhtPatchExpectedBytes(1024, 1) == 128
		&& QhtPatchExpectedBytes(1024, 4) == 512
		&& QhtPatchExpectedBytes(1024, 8) == 1024
		&& QhtPatchExpectedBytes(1024, 2) == 0
		&& QhtPatchExpectedBytes(1025, 1) == 0; // not divisible by 8
}

static bool test_qht_patch_compressed_budget()
{
	// 2x + 64 slack: expected=100 => budget=264
	return QhtPatchCompressedBudgetOk(0, 100, 100) == TRUE
		&& QhtPatchCompressedBudgetOk(200, 65, 100) == FALSE // 265 > 264
		&& QhtPatchCompressedBudgetOk(0, 1, 0) == FALSE
		&& QhtPatchCompressedBudgetOk(0, 16, 8) == TRUE // tiny table + zlib slack
		&& QhtPatchCompressedBudgetOk(0, MAXDWORD, MAXDWORD) == TRUE; // MAXDWORD budget branch
}

static bool test_ed2k_packed_inflate_ok()
{
	return Ed2kPackedInflateOk( 1 ) == TRUE
		&& Ed2kPackedInflateOk( ED2K_PACKED_INFLATE_MAX ) == TRUE
		&& Ed2kPackedInflateOk( 0 ) == FALSE
		&& Ed2kPackedInflateOk( ED2K_PACKED_INFLATE_MAX + 1 ) == FALSE;
}

static bool test_bt_tracker_http_response_bounds()
{
	return BtTrackerHttpResponseOk( 1 ) == TRUE
		&& BtTrackerHttpResponseOk( BT_TRACKER_HTTP_RESPONSE_MAX ) == TRUE
		&& BtTrackerHttpResponseOk( BT_TRACKER_HTTP_RESPONSE_MAX + 1 ) == FALSE
		&& BtTrackerHttpResponseOk( 0 ) == FALSE;
}

static bool test_discovery_http_response_bounds()
{
	return DiscoveryHttpResponseOk( 1 ) == TRUE
		&& DiscoveryHttpResponseOk( DISCOVERY_HTTP_RESPONSE_MAX ) == TRUE
		&& DiscoveryHttpResponseOk( DISCOVERY_HTTP_RESPONSE_MAX + 1 ) == FALSE
		&& DiscoveryHttpResponseOk( 0 ) == FALSE;
}

static bool test_host_browser_http_body_bounds()
{
	return HostBrowserHttpBodyOk( 1 ) == TRUE
		&& HostBrowserHttpBodyOk( HOST_BROWSER_HTTP_BODY_MAX ) == TRUE
		&& HostBrowserHttpBodyOk( HOST_BROWSER_HTTP_BODY_MAX + 1 ) == FALSE
		&& HostBrowserHttpBodyOk( 0 ) == FALSE
		&& HostBrowserHttpBodyOk( ~0ull ) == FALSE
		&& HostBrowserHttpBufferOk( 0 ) == TRUE
		&& HostBrowserHttpBufferOk( HOST_BROWSER_HTTP_BODY_MAX ) == TRUE
		&& HostBrowserHttpBufferOk( HOST_BROWSER_HTTP_BODY_MAX + 1 ) == FALSE;
}

static bool test_cbuffer_inflate_output_ok()
{
	return CBufferInflateOutputOk( 1 ) == TRUE
		&& CBufferInflateOutputOk( CBUFFER_INFLATE_MAX ) == TRUE
		&& CBufferInflateOutputOk( 0 ) == FALSE
		&& CBufferInflateOutputOk( CBUFFER_INFLATE_MAX + 1 ) == FALSE;
}

static bool test_cbuffer_inflate_stream_output_ok()
{
	return CBufferInflateStreamOutputOk( 0 ) == TRUE
		&& CBufferInflateStreamOutputOk( CBUFFER_INFLATE_STREAM_MAX ) == TRUE
		&& CBufferInflateStreamOutputOk( CBUFFER_INFLATE_STREAM_MAX + 1 ) == FALSE
		&& CBUFFER_INFLATE_STREAM_MAX == CBUFFER_INFLATE_MAX;
}

static bool test_ggep_inflate_output_ok()
{
	return GgepInflateOutputOk( 1 ) == TRUE
		&& GgepInflateOutputOk( GGEP_INFLATE_MAX ) == TRUE
		&& GgepInflateOutputOk( 0 ) == FALSE
		&& GgepInflateOutputOk( GGEP_INFLATE_MAX + 1 ) == FALSE;
}

static bool test_ed2k_compressedpart_inflate_ok()
{
	const std::uint64_t nPart = ED2K_COMPRESSEDPART_INFLATE_MAX;
	const bool bPred =
		Ed2kCompressedPartInflateOk( 0, nPart ) == TRUE
		&& Ed2kCompressedPartInflateOk( nPart, nPart ) == TRUE
		&& Ed2kCompressedPartInflateOk( nPart + 1, nPart ) == FALSE
		&& Ed2kCompressedPartInflateOk( 100, 50 ) == FALSE;
	// Accounting decision shared by AcceptCompressedPartChunk (EOF => 0).
	const bool bBudget =
		Ed2kCompressedPartInflateBudget( ~0ULL, 0 ) == nPart
		&& Ed2kCompressedPartInflateBudget( nPart, 0 ) == nPart
		&& Ed2kCompressedPartInflateBudget( 100, 40 ) == 60
		&& Ed2kCompressedPartInflateBudget( 100, 100 ) == 0
		&& Ed2kCompressedPartInflateBudget( 100, 101 ) == 0
		&& Ed2kCompressedPartInflateOk( 1, Ed2kCompressedPartInflateBudget( 100, 100 ) ) == FALSE;
	return bPred && bBudget;
}

static bool test_ed2k_compressedpart_accept_before_submit()
{
	// Call-site regression: drain helper gates SubmitData; both handlers call it.
	const std::array<const char*, 4> candidates = {
		"../Envy/DownloadTransferED2K.cpp",
		"../../Envy/DownloadTransferED2K.cpp",
		"Envy/DownloadTransferED2K.cpp",
		"../../../Envy/DownloadTransferED2K.cpp"
	};

	std::ifstream in;
	for ( const char* path : candidates )
	{
		in.open( path, std::ios::in | std::ios::binary );
		if ( in )
			break;
	}
	if ( !in )
		return false;

	std::string content( ( std::istreambuf_iterator<char>( in ) ),
		std::istreambuf_iterator<char>() );

	auto fn_body = [ &content ]( const char* szFn )
	{
		const size_t nFn = content.find( szFn );
		if ( nFn == std::string::npos )
			return std::string();
		const size_t nNext = content.find( "\nBOOL ", nFn + 1 );
		return content.substr( nFn,
			( nNext == std::string::npos ? content.size() : nNext ) - nFn );
	};

	const std::string drain = fn_body( "CDownloadTransferED2K::DrainCompressedPartInflate(" );
	const size_t nAccept = drain.find( "AcceptCompressedPartChunk" );
	const size_t nSubmit = drain.find( "SubmitData" );
	const bool bDrainGates = !drain.empty()
		&& nAccept != std::string::npos
		&& nSubmit != std::string::npos
		&& nAccept < nSubmit;

	const std::string part32 = fn_body( "CDownloadTransferED2K::OnCompressedPart(" );
	const std::string part64 = fn_body( "CDownloadTransferED2K::OnCompressedPart64(" );
	const bool bHandlersCallDrain =
		part32.find( "DrainCompressedPartInflate" ) != std::string::npos
		&& part64.find( "DrainCompressedPartInflate" ) != std::string::npos;

	return bDrainGates && bHandlersCallDrain;
}

static bool test_g1_wrapped_payload_ok()
{
	// G1_PACKET_HEADER_BYTES must match sizeof(GNUTELLAPACKET); enforced by
	// static_asserts in Envy/G1Neighbour.cpp and Envy/G2Packet.cpp.
	return G1WrappedPayloadLengthOk(0) == TRUE && G1WrappedPayloadLengthOk(static_cast<LONG>(G1_WRAPPED_PAYLOAD_MAX)) == TRUE &&
	       G1WrappedPayloadLengthOk(static_cast<LONG>(G1_WRAPPED_PAYLOAD_MAX + 1)) == FALSE && G1WrappedPayloadLengthOk(-1) == FALSE &&
	       G1WrappedPayloadFits(G1_PACKET_HEADER_BYTES + 10, 10) == TRUE && G1WrappedPayloadFits(G1_PACKET_HEADER_BYTES + 9, 10) == FALSE &&
	       G1WrappedPayloadFits(100, -1) == FALSE && G1WrappedPayloadFits(G1_PACKET_HEADER_BYTES - 1, 0) == FALSE &&
	       G1WrappedPayloadFits(G1_PACKET_HEADER_BYTES, 0) == TRUE;
}

static bool test_update_servers_http_response_bounds()
{
	return UpdateServersHttpResponseOk(1) == TRUE && UpdateServersHttpResponseOk(UPDATE_SERVERS_HTTP_RESPONSE_MAX) == TRUE && UpdateServersHttpResponseOk(UPDATE_SERVERS_HTTP_RESPONSE_MAX + 1) == FALSE && UpdateServersHttpResponseOk(0) == FALSE;
}

static bool test_version_checker_http_response_bounds()
{
	return VersionCheckerHttpResponseOk(1) == TRUE && VersionCheckerHttpResponseOk(VERSION_CHECK_HTTP_RESPONSE_MAX) == TRUE && VersionCheckerHttpResponseOk(VERSION_CHECK_HTTP_RESPONSE_MAX + 1) == FALSE && VersionCheckerHttpResponseOk(0) == FALSE;
}

static bool test_bt_compact_peer_list_bytes()
{
	return BtCompactPeerListBytesOk(6) == TRUE && BtCompactPeerListBytesOk(12) == TRUE && BtCompactPeerListBytesOk(0) == FALSE && BtCompactPeerListBytesOk(5) == FALSE && BtCompactPeerListBytesOk(7) == FALSE;
}

static bool test_bt_sources_wanted_allows_more()
{
	return BtSourcesWantedAllowsMore(0, 500) == TRUE && BtSourcesWantedAllowsMore(499, 500) == TRUE && BtSourcesWantedAllowsMore(500, 500) == FALSE && BtSourcesWantedAllowsMore(0, 0) == FALSE;
}

static bool test_g2_sgp_reassembly_bounds()
{
	return G2SgpFragmentCountOk(1) == TRUE && G2SgpFragmentCountOk(G2_SGP_FRAGMENT_MAX) == TRUE && G2SgpFragmentCountOk(0) == FALSE && G2SgpFragmentCountOk(static_cast<BYTE>(G2_SGP_FRAGMENT_MAX + 1)) == FALSE && G2SgpReassembledBytesOk(1) == TRUE && G2SgpReassembledBytesOk(G2_SGP_REASSEMBLED_MAX) == TRUE && G2SgpReassembledBytesOk(0) == FALSE && G2SgpReassembledBytesOk(G2_SGP_REASSEMBLED_MAX + 1) == FALSE && G2SgpEffectiveByteCap(0) == G2_SGP_REASSEMBLED_MAX && G2SgpEffectiveByteCap(G2_SGP_REASSEMBLED_MAX + 1) == G2_SGP_REASSEMBLED_MAX && G2SgpEffectiveByteCap(64u * 1024u) == 64u * 1024u && G2SgpReassembledBytesOk(64u * 1024u, 64u * 1024u) == TRUE && G2SgpReassembledBytesOk(64u * 1024u + 1, 64u * 1024u) == FALSE;
}

void register_protocol_parser_smoke_tests(TestSuite& suite)
{
	suite.add_test("ed2k_source_body_exact_fit", test_source_body_valid_exact);
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
	suite.add_test("bt_packet_length_ok", test_bt_packet_length_ok);
	suite.add_test("g2_subpacket_payload_fits", test_g2_subpacket_payload_fits);
	suite.add_test("g2_frame_length_fits", test_g2_frame_length_fits);

	suite.add_test( "g1_deflate_truncated_marker", test_g1_deflate_truncated_marker_only );
	suite.add_test( "g1_deflate_marker_no_payload", test_g1_deflate_marker_no_payload );
	suite.add_test( "g1_deflate_min_payload", test_g1_deflate_min_compressed_byte );
	suite.add_test( "g1_deflate_xml_inflate_ok", test_g1_deflate_xml_inflate_ok );
	suite.add_test( "g1_packet_total_length_ok", test_g1_packet_total_length_ok );
	suite.add_test("g1_queryhit_xml_fits_exact", test_g1_queryhit_xml_fits_exact);
	suite.add_test("g1_queryhit_xml_fits_zero", test_g1_queryhit_xml_fits_zero);
	suite.add_test("g1_queryhit_xml_oversized", test_g1_queryhit_xml_oversized);

	suite.add_test("ggep_h_length_zero", test_ggep_h_length_zero);
	suite.add_test("ggep_m_length_zero", test_ggep_m_length_zero);
	suite.add_test("ggep_h_type_byte_present", test_ggep_h_valid_type_byte);
	suite.add_test("ggep_h_sha1_sized", test_ggep_h_valid_sha1_sized);

	suite.add_test("ed2k_preview_frame_exact", test_ed2k_preview_normal_frame);
	suite.add_test("ed2k_preview_frame_too_large", test_ed2k_preview_frame_exceeds_remaining);
	suite.add_test("ed2k_preview_frame_high_bit", test_ed2k_preview_frame_high_bit);
	suite.add_test("ed2k_preview_frame_max_uint", test_ed2k_preview_frame_max_uint_vs_zero);
	suite.add_test("bencode_depth_ok_zero", test_bencode_depth_ok_zero);
	suite.add_test("bencode_depth_ok_max", test_bencode_depth_ok_max);
	suite.add_test("bencode_depth_over_max", test_bencode_depth_over_max);
	suite.add_test("parse_int64_bounded_normal", test_parse_int64_bounded_normal);
	suite.add_test("parse_int64_bounded_negative", test_parse_int64_bounded_negative);
	suite.add_test("parse_int64_bounded_overflow", test_parse_int64_bounded_overflow);
	suite.add_test("parse_int64_bounded_min", test_parse_int64_bounded_min);
	suite.add_test("ed2k_preview_acceptable_normal", test_ed2k_preview_acceptable_normal);
	suite.add_test("ed2k_preview_acceptable_zero", test_ed2k_preview_acceptable_zero);
	suite.add_test("ed2k_preview_acceptable_over_cap", test_ed2k_preview_acceptable_over_cap);
	suite.add_test("ed2k_preview_acceptable_at_cap", test_ed2k_preview_acceptable_at_cap);
	suite.add_test("ed2k_tag_blob_bounds", test_ed2k_tag_blob_bounds);
	suite.add_test("ed2k_tag_string_bounds", test_ed2k_tag_string_bounds);
	suite.add_test("ed2k_unknown_tag_string_skip", test_ed2k_unknown_tag_string_skip);
	suite.add_test("ed2k_file_comment_bounds", test_ed2k_file_comment_bounds);
	suite.add_test("ed2k_ed_string_header", test_ed2k_ed_string_header);
	suite.add_test("ed2k_ed_string_payload", test_ed2k_ed_string_payload);
	suite.add_test("ed2k_long_ed_string_payload", test_ed2k_long_ed_string_payload);
	suite.add_test("ed2k_ed_string_truncated_prefix_gate", test_ed2k_ed_string_truncated_prefix_gate);
	suite.add_test("ed2k_server_message_length", test_ed2k_server_message_length);
	suite.add_test("ed2k_tag_uint64_remaining", test_ed2k_tag_uint64_remaining);
	suite.add_test("ed2k_hashset_payload_bounds", test_ed2k_hashset_payload_bounds);
	suite.add_test("ed2k_chat_message_bounds", test_ed2k_chat_message_bounds);
	suite.add_test("bt_ut_metadata_size_ok", test_bt_ut_metadata_size_ok);
	suite.add_test("bt_ut_metadata_size_zero", test_bt_ut_metadata_size_zero);
	suite.add_test("bt_ut_metadata_size_at_max", test_bt_ut_metadata_size_at_max);
	suite.add_test("bt_ut_metadata_size_over_max", test_bt_ut_metadata_size_over_max);
	suite.add_test("kad_store_tag_length_ok", test_kad_store_tag_length_ok);
	suite.add_test("bt_mse_ia_length_ok", test_bt_mse_ia_length_ok);
	suite.add_test("bt_mse_pad_length_ok", test_bt_mse_pad_length_ok);
	suite.add_test("bt_source_response_no_delete_packet_owned_root", test_bt_source_response_no_delete_packet_owned_root);

	suite.add_test("cbuffer_unbzip_bounds", test_cbuffer_unbzip_bounds);

	suite.add_test( "qht_patch_expected_bytes", test_qht_patch_expected_bytes );
	suite.add_test( "qht_patch_compressed_budget", test_qht_patch_compressed_budget );
	suite.add_test( "ed2k_packed_inflate_ok", test_ed2k_packed_inflate_ok );
	suite.add_test( "bt_tracker_http_response_bounds", test_bt_tracker_http_response_bounds );
	suite.add_test( "discovery_http_response_bounds", test_discovery_http_response_bounds );
	suite.add_test("update_servers_http_response_bounds", test_update_servers_http_response_bounds);
	suite.add_test("version_checker_http_response_bounds", test_version_checker_http_response_bounds);
	suite.add_test( "host_browser_http_body_bounds", test_host_browser_http_body_bounds );
	suite.add_test( "cbuffer_inflate_output_ok", test_cbuffer_inflate_output_ok );
	suite.add_test("cbuffer_inflate_stream_output_ok", test_cbuffer_inflate_stream_output_ok);
	suite.add_test( "ggep_inflate_output_ok", test_ggep_inflate_output_ok );
	suite.add_test( "ed2k_compressedpart_inflate_ok", test_ed2k_compressedpart_inflate_ok );
	suite.add_test( "ed2k_compressedpart_accept_before_submit", test_ed2k_compressedpart_accept_before_submit );
	suite.add_test("g1_wrapped_payload_ok", test_g1_wrapped_payload_ok);
	suite.add_test("bt_compact_peer_list_bytes", test_bt_compact_peer_list_bytes);
	suite.add_test("bt_sources_wanted_allows_more", test_bt_sources_wanted_allows_more);
	suite.add_test("g2_sgp_reassembly_bounds", test_g2_sgp_reassembly_bounds);
}
