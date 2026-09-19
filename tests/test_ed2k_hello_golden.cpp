//
// test_ed2k_hello_golden.cpp
//
// Golden wire vectors for ED2K/eMule C2C Hello and HelloAnswer.
//
// SOURCE (all vectors in this file unless noted):
//   Envy implementation — bytes derived from CEDClient::SendHello layout
//   and Ed2kHelloCapabilities packing, NOT from an eMule/aMule capture.
//
// Level-2 reference-golden slots (eMule/aMule captures) are intentionally
// empty stubs so a later interop PR can drop real captures without redesign.
// Capture pipeline: tools/interop/ (issue #160). Do not fill these slots
// until origin, version, direction, opcode, date, and privacy normalization
// are documented. The Python harness duplicates Envy self-goldens only.
//
// Expected bytes are hand-authored (not taken from Ed2kPackHelloTcpPacket
// output) so the packer under test is not tautological. Hello and HelloAnswer
// share one literal body because their wire payload is identical apart from
// the Hello-only 0x10 prefix and TCP opcode/length.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"

#include "../Envy/Ed2kHelloWire.h"
#include "../Envy/Ed2kHelloCapabilities.h"
#include "../Envy/SecureIdentPolicy.h"

#include <cstdio>
#include <cstring>
#include <string>

// ---------------------------------------------------------------------------
// Deterministic nominal inputs (Envy self-golden)
// ---------------------------------------------------------------------------

static const BYTE kNickUtf8[] = { 'E', 'n', 'v', 'y' };	// "Envy"

// Pre-mutation GUID; packer applies [5]=14, [14]=111 like SendHello.
static const BYTE kUserHashRaw[16] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

static const BYTE kUserHashMutated[16] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x0E, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x6F, 0x0F
};

static const DWORD kClientId = 0x11223344u;
static const WORD kTcpPort = 4662;			// 0x1236
static const WORD kUdpPort = 4662;
static const DWORD kEd2kVersion = ED2K_VERSION;	// 0x3D
static const DWORD kSoftwareVersion = 0x50080000u;	// client 80, 4.0
// Honest MiscOptions from current advertise helpers + SendHello constants.
// Compression nibble = ED2K_VERSION_COMPRESSION (1) — frozen, decision later.
static const DWORD kMiscOptions1 = 0x12102211u;
static const DWORD kMiscOptions2 = 0x00000C10u;

static Ed2kHelloWireInput make_nominal_input(BOOL bHello)
{
	Ed2kHelloWireInput in = {};
	CopyMemory( in.userHash, kUserHashRaw, 16 );
	in.clientId = kClientId;
	in.tcpPort = kTcpPort;
	in.udpPort = kUdpPort;
	in.nickUtf8 = kNickUtf8;
	in.nickUtf8Len = (WORD)sizeof( kNickUtf8 );
	in.ed2kVersion = kEd2kVersion;
	in.miscOptions1 = kMiscOptions1;
	in.miscOptions2 = kMiscOptions2;
	in.softwareVersion = kSoftwareVersion;
	in.serverIp = 0;
	in.serverPort = 0;
	in.bHello = bHello;
	return in;
}

static std::string describe_diff(
	const BYTE* pExpected, size_t nExpected,
	const BYTE* pActual, size_t nActual)
{
	char buf[192];
	if ( nExpected != nActual )
	{
		std::snprintf( buf, sizeof( buf ),
			"length mismatch: expected %zu actual %zu", nExpected, nActual );
		return buf;
	}

	for ( size_t i = 0; i < nExpected; ++i )
	{
		if ( pExpected[i] != pActual[i] )
		{
			std::snprintf( buf, sizeof( buf ),
				"first diff at offset %zu: expected 0x%02X actual 0x%02X",
				i, (unsigned)pExpected[i], (unsigned)pActual[i] );
			return buf;
		}
	}
	return {};
}

static bool bytes_equal(
	const BYTE* pExpected, size_t nExpected,
	const BYTE* pActual, size_t nActual)
{
	const std::string diff = describe_diff( pExpected, nExpected, pActual, nActual );
	if ( ! diff.empty() )
	{
		std::cout << "    -> " << diff << "\n";
		return false;
	}
	return true;
}

// ---------------------------------------------------------------------------
// Vectors A/B — Hello and HelloAnswer Envy nominal (full TCP frames)
//
// SOURCE: Envy implementation (self-golden). Hand-authored from SendHello.
// The protocol payload after the Hello-only 0x10 byte is common to both
// packets, so it is written once here instead of duplicated line-for-line.
// ---------------------------------------------------------------------------

static const BYTE kExpectedHelloPrefix[] =
{
	0xE3,										// ED2K_PROTOCOL_EDONKEY
	0x54, 0x00, 0x00, 0x00,						// length = body + 1 = 84
	0x01,										// ED2K_C2C_HELLO
	0x10										// legacy hash size
};

static const BYTE kExpectedHelloAnswerPrefix[] =
{
	0xE3,
	0x53, 0x00, 0x00, 0x00,						// length = 83
	0x4C										// ED2K_C2C_HELLOANSWER
};

static const BYTE kExpectedHelloCommonBody[] =
{
	// user hash (after mutation)
	0x00, 0x01, 0x02, 0x03, 0x04, 0x0E, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x6F, 0x0F,
	// client ID LE
	0x44, 0x33, 0x22, 0x11,
	// TCP port LE
	0x36, 0x12,
	// tag count = 6
	0x06, 0x00, 0x00, 0x00,

	// CT_NAME "Envy" (Unicode ED-string)
	0x02, 0x01, 0x00, 0x01, 0x04, 0x00, 0x45, 0x6E, 0x76, 0x79,

	// CT_VERSION = 0x3D
	0x03, 0x01, 0x00, 0x11, 0x3D, 0x00, 0x00, 0x00,

	// CT_UDPPORTS = 4662
	0x03, 0x01, 0x00, 0xF9, 0x36, 0x12, 0x00, 0x00,

	// CT_FEATUREVERSIONS / MiscOptions1 = 0x12102211
	0x03, 0x01, 0x00, 0xFA, 0x11, 0x22, 0x10, 0x12,

	// CT_MOREFEATUREVERSIONS / MiscOptions2 = 0x00000C10
	0x03, 0x01, 0x00, 0xFE, 0x10, 0x0C, 0x00, 0x00,

	// CT_SOFTWAREVERSION = 0x50080000
	0x03, 0x01, 0x00, 0xFB, 0x00, 0x00, 0x08, 0x50,

	// server IP/port (none)
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00
};

static bool build_expected_packet(BOOL bHello, BYTE* pOut, size_t nCap, size_t* pLen)
{
	if ( ! pOut || ! pLen )
		return false;

	const BYTE* pPrefix = bHello ? kExpectedHelloPrefix : kExpectedHelloAnswerPrefix;
	const size_t nPrefix = bHello ? sizeof( kExpectedHelloPrefix ) : sizeof( kExpectedHelloAnswerPrefix );
	const size_t nTotal = nPrefix + sizeof( kExpectedHelloCommonBody );
	if ( nCap < nTotal )
		return false;

	CopyMemory( pOut, pPrefix, nPrefix );
	CopyMemory( pOut + nPrefix, kExpectedHelloCommonBody, sizeof( kExpectedHelloCommonBody ) );
	*pLen = nTotal;
	return true;
}

static bool test_nominal_packet_bytes(BOOL bHello)
{
	const Ed2kHelloWireInput in = make_nominal_input( bHello );
	BYTE actual[256];
	BYTE expected[256];
	size_t nActual = 0;
	size_t nExpected = 0;
	if ( ! Ed2kPackHelloTcpPacket( &in, actual, sizeof( actual ), &nActual )
		|| ! build_expected_packet( bHello, expected, sizeof( expected ), &nExpected ) )
	{
		return false;
	}

	return bytes_equal( expected, nExpected, actual, nActual );
}

static bool test_guid_mutation_matches_sendhello()
{
	BYTE hash[16];
	CopyMemory( hash, kUserHashRaw, 16 );
	Ed2kHelloApplyGuidMutation( hash );
	return std::memcmp( hash, kUserHashMutated, 16 ) == 0;
}

static bool test_vector_a_hello_nominal_bytes()
{
	return test_nominal_packet_bytes( TRUE );
}

static bool test_vector_b_helloanswer_nominal_bytes()
{
	return test_nominal_packet_bytes( FALSE );
}

// ---------------------------------------------------------------------------
// Vector C — MiscOptions bit positions / honest advertise freeze
// ---------------------------------------------------------------------------

static bool test_vector_c_miscoptions_match_capability_helpers()
{
	// Recompute MiscOptions from the same helpers SendHello uses for honesty.
	const DWORD nOpt1 = Ed2kPackFeatureVersions1(
		Ed2kAichAdvertisedVersion(),
		TRUE,					// Unicode
		2,						// ED2K_VERSION_UDP
		1,						// ED2K_VERSION_COMPRESSION (frozen — see TODO)
		Ed2kSecureIdentAdvertisedVersion(),
		2,						// ED2K_VERSION_SOURCEEXCHANGE
		2,						// ExtendedRequest (SendHello min with ED2K_VERSION_EXTENDEDREQUEST)
		1,						// ED2K_VERSION_COMMENTS
		TRUE );					// Preview

	const DWORD nOpt2 = Ed2kPackFeatureVersions2(
		TRUE,					// Captcha
		TRUE,					// SourceEx2
		Ed2kCryptLayerRequiresAdvertised(),
		Ed2kCryptLayerRequestsAdvertised(),
		Ed2kCryptLayerSupportsAdvertised(),
		Ed2kExtMultipacketAdvertised(),
		TRUE,					// LargeFiles
		0 );					// Kad nibble

	if ( nOpt1 != kMiscOptions1 || nOpt2 != kMiscOptions2 )
	{
		std::cout << "    -> miscOptions mismatch opt1=0x" << std::hex << nOpt1
			<< " expected 0x" << kMiscOptions1
			<< " opt2=0x" << nOpt2
			<< " expected 0x" << kMiscOptions2 << std::dec << "\n";
		return false;
	}

	return Ed2kFeatureVersions1Aich( nOpt1 ) == 0
		&& Ed2kFeatureVersions1SecureIdent( nOpt1 ) == 0
		&& ( ( nOpt1 >> 28 ) & 0x01 ) == 1			// Unicode
		&& ( ( nOpt1 >> 24 ) & 0x0F ) == 2			// UDP
		&& ( ( nOpt1 >> 20 ) & 0x0F ) == 1			// Compression (frozen)
		&& ( ( nOpt1 >> 12 ) & 0x0F ) == 2			// SourceEx
		&& ( ( nOpt1 >> 8 ) & 0x0F ) == 2			// ExtReq
		&& ( ( nOpt1 >> 4 ) & 0x0F ) == 1			// Comments
		&& ( nOpt1 & 0x01 ) == 1						// Preview
		&& Ed2kFeatureVersions2ExtMultipacket( nOpt2 ) == FALSE
		&& Ed2kFeatureVersions2SupportsCrypt( nOpt2 ) == FALSE
		&& Ed2kFeatureVersions2RequestsCrypt( nOpt2 ) == FALSE
		&& Ed2kFeatureVersions2RequiresCrypt( nOpt2 ) == FALSE
		&& ( ( nOpt2 >> 11 ) & 0x01 ) == 1			// Captcha
		&& ( ( nOpt2 >> 10 ) & 0x01 ) == 1			// SourceEx2
		&& ( ( nOpt2 >> 4 ) & 0x01 ) == 1				// LargeFiles
		&& ( nOpt2 & 0x0F ) == 0;						// Kad
}

// Frozen compression advertise state. Do NOT flip this bit in this PR.
// TODO / follow-up:
//   compare advertised compression capability with actual upload compression
//   before deciding whether to disable advertisement or implement sending.
static bool test_vector_c_compression_advertise_frozen()
{
	const DWORD nOpt1 = Ed2kPackFeatureVersions1(
		0, TRUE, 2, 1, 0, 2, 2, 1, TRUE );
	return ( ( nOpt1 >> 20 ) & 0x0F ) == 1;
}

static bool test_vector_c_mutation_ext_multipacket_would_break_golden()
{
	// Mental mutation: Ext Multipacket 0 → 1 must diverge from golden MiscOptions2.
	const DWORD nMutated = Ed2kPackFeatureVersions2(
		TRUE, TRUE, FALSE, FALSE, FALSE, TRUE /*ext*/, TRUE, 0 );
	return nMutated != kMiscOptions2
		&& Ed2kFeatureVersions2ExtMultipacket( nMutated ) == TRUE;
}

static bool test_vector_c_mutation_secureident_would_break_golden()
{
	const DWORD nMutated = Ed2kPackFeatureVersions1(
		0, TRUE, 2, 1, 1 /*SecureIdent*/, 2, 2, 1, TRUE );
	return nMutated != kMiscOptions1
		&& Ed2kFeatureVersions1SecureIdent( nMutated ) == 1;
}

static bool test_vector_c_mutation_kad_nibble_would_break_golden()
{
	const DWORD nMutated = Ed2kPackFeatureVersions2(
		TRUE, TRUE, FALSE, FALSE, FALSE, FALSE, TRUE, 1 );
	return nMutated != kMiscOptions2
		&& ( nMutated & 0x0F ) == 1;
}

static bool test_vector_c_software_version_helper()
{
	return Ed2kPackSoftwareVersion( 80, 4, 0 ) == kSoftwareVersion;
}

// ---------------------------------------------------------------------------
// Vector D — round-trip parse of golden MiscOptions tags
// ---------------------------------------------------------------------------

static bool parse_golden_miscoptions(BOOL bHello, DWORD* pOpt1, DWORD* pOpt2)
{
	BYTE packet[256];
	size_t nPacket = 0;
	if ( ! pOpt1 || ! pOpt2
		|| ! build_expected_packet( bHello, packet, sizeof( packet ), &nPacket ) )
	{
		return false;
	}

	BYTE opcode = 0;
	const BYTE* pBody = NULL;
	size_t nBody = 0;
	if ( ! Ed2kHelloTcpStripHeader( packet, nPacket, &opcode, &pBody, &nBody ) )
		return false;

	const BYTE nExpectedOpcode = bHello ? (BYTE)ED2K_C2C_HELLO : (BYTE)ED2K_C2C_HELLOANSWER;
	return opcode == nExpectedOpcode
		&& Ed2kHelloBodyFindIntTag( pBody, nBody, bHello, ED2K_CT_FEATUREVERSIONS, pOpt1 )
		&& Ed2kHelloBodyFindIntTag( pBody, nBody, bHello, ED2K_CT_MOREFEATUREVERSIONS, pOpt2 );
}

static bool test_vector_d_parse_miscoptions_from_hello_golden()
{
	DWORD nOpt1 = 0;
	DWORD nOpt2 = 0;
	if ( ! parse_golden_miscoptions( TRUE, &nOpt1, &nOpt2 ) )
		return false;

	return nOpt1 == kMiscOptions1
		&& nOpt2 == kMiscOptions2
		&& Ed2kFeatureVersions2ExtMultipacket( nOpt2 ) == FALSE
		&& Ed2kFeatureVersions1SecureIdent( nOpt1 ) == 0
		&& Ed2kFeatureVersions1Aich( nOpt1 ) == 0;
}

static bool test_vector_d_parse_miscoptions_from_helloanswer_golden()
{
	DWORD nOpt1 = 0;
	DWORD nOpt2 = 0;
	return parse_golden_miscoptions( FALSE, &nOpt1, &nOpt2 )
		&& nOpt1 == kMiscOptions1
		&& nOpt2 == kMiscOptions2;
}

static bool test_vector_d_roundtrip_packer_then_parse()
{
	const Ed2kHelloWireInput in = make_nominal_input( TRUE );
	BYTE packet[256];
	size_t nPacket = 0;
	if ( ! Ed2kPackHelloTcpPacket( &in, packet, sizeof( packet ), &nPacket ) )
		return false;

	BYTE opcode = 0;
	const BYTE* pBody = NULL;
	size_t nBody = 0;
	if ( ! Ed2kHelloTcpStripHeader( packet, nPacket, &opcode, &pBody, &nBody ) )
		return false;

	DWORD nOpt1 = 0;
	DWORD nOpt2 = 0;
	DWORD nPortTag = 0;
	if ( ! Ed2kHelloBodyFindIntTag( pBody, nBody, TRUE, ED2K_CT_FEATUREVERSIONS, &nOpt1 ) )
		return false;
	if ( ! Ed2kHelloBodyFindIntTag( pBody, nBody, TRUE, ED2K_CT_MOREFEATUREVERSIONS, &nOpt2 ) )
		return false;
	if ( ! Ed2kHelloBodyFindIntTag( pBody, nBody, TRUE, ED2K_CT_UDPPORTS, &nPortTag ) )
		return false;

	return opcode == ED2K_C2C_HELLO
		&& nOpt1 == kMiscOptions1
		&& nOpt2 == kMiscOptions2
		&& nPortTag == kUdpPort;
}

// ---------------------------------------------------------------------------
// Level-2 reference-golden placeholders (eMule/aMule captures — not yet present)
// ---------------------------------------------------------------------------

static bool reference_capture_slot_empty(const BYTE* pCapture, size_t nCaptureLen)
{
	return pCapture == NULL && nCaptureLen == 0;
}

static bool test_reference_golden_emule_capture_slot_empty()
{
	// SOURCE: eMule capture — NOT YET AVAILABLE.
	static const BYTE* const kEmuleHelloCapture = NULL;
	static const size_t kEmuleHelloCaptureLen = 0;
	return reference_capture_slot_empty( kEmuleHelloCapture, kEmuleHelloCaptureLen );
}

static bool test_reference_golden_amule_capture_slot_empty()
{
	// SOURCE: aMule capture — NOT YET AVAILABLE.
	static const BYTE* const kAmuleHelloCapture = NULL;
	static const size_t kAmuleHelloCaptureLen = 0;
	return reference_capture_slot_empty( kAmuleHelloCapture, kAmuleHelloCaptureLen );
}

void register_ed2k_hello_golden_tests(TestSuite& suite)
{
	suite.add_test("ed2k_hello_guid_mutation", test_guid_mutation_matches_sendhello);
	suite.add_test("ed2k_hello_golden_vector_a_nominal", test_vector_a_hello_nominal_bytes);
	suite.add_test("ed2k_helloanswer_golden_vector_b_nominal", test_vector_b_helloanswer_nominal_bytes);
	suite.add_test("ed2k_hello_golden_vector_c_miscoptions", test_vector_c_miscoptions_match_capability_helpers);
	suite.add_test("ed2k_hello_compression_advertise_frozen", test_vector_c_compression_advertise_frozen);
	suite.add_test("ed2k_hello_mutation_ext_multipacket", test_vector_c_mutation_ext_multipacket_would_break_golden);
	suite.add_test("ed2k_hello_mutation_secureident", test_vector_c_mutation_secureident_would_break_golden);
	suite.add_test("ed2k_hello_mutation_kad_nibble", test_vector_c_mutation_kad_nibble_would_break_golden);
	suite.add_test("ed2k_hello_software_version_pack", test_vector_c_software_version_helper);
	suite.add_test("ed2k_hello_golden_vector_d_parse_hello", test_vector_d_parse_miscoptions_from_hello_golden);
	suite.add_test("ed2k_hello_golden_vector_d_parse_answer", test_vector_d_parse_miscoptions_from_helloanswer_golden);
	suite.add_test("ed2k_hello_golden_vector_d_roundtrip", test_vector_d_roundtrip_packer_then_parse);
	suite.add_test("ed2k_hello_reference_emule_slot_empty", test_reference_golden_emule_capture_slot_empty);
	suite.add_test("ed2k_hello_reference_amule_slot_empty", test_reference_golden_amule_capture_slot_empty);
}
