//
// test_ed2k_hello_capabilities_smoke.cpp
//
// Smoke tests for honest ED2K Hello capability packing (#87).
// No live network / MFC client — pure packing helpers only.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/Ed2kHelloCapabilities.h"
#include "../Envy/SecureIdentPolicy.h"

static bool test_aich_not_advertised_until_c2c()
{
	return Ed2kAichAdvertisedVersion() == 0;
}

static bool test_secureident_still_zero()
{
	return Ed2kSecureIdentAdvertisedVersion() == 0;
}

static bool test_cryptlayer_advertise_all_zero()
{
	return Ed2kCryptLayerSupportsAdvertised() == FALSE
		&& Ed2kCryptLayerRequestsAdvertised() == FALSE
		&& Ed2kCryptLayerRequiresAdvertised() == FALSE
		&& Ed2kCryptLayerTcpObfuscationImplemented() == FALSE
		&& Ed2kCryptLayerHelloBitsMayStartPacketCrypto() == FALSE;
}

static bool test_ext_multipacket_not_advertised()
{
	return Ed2kExtMultipacketAdvertised() == FALSE;
}

static bool test_pack_opt1_matches_honest_defaults()
{
	const DWORD nOpt1 = Ed2kPackFeatureVersions1(
		Ed2kAichAdvertisedVersion(),
		TRUE,
		2,	// ED2K_VERSION_UDP (Envy/EDPacket.h)
		1,	// ED2K_VERSION_COMPRESSION
		Ed2kSecureIdentAdvertisedVersion(),
		2,	// SourceEx
		2,	// ExtReq
		1,	// Comments
		TRUE );

	return Ed2kFeatureVersions1Aich(nOpt1) == 0
		&& Ed2kFeatureVersions1SecureIdent(nOpt1) == 0
		&& ( ( nOpt1 >> 28 ) & 0x01 ) == 1	// Unicode
		&& ( ( nOpt1 >> 24 ) & 0x0F ) == 2	// UDP nibble
		&& ( ( nOpt1 >> 12 ) & 0x0F ) == 2	// SourceEx
		&& ( nOpt1 & 0x01 ) == 1;			// Preview
}

static bool test_pack_opt2_honest_defaults()
{
	const DWORD nOpt2 = Ed2kPackFeatureVersions2(
		TRUE,	// Captcha
		TRUE,	// SourceEx2
		Ed2kCryptLayerRequiresAdvertised(),
		Ed2kCryptLayerRequestsAdvertised(),
		Ed2kCryptLayerSupportsAdvertised(),
		Ed2kExtMultipacketAdvertised(),
		TRUE,	// LargeFiles
		0 );	// Kad version nibble

	return Ed2kFeatureVersions2SupportsCrypt(nOpt2) == FALSE
		&& Ed2kFeatureVersions2RequestsCrypt(nOpt2) == FALSE
		&& Ed2kFeatureVersions2RequiresCrypt(nOpt2) == FALSE
		&& Ed2kFeatureVersions2ExtMultipacket(nOpt2) == FALSE
		&& ( ( nOpt2 >> 11 ) & 0x01 ) == 1	// Captcha
		&& ( ( nOpt2 >> 10 ) & 0x01 ) == 1	// SourceEx2
		&& ( ( nOpt2 >> 4 ) & 0x01 ) == 1	// LargeFiles
		&& ( nOpt2 & 0x0F ) == 0;			// Kad
}

static bool test_pack_opt2_ext_multipacket_bit_position()
{
	// Packer coverage: bit 5 must toggle when explicitly requested.
	const DWORD nOn = Ed2kPackFeatureVersions2(
		FALSE, FALSE, FALSE, FALSE, FALSE, TRUE, FALSE, 0 );
	const DWORD nOff = Ed2kPackFeatureVersions2(
		FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, 0 );
	return Ed2kFeatureVersions2ExtMultipacket(nOn) == TRUE
		&& Ed2kFeatureVersions2ExtMultipacket(nOff) == FALSE;
}

static bool test_require_clamped_without_support()
{
	// eMule-style clamp: Require without Support/Request must pack as 0.
	const DWORD nOpt2 = Ed2kPackFeatureVersions2(
		FALSE, FALSE,
		TRUE,	// Requires
		FALSE,	// Requests
		FALSE,	// Supports
		FALSE, FALSE, 0 );

	return Ed2kFeatureVersions2SupportsCrypt(nOpt2) == FALSE
		&& Ed2kFeatureVersions2RequestsCrypt(nOpt2) == FALSE
		&& Ed2kFeatureVersions2RequiresCrypt(nOpt2) == FALSE;
}

// CT_EMULE_UDPPORTS layout: Kad port in the high word, ED2K UDP in the low.
static bool test_udpports_kad_high_word()
{
	const DWORD n = Ed2kPackUdpPorts( 4672, 4665 );
	return n == 0x12391240u
		&& Ed2kUdpPortsKadPort( n ) == 4665
		&& Ed2kUdpPortsUdpPort( n ) == 4672;
}

// Kad off keeps the legacy tag value (golden Hello vector: 4662, Kad 0).
static bool test_udpports_kad_off_is_legacy()
{
	const DWORD n = Ed2kPackUdpPorts( 4662, 0 );
	return n == 4662u && Ed2kUdpPortsKadPort( n ) == 0;
}

// Kad nibble: our version while Kad runs (eMule buddy ping/pong needs != 0),
// 0 when Kad is off so the golden Kad-off Hello stays unchanged.
static bool test_kad_nibble_follows_kad_state()
{
	const DWORD nBase = Ed2kPackFeatureVersions2(TRUE, TRUE, FALSE, FALSE, FALSE, FALSE, TRUE, 0);
	const DWORD nOn = nBase | Ed2kHelloKadVersionNibble(true, 8);
	const DWORD nOff = nBase | Ed2kHelloKadVersionNibble(false, 8);
	return (nOn & 0x0F) == 8 && nOff == nBase && (nOn & ~0x0Fu) == nBase
	       && Ed2kHelloKadVersionNibble(true, 0x18) == 8;
}

void register_ed2k_hello_capabilities_smoke_tests(TestSuite& suite)
{
	suite.add_test("aich_not_advertised_until_c2c", test_aich_not_advertised_until_c2c);
	suite.add_test("secureident_still_zero_in_hello_pack", test_secureident_still_zero);
	suite.add_test("cryptlayer_advertise_all_zero", test_cryptlayer_advertise_all_zero);
	suite.add_test("ext_multipacket_not_advertised", test_ext_multipacket_not_advertised);
	suite.add_test("pack_opt1_matches_honest_defaults", test_pack_opt1_matches_honest_defaults);
	suite.add_test("pack_opt2_honest_defaults", test_pack_opt2_honest_defaults);
	suite.add_test("pack_opt2_ext_multipacket_bit_position", test_pack_opt2_ext_multipacket_bit_position);
	suite.add_test("require_clamped_without_support", test_require_clamped_without_support);
	suite.add_test("udpports_kad_high_word", test_udpports_kad_high_word);
	suite.add_test("udpports_kad_off_is_legacy", test_udpports_kad_off_is_legacy);
	suite.add_test("kad_nibble_follows_kad_state", test_kad_nibble_follows_kad_state);
}
