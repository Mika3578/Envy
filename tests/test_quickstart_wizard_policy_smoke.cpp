//
// test_quickstart_wizard_policy_smoke.cpp
//
// Regression tests for QuickStart bandwidth parsing, upload-limit arithmetic,
// listen-port policy, network bootstrap gating, and Flags empty-state helpers.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/WizardQuickStartPolicy.h"
#include "../Envy/FlagsState.h"

#include <cstdint>
#include <cstring>
#include <string>

static bool test_parse_valid_kbps()
{
	std::uint32_t nKbps = 0;
	WizardBandwidthParseError nError = WizardBandwidthParseNone;
	return ParseWizardBandwidthKbps(L"768 kbps", nKbps, nError) &&
	       nKbps == 768u && nError == WizardBandwidthParseNone;
}

static bool test_parse_valid_mbps()
{
	std::uint32_t nKbps = 0;
	WizardBandwidthParseError nError = WizardBandwidthParseNone;
	return ParseWizardBandwidthKbps(L"1.5 mbps", nKbps, nError) &&
	       nKbps == 1536u && nError == WizardBandwidthParseNone;
}

static bool test_parse_valid_gbps()
{
	std::uint32_t nKbps = 0;
	WizardBandwidthParseError nError = WizardBandwidthParseNone;
	return ParseWizardBandwidthKbps(L"1 Gbps", nKbps, nError) &&
	       nKbps == 1048576u && nError == WizardBandwidthParseNone;
}

static bool test_parse_decimal_and_mixed_case()
{
	std::uint32_t nKbps = 0;
	WizardBandwidthParseError nError = WizardBandwidthParseNone;
	return ParseWizardBandwidthKbps(L"  2.0 Mbps  ", nKbps, nError) &&
	       nKbps == 2048u && nError == WizardBandwidthParseNone;
}

static bool test_parse_bare_number_is_kbps()
{
	std::uint32_t nKbps = 0;
	WizardBandwidthParseError nError = WizardBandwidthParseNone;
	return ParseWizardBandwidthKbps(L"4096", nKbps, nError) &&
	       nKbps == 4096u;
}

static bool test_parse_combo_display_suffix()
{
	std::uint32_t nKbps = 0;
	WizardBandwidthParseError nError = WizardBandwidthParseNone;
	return ParseWizardBandwidthKbps(L"768 kbps    (96 KB/s)", nKbps, nError) &&
	       nKbps == 768u &&
	       ParseWizardBandwidthKbps(L"1.0 mbps    (128 KB/s)", nKbps, nError) &&
	       nKbps == 1024u;
}

static bool test_parse_rejects_empty()
{
	std::uint32_t nKbps = 99;
	WizardBandwidthParseError nError = WizardBandwidthParseNone;
	return !ParseWizardBandwidthKbps(L"", nKbps, nError) &&
	       nError == WizardBandwidthParseEmpty && nKbps == 0 &&
	       !ParseWizardBandwidthKbps(L"   ", nKbps, nError) &&
	       nError == WizardBandwidthParseEmpty;
}

static bool test_parse_rejects_zero()
{
	std::uint32_t nKbps = 99;
	WizardBandwidthParseError nError = WizardBandwidthParseNone;
	return !ParseWizardBandwidthKbps(L"0 kbps", nKbps, nError) &&
	       nError == WizardBandwidthParseZero && nKbps == 0;
}

static bool test_parse_rejects_negative()
{
	std::uint32_t nKbps = 99;
	WizardBandwidthParseError nError = WizardBandwidthParseNone;
	return !ParseWizardBandwidthKbps(L"-12 Mbps", nKbps, nError) &&
	       nError == WizardBandwidthParseNegative && nKbps == 0;
}

static bool test_parse_rejects_trailing_junk()
{
	std::uint32_t nKbps = 99;
	WizardBandwidthParseError nError = WizardBandwidthParseNone;
	return !ParseWizardBandwidthKbps(L"100 kbps foo", nKbps, nError) &&
	       nError == WizardBandwidthParseTrailingJunk && nKbps == 0;
}

static bool test_parse_rejects_unknown_unit()
{
	std::uint32_t nKbps = 99;
	WizardBandwidthParseError nError = WizardBandwidthParseNone;
	return !ParseWizardBandwidthKbps(L"100 widgets", nKbps, nError) &&
	       nError == WizardBandwidthParseUnknownUnit && nKbps == 0;
}

static bool test_parse_rejects_overflow()
{
	std::uint32_t nKbps = 99;
	WizardBandwidthParseError nError = WizardBandwidthParseNone;
	return !ParseWizardBandwidthKbps(L"5000 Gbps", nKbps, nError) &&
	       nError == WizardBandwidthParseOverflow && nKbps == 0;
}

static bool test_parse_rejects_nan_inf()
{
	std::uint32_t nKbps = 99;
	WizardBandwidthParseError nError = WizardBandwidthParseNone;
	return !ParseWizardBandwidthKbps(L"nan kbps", nKbps, nError) &&
	       !ParseWizardBandwidthKbps(L"inf Mbps", nKbps, nError);
}

static bool test_historical_mbps_find_is_not_used()
{
	// CString::Find(L"mbps") is not a boolean presence test. The parser must
	// still treat mixed-case Mbps as megabits, not leave the raw number.
	std::uint32_t nKbps = 0;
	WizardBandwidthParseError nError = WizardBandwidthParseNone;
	return ParseWizardBandwidthKbps(L"1.5 Mbps", nKbps, nError) && nKbps == 1536u;
}

static bool test_upload_limit_default_factor()
{
	// OutSpeed 768 kbps, factor 8 => keep 92%, floor to KiB/s.
	const std::uint32_t nBytes = WizardUploadLimitBytesPerSecond(768u, 8u);
	return nBytes == 90112u;
}

static bool test_upload_limit_factor_zero()
{
	const std::uint32_t nBytes = WizardUploadLimitBytesPerSecond(768u, 0u);
	return nBytes == 98304u;
}

static bool test_upload_limit_not_integer_percent_zero()
{
	// The legacy wizard used ((100 - factor) / 100) with integers, which is 0
	// for every factor in 1..99. The helper must not reproduce that.
	const std::uint32_t nBroken = (768u / 8u) * ((100u - 8u) / 100u) * 1024u;
	const std::uint32_t nFixed = WizardUploadLimitBytesPerSecond(768u, 8u);
	return nBroken == 0u && nFixed > 0u;
}

static bool test_upload_limit_upper_bound_no_overflow()
{
	const std::uint32_t nBytes = WizardUploadLimitBytesPerSecond(0xFFFFFFFFu, 0u);
	return nBytes == 0xFFFFFFFFu;
}

static bool test_upload_limit_zero_is_unlimited()
{
	return WizardUploadLimitBytesPerSecond(0u, 8u) == 0u &&
	       WizardUploadLimitBytesPerSecond(1u, 99u) == 0u;
}

static bool test_listen_port_policy()
{
	return !WizardListenPortIsValid(0) &&
	       !WizardListenPortIsValid(1023) &&
	       WizardListenPortIsValid(1024) &&
	       WizardListenPortIsValid(6480) &&
	       WizardListenPortIsValid(65535) &&
	       !WizardListenPortIsValid(65536) &&
	       WizardListenPortMin() == 1024u &&
	       WizardListenPortMax() == 65535u;
}

static bool test_connection_page_may_not_bootstrap()
{
	return WizardConnectionPageMayBootstrap() == false;
}

static bool test_ed2k_bootstrap_requires_enable()
{
	return WizardShouldBootstrapEd2k(true, 0) == true &&
	       WizardShouldBootstrapEd2k(true, 2) == true &&
	       WizardShouldBootstrapEd2k(true, 3) == false &&
	       WizardShouldBootstrapEd2k(false, 0) == false;
}

static bool test_dc_bootstrap_requires_enable()
{
	return WizardShouldBootstrapDc(true, 0) == true &&
	       WizardShouldBootstrapDc(true, 4) == true &&
	       WizardShouldBootstrapDc(true, 5) == false &&
	       WizardShouldBootstrapDc(false, 0) == false;
}

static bool test_connect_any_selected_network()
{
	return WizardShouldConnectNetworks(false, false, false, false, false) == false &&
	       WizardShouldConnectNetworks(true, false, false, false, false) == true &&
	       WizardShouldConnectNetworks(false, false, false, true, false) == true &&
	       WizardShouldConnectNetworks(false, false, false, false, true) == true;
}

static bool test_torrent_association_independent()
{
	return WizardTorrentAssociationIndependentOfEngine() == true;
}

static bool test_flags_initial_empty_state()
{
	FlagsDimensions dims;
	std::memset(&dims, 0x7F, sizeof(dims));
	FlagsResetDimensions(dims);
	return FlagsDimensionsAreEmpty(dims) &&
	       dims.Height == 0 && dims.Width == 0 &&
	       dims.ImageListHeight == 0 && dims.ImageListWidth == 0;
}

static bool test_flags_create_args_reject_invalid()
{
	return FlagsImageListCreateArgsOk(18, 16, 26) == true &&
	       FlagsImageListCreateArgsOk(0, 16, 1) == false &&
	       FlagsImageListCreateArgsOk(18, 0, 1) == false &&
	       FlagsImageListCreateArgsOk(18, 16, -1) == false &&
	       FlagsImageListCreateArgsOk(300, 16, 1) == false;
}

static bool test_flags_count_and_index_safe()
{
	return FlagsCountOrZero(false, 99) == 0 &&
	       FlagsCountOrZero(true, -1) == 0 &&
	       FlagsCountOrZero(true, 12) == 12 &&
	       FlagsIndexIsValid(0, 1) == true &&
	       FlagsIndexIsValid(1, 1) == false &&
	       FlagsIndexIsValid(-1, 10) == false &&
	       FlagsIndexIsValid(0, 0) == false;
}

static bool test_flags_country_index()
{
	return FlagsIndexFromCountryCode(L'A', L'A') == 0 &&
	       FlagsIndexFromCountryCode(L'U', L'S') == ('U' - 'A') * 26 + ('S' - 'A') &&
	       FlagsIndexFromCountryCode(L'A', L'1') == -1 &&
	       FlagsIndexFromCountryCode(L'a', L'a') == -1;
}

void register_quickstart_wizard_policy_smoke_tests(TestSuite& suite)
{
	suite.add_test("quickstart_parse_valid_kbps", test_parse_valid_kbps);
	suite.add_test("quickstart_parse_valid_mbps", test_parse_valid_mbps);
	suite.add_test("quickstart_parse_valid_gbps", test_parse_valid_gbps);
	suite.add_test("quickstart_parse_decimal_mixed_case", test_parse_decimal_and_mixed_case);
	suite.add_test("quickstart_parse_bare_number_kbps", test_parse_bare_number_is_kbps);
	suite.add_test("quickstart_parse_combo_display_suffix", test_parse_combo_display_suffix);
	suite.add_test("quickstart_parse_rejects_empty", test_parse_rejects_empty);
	suite.add_test("quickstart_parse_rejects_zero", test_parse_rejects_zero);
	suite.add_test("quickstart_parse_rejects_negative", test_parse_rejects_negative);
	suite.add_test("quickstart_parse_rejects_trailing_junk", test_parse_rejects_trailing_junk);
	suite.add_test("quickstart_parse_rejects_unknown_unit", test_parse_rejects_unknown_unit);
	suite.add_test("quickstart_parse_rejects_overflow", test_parse_rejects_overflow);
	suite.add_test("quickstart_parse_rejects_nan_inf", test_parse_rejects_nan_inf);
	suite.add_test("quickstart_parse_not_cstring_find", test_historical_mbps_find_is_not_used);
	suite.add_test("quickstart_upload_limit_default_factor", test_upload_limit_default_factor);
	suite.add_test("quickstart_upload_limit_factor_zero", test_upload_limit_factor_zero);
	suite.add_test("quickstart_upload_limit_not_int_percent_zero", test_upload_limit_not_integer_percent_zero);
	suite.add_test("quickstart_upload_limit_no_overflow", test_upload_limit_upper_bound_no_overflow);
	suite.add_test("quickstart_upload_limit_zero_unlimited", test_upload_limit_zero_is_unlimited);
	suite.add_test("quickstart_listen_port_policy", test_listen_port_policy);
	suite.add_test("quickstart_connection_no_bootstrap", test_connection_page_may_not_bootstrap);
	suite.add_test("quickstart_ed2k_bootstrap_gate", test_ed2k_bootstrap_requires_enable);
	suite.add_test("quickstart_dc_bootstrap_gate", test_dc_bootstrap_requires_enable);
	suite.add_test("quickstart_connect_selected_networks", test_connect_any_selected_network);
	suite.add_test("quickstart_torrent_assoc_independent", test_torrent_association_independent);
	suite.add_test("quickstart_flags_empty_state", test_flags_initial_empty_state);
	suite.add_test("quickstart_flags_create_args", test_flags_create_args_reject_invalid);
	suite.add_test("quickstart_flags_count_index", test_flags_count_and_index_safe);
	suite.add_test("quickstart_flags_country_index", test_flags_country_index);
}
