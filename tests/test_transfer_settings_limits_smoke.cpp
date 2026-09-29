//
// test_transfer_settings_limits_smoke.cpp
//
// Smoke tests for transfer-settings limit helpers (Uploads/Downloads pages).
// Covers defaults, unlimited tokens (including legacy MAX/NONE), DWORD
// conversion, MaxPerHost clamp, Fair-Use 10% media clip, and absent-key
// fallback — without loading MFC CSettings.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/TransferSettingsLimits.h"
#include "../Envy/TransferConnectionCapacity.h"

#include <cwchar>
#include <map>
#include <string>

namespace
{

class DwordSettingStore
{
public:
	void SetDword(LPCTSTR pszSection, LPCTSTR pszName, DWORD nValue)
	{
		m_oValues[Key(pszSection, pszName)] = nValue;
	}

	bool Has(LPCTSTR pszSection, LPCTSTR pszName) const
	{
		return m_oValues.find(Key(pszSection, pszName)) != m_oValues.end();
	}

	void Delete(LPCTSTR pszSection, LPCTSTR pszName)
	{
		m_oValues.erase(Key(pszSection, pszName));
	}

	DWORD GetDword(LPCTSTR pszSection, LPCTSTR pszName, DWORD nDefault) const
	{
		const auto it = m_oValues.find(Key(pszSection, pszName));
		if (it == m_oValues.end())
			return nDefault;
		return it->second;
	}

private:
	static std::wstring Key(LPCTSTR pszSection, LPCTSTR pszName)
	{
		std::wstring s(pszSection ? pszSection : L"");
		s.push_back(L'\\');
		s.append(pszName ? pszName : L"");
		return s;
	}

	std::map<std::wstring, DWORD> m_oValues;
};

DWORD LoadUploads(const DwordSettingStore& store)
{
	return store.GetDword(L"Bandwidth", L"Uploads", TransferBandwidthUnlimitedValue());
}

DWORD LoadMaxPerHost(const DwordSettingStore& store)
{
	DWORD nValue = store.GetDword(L"Uploads", L"MaxPerHost", TransferMaxPerHostDefault());
	return TransferMaxPerHostClamp(nValue);
}

} // namespace

static bool test_bandwidth_unlimited_value_is_zero()
{
	return TransferBandwidthUnlimitedValue() == 0 && TransferBandwidthSettingIsUnlimited(0) == true && TransferBandwidthSettingIsUnlimited(1) == false;
}

static bool test_bandwidth_display_token_unlimited()
{
	return wcscmp(TransferBandwidthUnlimitedDisplayToken(), L"Unlimited") == 0;
}

static bool test_bandwidth_token_empty_unlimited()
{
	return TransferBandwidthTokenIsUnlimited(L"") && TransferBandwidthTokenIsUnlimited(L"   ") && TransferBandwidthTokenIsUnlimited(L"\x200E") && TransferBandwidthTokenIsUnlimited(NULL);
}

static bool test_bandwidth_token_legacy_max_none()
{
	return TransferBandwidthTokenIsUnlimited(L"MAX") && TransferBandwidthTokenIsUnlimited(L"max") && TransferBandwidthTokenIsUnlimited(L" NONE ") && TransferBandwidthTokenIsUnlimited(L"none");
}

static bool test_bandwidth_token_unlimited_word()
{
	return TransferBandwidthTokenIsUnlimited(L"Unlimited") && TransferBandwidthTokenIsUnlimited(L"UNLIMITED") && TransferBandwidthTokenIsUnlimited(L"unlimited");
}

static bool test_bandwidth_token_localized_unlimited()
{
	return TransferBandwidthTokenIsUnlimited(L"Illimité", L"Illimité") && TransferBandwidthTokenIsUnlimited(L"illimité", L"Illimité") && TransferBandwidthTokenIsUnlimited(L"MAX", L"Illimité");
}

static bool test_bandwidth_token_numeric_is_limited()
{
	return TransferBandwidthTokenIsUnlimited(L"50 KB/s") == false && TransferBandwidthTokenIsUnlimited(L"123 kb/s") == false && TransferBandwidthTokenIsUnlimited(L"0 KB/s") == false;
}

static bool test_bandwidth_token_unknown_not_unlimited()
{
	return TransferBandwidthTokenIsUnlimited(L"garbage") == false && TransferBandwidthTokenIsUnlimited(L"-") == false;
}

static bool test_bandwidth_bytes_to_setting_zero_preserved()
{
	return TransferBandwidthBytesToSetting(0) == 0u;
}

static bool test_bandwidth_share_bytes_zero_points()
{
	return TransferBandwidthShareBytes(1024u, 0u, 100u) == 0u;
}

static bool test_bandwidth_bytes_to_setting_typical()
{
	return TransferBandwidthBytesToSetting(1024) == 1024 && TransferBandwidthBytesToSetting(0xFFFFFFFFull) == 0xFFFFFFFFul;
}

static bool test_bandwidth_bytes_to_meter_limit_unlimited()
{
	return TransferBandwidthBytesToMeterLimit(TransferBandwidthUnlimitedValue()) == 0xFFFFFFFFu &&
	       TransferBandwidthBytesToMeterLimit(8192u) == 8192u;
}

static bool test_bandwidth_bytes_to_setting_overflow_clamps()
{
	return TransferBandwidthBytesToSetting(0x100000000ull) == 0xFFFFFFFFul && TransferBandwidthBytesToSetting(~0ull) == 0xFFFFFFFFul;
}

static unsigned long long legacy_headroom_buggy_formula(DWORD nOutSpeedKbps, unsigned int nFreeBandwidthFactor)
{
	return static_cast<unsigned long long>(nOutSpeedKbps / 8) *
	       static_cast<unsigned long long>((100 - nFreeBandwidthFactor) / 100) * 1024ull;
}

static bool test_connection_kbps_to_bytes_zero()
{
	return TransferConnectionKilobitsToBytesPerSecond(0) == 0 &&
	       TransferConnectionKilobitsToBytesPerSecondDword(0) == TransferBandwidthUnlimitedValue();
}

static bool test_connection_kbps_to_bytes_legacy_defaults()
{
	return TransferConnectionKilobitsToBytesPerSecond(768) == 98304ull &&
	       TransferConnectionKilobitsToBytesPerSecond(4096) == 524288ull;
}

static bool test_connection_kbps_to_bytes_multigig()
{
	return TransferConnectionKilobitsToBytesPerSecond(100000) == 12800000ull &&
	       TransferConnectionKilobitsToBytesPerSecond(1000000) == 128000000ull &&
	       TransferConnectionKilobitsToBytesPerSecond(10000000) == 1280000000ull &&
	       TransferConnectionKilobitsToBytesPerSecond(2500000) == 320000000ull &&
	       TransferConnectionKilobitsToBytesPerSecond(5000000) == 640000000ull;
}

static bool test_connection_kbps_overflow_boundary_no_wrap()
{
	const DWORD nBelow = 4194303u;
	const DWORD nAt = 4194304u;
	const unsigned long long nExpectedBelow = static_cast<unsigned long long>(nBelow) * 128ull;
	const unsigned long long nExpectedAt = static_cast<unsigned long long>(nAt) * 128ull;
	const unsigned long long nWrongAt =
	    static_cast<unsigned long long>(static_cast<DWORD>(nAt * 1024u) / 8u);
	return TransferConnectionKilobitsToBytesPerSecond(nBelow) == nExpectedBelow &&
	       TransferConnectionKilobitsToBytesPerSecond(nAt) == nExpectedAt &&
	       nWrongAt != nExpectedAt;
}

static bool test_connection_kbps_saturation_to_dword()
{
	return TransferConnectionKilobitsToBytesPerSecondDword(50000000u) == 0xFFFFFFFFul;
}

static bool test_bandwidth_apply_usable_percent_factors()
{
	const unsigned long long nCapacity = 100000ull;
	return TransferBandwidthApplyUsablePercent(nCapacity, 0) == 100000ull &&
	       TransferBandwidthApplyUsablePercent(nCapacity, 1) == 99000ull &&
	       TransferBandwidthApplyUsablePercent(nCapacity, 8) == 92000ull &&
	       TransferBandwidthApplyUsablePercent(nCapacity, 50) == 50000ull &&
	       TransferBandwidthApplyUsablePercent(nCapacity, 99) == 1000ull;
}

static bool test_upload_headroom_default_not_accidental_unlimited()
{
	const DWORD nLimit = TransferBandwidthUploadLimitFromOutboundKilobits(768, 8);
	if (nLimit == TransferBandwidthUnlimitedValue())
		return false;
	if (legacy_headroom_buggy_formula(768, 8) != 0)
		return false;
	return nLimit == 90439u;
}

static bool test_upload_headroom_regression_92_over_100_integer_division()
{
	return legacy_headroom_buggy_formula(768, 8) == 0 &&
	       TransferBandwidthUploadLimitFromOutboundKilobits(768, 8) == 90439u;
}

static bool test_upload_headroom_10g_default_reserve()
{
	const DWORD nLimit = TransferBandwidthUploadLimitFromOutboundKilobits(10000000, 8);
	return nLimit == 1177600000u;
}

static bool test_bandwidth_torrent_percent_multigig_no_dword_wrap()
{
	const DWORD nBase = TransferConnectionKilobitsToBytesPerSecondDword(10000000);
	const unsigned long long nScaled = static_cast<unsigned long long>(nBase) * 90ull / 100ull;
	const DWORD nExpected = TransferBandwidthBytesToSetting(nScaled);
	const DWORD nWrapped = (nBase * 90) / 100;
	return nExpected != 0 && nWrapped != nExpected;
}

static bool test_max_per_host_defaults_and_range()
{
	return TransferMaxPerHostDefault() == 2 && TransferMaxPerHostMin() == 1 && TransferMaxPerHostMax() == 64;
}

static bool test_max_per_host_clamp_bounds()
{
	return TransferMaxPerHostClamp(0) == 1 && TransferMaxPerHostClamp(1) == 1 && TransferMaxPerHostClamp(2) == 2 && TransferMaxPerHostClamp(64) == 64 && TransferMaxPerHostClamp(65) == 64 && TransferMaxPerHostClamp(0xFFFFFFFFull) == 64;
}

static bool test_max_per_host_from_signed()
{
	return TransferMaxPerHostFromSigned(-1) == 1 && TransferMaxPerHostFromSigned(-999999) == 1 && TransferMaxPerHostFromSigned(0) == 1 && TransferMaxPerHostFromSigned(32) == 32 && TransferMaxPerHostFromSigned(65) == 64;
}

static bool test_fair_use_implemented_opt_in()
{
	return TransferFairUseModeImplemented() == true && TransferFairUseModeDefault() == false && TransferFairUseSharePercent() == 10 && TransferFairUseGrantLimit() == 4096;
}

static bool test_fair_use_applies_only_to_complete_media()
{
	return TransferFairUseApplies(true, true, false, false) == true && TransferFairUseApplies(false, true, false, false) == false && TransferFairUseApplies(true, false, false, false) == false && TransferFairUseApplies(true, true, true, false) == false && TransferFairUseApplies(true, true, false, true) == false && TransferFairUseIsMedia(true, false) == true && TransferFairUseIsMedia(false, true) == true && TransferFairUseIsMedia(false, false) == false;
}

static bool test_fair_use_max_bytes_ten_percent()
{
	return TransferFairUseMaxBytes(0) == 0 && TransferFairUseMaxBytes(1) == 1 && TransferFairUseMaxBytes(9) == 1 && TransferFairUseMaxBytes(10) == 1 && TransferFairUseMaxBytes(100) == 10 && TransferFairUseMaxBytes(1000) == 100 && TransferFairUseMaxBytes(0x100000000ull) == 0x100000000ull / 10ull;
}

static bool test_fair_use_clip_first_request()
{
	unsigned long long nOffset = 0;
	unsigned long long nLength = 1000;
	if (!TransferFairUseClipRange(nOffset, nLength, 1000, 0))
		return false;
	return nOffset == 0 && nLength == 100;
}

static bool test_fair_use_clip_remaining_then_deny()
{
	unsigned long long nOffset = 0;
	unsigned long long nLength = 1000;
	if (!TransferFairUseClipRange(nOffset, nLength, 1000, 60))
		return false;
	if (nOffset != 0 || nLength != 40)
		return false;
	nOffset = 100;
	nLength = 50;
	return TransferFairUseClipRange(nOffset, nLength, 1000, 100) == false;
}

static bool test_fair_use_clip_keeps_requested_offset()
{
	unsigned long long nOffset = 500;
	unsigned long long nLength = 400;
	if (!TransferFairUseClipRange(nOffset, nLength, 1000, 0))
		return false;
	return nOffset == 500 && nLength == 100;
}

static bool test_fair_use_clip_past_eof_denied()
{
	unsigned long long nOffset = 1000;
	unsigned long long nLength = 10;
	return TransferFairUseClipRange(nOffset, nLength, 1000, 0) == false;
}

static bool test_fair_use_saturating_add()
{
	return TransferFairUseSaturatingAdd(0, 0) == 0 && TransferFairUseSaturatingAdd(40, 60) == 100 && TransferFairUseSaturatingAdd(~0ull, 1) == ~0ull && TransferFairUseSaturatingAdd(~0ull - 5ull, 5) == ~0ull && TransferFairUseSaturatingAdd(~0ull - 5ull, 6) == ~0ull;
}

static bool test_fair_use_charge_body_and_unused()
{
	// HEAD / no body: reservation stays unused and can roll back in full.
	if (TransferFairUseChargeBody(100, 0, 0) != 0)
		return false;
	if (TransferFairUseUnused(100, 0) != 100)
		return false;

	// Partial GET then abort: only sent bytes stay charged.
	const unsigned long long nAfter40 = TransferFairUseChargeBody(100, 0, 40);
	if (nAfter40 != 40 || TransferFairUseUnused(100, nAfter40) != 60)
		return false;

	// Complete GET: unused is 0 (nothing to roll back).
	const unsigned long long nAfter100 = TransferFairUseChargeBody(100, nAfter40, 80);
	if (nAfter100 != 100 || TransferFairUseUnused(100, nAfter100) != 0)
		return false;

	// Extra body bytes cannot exceed the reservation.
	return TransferFairUseChargeBody(100, 100, 50) == 100 && TransferFairUseUnused(40, 40) == 0 && TransferFairUseUnused(0, 0) == 0;
}

static bool test_throttle_mode_default_average()
{
	return TransferThrottleModeDefault() == false;
}

static bool test_bandwidth_absent_key_loads_unlimited()
{
	DwordSettingStore store;
	return store.Has(L"Bandwidth", L"Uploads") == false && LoadUploads(store) == TransferBandwidthUnlimitedValue();
}

static bool test_bandwidth_save_reload_unlimited()
{
	DwordSettingStore store;
	store.SetDword(L"Bandwidth", L"Uploads", TransferBandwidthUnlimitedValue());
	return LoadUploads(store) == 0 && TransferBandwidthSettingIsUnlimited(LoadUploads(store));
}

static bool test_bandwidth_save_reload_limited()
{
	DwordSettingStore store;
	store.SetDword(L"Bandwidth", L"Uploads", 128000);
	return LoadUploads(store) == 128000;
}

static bool test_bandwidth_old_max_token_maps_to_zero()
{
	// Historical UI wrote ParseVolume("MAX") == 0 into Bandwidth.Uploads.
	DwordSettingStore store;
	store.SetDword(L"Bandwidth", L"Uploads", 0);
	return TransferBandwidthTokenIsUnlimited(L"MAX") && LoadUploads(store) == TransferBandwidthUnlimitedValue();
}

static bool test_max_per_host_absent_key_loads_default()
{
	DwordSettingStore store;
	return LoadMaxPerHost(store) == TransferMaxPerHostDefault();
}

static bool test_max_per_host_save_reload()
{
	DwordSettingStore store;
	store.SetDword(L"Uploads", L"MaxPerHost", 8);
	return LoadMaxPerHost(store) == 8;
}

static bool test_max_per_host_invalid_registry_clamped()
{
	DwordSettingStore store;
	store.SetDword(L"Uploads", L"MaxPerHost", 0);
	if (LoadMaxPerHost(store) != 1)
		return false;
	store.SetDword(L"Uploads", L"MaxPerHost", 9999);
	return LoadMaxPerHost(store) == 64;
}

static bool test_effective_download_unlimited_not_capped_by_capacity()
{
	const DWORD nLegacyIn = 4096u;
	const DWORD nCapBytes = TransferConnectionKilobitsToBytesPerSecondDword(nLegacyIn);
	return TransferEffectiveDownloadLimitBytes(TransferBandwidthUnlimitedValue()) == 0xFFFFFFFFu &&
	       TransferEffectiveDownloadLimitBytes(TransferBandwidthUnlimitedValue()) > nCapBytes;
}

static bool test_effective_download_finite_user_limit()
{
	return TransferEffectiveDownloadLimitBytes(128000u) == 128000u;
}

static bool test_outgoing_heuristic_unlimited_uses_capacity()
{
	return TransferOutgoingBandwidthHeuristicKBps(0, 768u) == 96u &&
	       TransferOutgoingBandwidthHeuristicKBps(0, 4096u) == 512u;
}

static bool test_outgoing_heuristic_finite_user_limit()
{
	const DWORD nUser = 256u * 1024u;
	return TransferOutgoingBandwidthHeuristicKBps(nUser, 4096u) == 256u;
}

static bool test_connection_apply_does_not_sync_upload_limit()
{
	const DWORD nExplicitUpload = 128000u;
	const DWORD nAfterApply = TransferBandwidthUploadAfterConnectionSettingsApply(
	    nExplicitUpload, 10485760u, 8u);
	return nAfterApply == nExplicitUpload;
}

static bool test_wizard_upload_default_only_first_run()
{
	return TransferConnectionCapacityShouldSetWizardUploadDefault(true, false) == true &&
	       TransferConnectionCapacityShouldSetWizardUploadDefault(false, false) == false &&
	       TransferConnectionCapacityShouldSetWizardUploadDefault(true, true) == false;
}

static bool test_capacity_presets_include_modern_values()
{
	bool b100 = false, b300 = false, b500 = false, b1g = false, b25 = false, b5 = false, b10 = false;
	for (unsigned int i = 0; i < TransferConnectionCapacityPresetCount(); ++i)
	{
		const DWORD n = TransferConnectionCapacityPresetKilobits(i);
		if (n == 102400u)
			b100 = true;
		if (n == 307200u)
			b300 = true;
		if (n == 512000u)
			b500 = true;
		if (n == 1024000u)
			b1g = true;
		if (n == 2621440u)
			b25 = true;
		if (n == 5242880u)
			b5 = true;
		if (n == 10485760u)
			b10 = true;
	}
	return b100 && b300 && b500 && b1g && b25 && b5 && b10;
}

static bool test_capacity_presets_sorted_unique()
{
	DWORD nPrev = 0;
	for (unsigned int i = 0; i < TransferConnectionCapacityPresetCount(); ++i)
	{
		const DWORD n = TransferConnectionCapacityPresetKilobits(i);
		if (n <= nPrev)
			return false;
		nPrev = n;
	}
	return true;
}

static bool test_capacity_parse_kbps_wizard_string()
{
	const auto o = TransferConnectionCapacityParseKilobitsText(L"102400 kbps    (12.50 MB/s)");
	return o.eStatus == TransferConnectionCapacityParseStatus::Ok && o.nKilobitsPerSecond == 102400ull;
}

static bool test_capacity_parse_mbps()
{
	const auto o = TransferConnectionCapacityParseKilobitsText(L"100 mbps     (12.50 MB/s)");
	return o.eStatus == TransferConnectionCapacityParseStatus::Ok && o.nKilobitsPerSecond == 102400ull;
}

static bool test_capacity_parse_wizard_mbps_with_kbs_parenthetical()
{
	const auto o = TransferConnectionCapacityParseKilobitsText(L"1.0 mbps    (128 KB/s)");
	return o.eStatus == TransferConnectionCapacityParseStatus::Ok && o.nKilobitsPerSecond == 1024ull;
}

static bool test_capacity_parse_byte_units_to_kilobits()
{
	const auto oMb = TransferConnectionCapacityParseKilobitsText(L"100 MB/s");
	const auto oKb = TransferConnectionCapacityParseKilobitsText(L"512.0 KB/s");
	return oMb.eStatus == TransferConnectionCapacityParseStatus::Ok && oMb.nKilobitsPerSecond == 819200ull &&
	       oKb.eStatus == TransferConnectionCapacityParseStatus::Ok && oKb.nKilobitsPerSecond == 4096ull;
}

static bool test_capacity_parse_bits_per_sec_smart_speed()
{
	const auto o = TransferConnectionCapacityParseKilobitsText(L"104857600 b/s");
	return o.eStatus == TransferConnectionCapacityParseStatus::Ok && o.nKilobitsPerSecond == 102400ull;
}

static bool test_wizard_profiles_use_canonical_gigabit_capacity()
{
	return TransferConnectionCapacityWizardProfileDownload(18) == 1024000u &&
	       TransferConnectionCapacityWizardProfileUpload(18) == 921600u;
}

static bool test_capacity_parse_rejects_nan()
{
	const auto o = TransferConnectionCapacityParseKilobitsText(L"nan mbps");
	return o.eStatus == TransferConnectionCapacityParseStatus::Negative;
}

static bool test_capacity_parse_garbage_not_gigabit()
{
	const auto o = TransferConnectionCapacityParseKilobitsText(L"100 garbage");
	return o.eStatus == TransferConnectionCapacityParseStatus::Ok && o.nKilobitsPerSecond == 100ull;
}

static bool test_bandwidth_share_bytes_10g_no_wrap()
{
	const DWORD nRef = TransferConnectionKilobitsToBytesPerSecondDword(10485760u);
	const DWORD nShare = TransferBandwidthShareBytes(nRef, 30u, 100u);
	const unsigned long long nExpected =
	    static_cast<unsigned long long>(nRef) * 30ull / 100ull;
	return nShare == static_cast<DWORD>(nExpected);
}

static bool test_capacity_parse_gbps()
{
	const auto o = TransferConnectionCapacityParseKilobitsText(L"10 gbps");
	return o.eStatus == TransferConnectionCapacityParseStatus::Ok && o.nKilobitsPerSecond == 10485760ull;
}

static bool test_capacity_parse_malformed()
{
	const auto o = TransferConnectionCapacityParseKilobitsText(L"not-a-speed");
	return o.eStatus == TransferConnectionCapacityParseStatus::Malformed;
}

static bool test_capacity_parse_negative()
{
	const auto o = TransferConnectionCapacityParseKilobitsText(L"-50 mbps");
	return o.eStatus == TransferConnectionCapacityParseStatus::Negative;
}

static bool test_capacity_parse_overflow()
{
	const auto o = TransferConnectionCapacityParseKilobitsText(L"50000 gbps");
	return o.eStatus == TransferConnectionCapacityParseStatus::Overflow;
}

void register_transfer_settings_limits_smoke_tests(TestSuite& suite)
{
	suite.add_test("transfer_bandwidth_unlimited_value_is_zero",
	               test_bandwidth_unlimited_value_is_zero);
	suite.add_test("transfer_bandwidth_display_token_unlimited",
	               test_bandwidth_display_token_unlimited);
	suite.add_test("transfer_bandwidth_token_empty_unlimited",
	               test_bandwidth_token_empty_unlimited);
	suite.add_test("transfer_bandwidth_token_legacy_max_none",
	               test_bandwidth_token_legacy_max_none);
	suite.add_test("transfer_bandwidth_token_unlimited_word",
	               test_bandwidth_token_unlimited_word);
	suite.add_test("transfer_bandwidth_token_localized_unlimited",
	               test_bandwidth_token_localized_unlimited);
	suite.add_test("transfer_bandwidth_token_numeric_is_limited",
	               test_bandwidth_token_numeric_is_limited);
	suite.add_test("transfer_bandwidth_token_unknown_not_unlimited",
	               test_bandwidth_token_unknown_not_unlimited);
	suite.add_test("transfer_bandwidth_bytes_to_setting_zero_preserved",
	               test_bandwidth_bytes_to_setting_zero_preserved);
	suite.add_test("transfer_bandwidth_share_bytes_zero_points",
	               test_bandwidth_share_bytes_zero_points);
	suite.add_test("transfer_bandwidth_bytes_to_setting_typical",
	               test_bandwidth_bytes_to_setting_typical);
	suite.add_test("transfer_bandwidth_bytes_to_meter_limit_unlimited",
	               test_bandwidth_bytes_to_meter_limit_unlimited);
	suite.add_test("transfer_bandwidth_bytes_to_setting_overflow_clamps",
	               test_bandwidth_bytes_to_setting_overflow_clamps);
	suite.add_test("transfer_connection_kbps_to_bytes_zero",
	               test_connection_kbps_to_bytes_zero);
	suite.add_test("transfer_connection_kbps_to_bytes_legacy_defaults",
	               test_connection_kbps_to_bytes_legacy_defaults);
	suite.add_test("transfer_connection_kbps_to_bytes_multigig",
	               test_connection_kbps_to_bytes_multigig);
	suite.add_test("transfer_connection_kbps_overflow_boundary_no_wrap",
	               test_connection_kbps_overflow_boundary_no_wrap);
	suite.add_test("transfer_connection_kbps_saturation_to_dword",
	               test_connection_kbps_saturation_to_dword);
	suite.add_test("transfer_bandwidth_apply_usable_percent_factors",
	               test_bandwidth_apply_usable_percent_factors);
	suite.add_test("transfer_upload_headroom_default_not_accidental_unlimited",
	               test_upload_headroom_default_not_accidental_unlimited);
	suite.add_test("transfer_upload_headroom_regression_92_over_100_integer_division",
	               test_upload_headroom_regression_92_over_100_integer_division);
	suite.add_test("transfer_upload_headroom_10g_default_reserve",
	               test_upload_headroom_10g_default_reserve);
	suite.add_test("transfer_max_per_host_defaults_and_range",
	               test_max_per_host_defaults_and_range);
	suite.add_test("transfer_max_per_host_clamp_bounds",
	               test_max_per_host_clamp_bounds);
	suite.add_test("transfer_max_per_host_from_signed",
	               test_max_per_host_from_signed);
	suite.add_test("transfer_fair_use_implemented_opt_in",
	               test_fair_use_implemented_opt_in);
	suite.add_test("transfer_fair_use_applies_only_to_complete_media",
	               test_fair_use_applies_only_to_complete_media);
	suite.add_test("transfer_fair_use_max_bytes_ten_percent",
	               test_fair_use_max_bytes_ten_percent);
	suite.add_test("transfer_fair_use_clip_first_request",
	               test_fair_use_clip_first_request);
	suite.add_test("transfer_fair_use_clip_remaining_then_deny",
	               test_fair_use_clip_remaining_then_deny);
	suite.add_test("transfer_fair_use_clip_keeps_requested_offset",
	               test_fair_use_clip_keeps_requested_offset);
	suite.add_test("transfer_fair_use_clip_past_eof_denied",
	               test_fair_use_clip_past_eof_denied);
	suite.add_test("transfer_fair_use_saturating_add",
	               test_fair_use_saturating_add);
	suite.add_test("transfer_fair_use_charge_body_and_unused",
	               test_fair_use_charge_body_and_unused);
	suite.add_test("transfer_throttle_mode_default_average",
	               test_throttle_mode_default_average);
	suite.add_test("transfer_bandwidth_absent_key_loads_unlimited",
	               test_bandwidth_absent_key_loads_unlimited);
	suite.add_test("transfer_bandwidth_save_reload_unlimited",
	               test_bandwidth_save_reload_unlimited);
	suite.add_test("transfer_bandwidth_save_reload_limited",
	               test_bandwidth_save_reload_limited);
	suite.add_test("transfer_bandwidth_old_max_token_maps_to_zero",
	               test_bandwidth_old_max_token_maps_to_zero);
	suite.add_test("transfer_max_per_host_absent_key_loads_default",
	               test_max_per_host_absent_key_loads_default);
	suite.add_test("transfer_max_per_host_save_reload",
	               test_max_per_host_save_reload);
	suite.add_test("transfer_max_per_host_invalid_registry_clamped",
	               test_max_per_host_invalid_registry_clamped);
	suite.add_test("transfer_effective_download_unlimited_not_capped_by_capacity",
	               test_effective_download_unlimited_not_capped_by_capacity);
	suite.add_test("transfer_effective_download_finite_user_limit",
	               test_effective_download_finite_user_limit);
	suite.add_test("transfer_outgoing_heuristic_unlimited_uses_capacity",
	               test_outgoing_heuristic_unlimited_uses_capacity);
	suite.add_test("transfer_outgoing_heuristic_finite_user_limit",
	               test_outgoing_heuristic_finite_user_limit);
	suite.add_test("transfer_connection_apply_does_not_sync_upload_limit",
	               test_connection_apply_does_not_sync_upload_limit);
	suite.add_test("transfer_wizard_upload_default_only_first_run",
	               test_wizard_upload_default_only_first_run);
	suite.add_test("transfer_capacity_presets_include_modern_values",
	               test_capacity_presets_include_modern_values);
	suite.add_test("transfer_capacity_presets_sorted_unique",
	               test_capacity_presets_sorted_unique);
	suite.add_test("transfer_capacity_parse_kbps_wizard_string",
	               test_capacity_parse_kbps_wizard_string);
	suite.add_test("transfer_capacity_parse_mbps",
	               test_capacity_parse_mbps);
	suite.add_test("transfer_capacity_parse_wizard_mbps_with_kbs_parenthetical",
	               test_capacity_parse_wizard_mbps_with_kbs_parenthetical);
	suite.add_test("transfer_capacity_parse_byte_units_to_kilobits",
	               test_capacity_parse_byte_units_to_kilobits);
	suite.add_test("transfer_capacity_parse_bits_per_sec_smart_speed",
	               test_capacity_parse_bits_per_sec_smart_speed);
	suite.add_test("transfer_wizard_profiles_use_canonical_gigabit_capacity",
	               test_wizard_profiles_use_canonical_gigabit_capacity);
	suite.add_test("transfer_capacity_parse_rejects_nan",
	               test_capacity_parse_rejects_nan);
	suite.add_test("transfer_capacity_parse_garbage_not_gigabit",
	               test_capacity_parse_garbage_not_gigabit);
	suite.add_test("transfer_bandwidth_share_bytes_10g_no_wrap",
	               test_bandwidth_share_bytes_10g_no_wrap);
	suite.add_test("transfer_capacity_parse_gbps",
	               test_capacity_parse_gbps);
	suite.add_test("transfer_capacity_parse_malformed",
	               test_capacity_parse_malformed);
	suite.add_test("transfer_capacity_parse_negative",
	               test_capacity_parse_negative);
	suite.add_test("transfer_capacity_parse_overflow",
	               test_capacity_parse_overflow);
}
