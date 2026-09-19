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

#include <cwchar>
#include <map>
#include <string>

namespace {

class DwordSettingStore
{
public:
	void SetDword(LPCTSTR pszSection, LPCTSTR pszName, DWORD nValue)
	{
		m_oValues[ Key( pszSection, pszName ) ] = nValue;
	}

	bool Has(LPCTSTR pszSection, LPCTSTR pszName) const
	{
		return m_oValues.find( Key( pszSection, pszName ) ) != m_oValues.end();
	}

	void Delete(LPCTSTR pszSection, LPCTSTR pszName)
	{
		m_oValues.erase( Key( pszSection, pszName ) );
	}

	DWORD GetDword(LPCTSTR pszSection, LPCTSTR pszName, DWORD nDefault) const
	{
		const auto it = m_oValues.find( Key( pszSection, pszName ) );
		if ( it == m_oValues.end() )
			return nDefault;
		return it->second;
	}

private:
	static std::wstring Key(LPCTSTR pszSection, LPCTSTR pszName)
	{
		std::wstring s( pszSection ? pszSection : L"" );
		s.push_back( L'\\' );
		s.append( pszName ? pszName : L"" );
		return s;
	}

	std::map< std::wstring, DWORD > m_oValues;
};

DWORD LoadUploads(const DwordSettingStore& store)
{
	return store.GetDword( L"Bandwidth", L"Uploads", TransferBandwidthUnlimitedValue() );
}

DWORD LoadMaxPerHost(const DwordSettingStore& store)
{
	DWORD nValue = store.GetDword( L"Uploads", L"MaxPerHost", TransferMaxPerHostDefault() );
	return TransferMaxPerHostClamp( nValue );
}

} // namespace

static bool test_bandwidth_unlimited_value_is_zero()
{
	return TransferBandwidthUnlimitedValue() == 0
		&& TransferBandwidthSettingIsUnlimited( 0 ) == true
		&& TransferBandwidthSettingIsUnlimited( 1 ) == false;
}

static bool test_bandwidth_display_token_unlimited()
{
	return wcscmp( TransferBandwidthUnlimitedDisplayToken(), L"Unlimited" ) == 0;
}

static bool test_bandwidth_token_empty_unlimited()
{
	return TransferBandwidthTokenIsUnlimited( L"" )
		&& TransferBandwidthTokenIsUnlimited( L"   " )
		&& TransferBandwidthTokenIsUnlimited( L"\x200E" )
		&& TransferBandwidthTokenIsUnlimited( NULL );
}

static bool test_bandwidth_token_legacy_max_none()
{
	return TransferBandwidthTokenIsUnlimited( L"MAX" )
		&& TransferBandwidthTokenIsUnlimited( L"max" )
		&& TransferBandwidthTokenIsUnlimited( L" NONE " )
		&& TransferBandwidthTokenIsUnlimited( L"none" );
}

static bool test_bandwidth_token_unlimited_word()
{
	return TransferBandwidthTokenIsUnlimited( L"Unlimited" )
		&& TransferBandwidthTokenIsUnlimited( L"UNLIMITED" )
		&& TransferBandwidthTokenIsUnlimited( L"unlimited" );
}

static bool test_bandwidth_token_localized_unlimited()
{
	return TransferBandwidthTokenIsUnlimited( L"Illimité", L"Illimité" )
		&& TransferBandwidthTokenIsUnlimited( L"illimité", L"Illimité" )
		&& TransferBandwidthTokenIsUnlimited( L"MAX", L"Illimité" );
}

static bool test_bandwidth_token_numeric_is_limited()
{
	return TransferBandwidthTokenIsUnlimited( L"50 KB/s" ) == false
		&& TransferBandwidthTokenIsUnlimited( L"123 kb/s" ) == false
		&& TransferBandwidthTokenIsUnlimited( L"0 KB/s" ) == false;
}

static bool test_bandwidth_token_unknown_not_unlimited()
{
	return TransferBandwidthTokenIsUnlimited( L"garbage" ) == false
		&& TransferBandwidthTokenIsUnlimited( L"-" ) == false;
}

static bool test_bandwidth_bytes_to_setting_zero_unlimited()
{
	return TransferBandwidthBytesToSetting( 0 ) == TransferBandwidthUnlimitedValue();
}

static bool test_bandwidth_bytes_to_setting_typical()
{
	return TransferBandwidthBytesToSetting( 1024 ) == 1024
		&& TransferBandwidthBytesToSetting( 0xFFFFFFFFull ) == 0xFFFFFFFFul;
}

static bool test_bandwidth_bytes_to_setting_overflow_clamps()
{
	return TransferBandwidthBytesToSetting( 0x100000000ull ) == 0xFFFFFFFFul
		&& TransferBandwidthBytesToSetting( ~0ull ) == 0xFFFFFFFFul;
}

static bool test_max_per_host_defaults_and_range()
{
	return TransferMaxPerHostDefault() == 2
		&& TransferMaxPerHostMin() == 1
		&& TransferMaxPerHostMax() == 64;
}

static bool test_max_per_host_clamp_bounds()
{
	return TransferMaxPerHostClamp( 0 ) == 1
		&& TransferMaxPerHostClamp( 1 ) == 1
		&& TransferMaxPerHostClamp( 2 ) == 2
		&& TransferMaxPerHostClamp( 64 ) == 64
		&& TransferMaxPerHostClamp( 65 ) == 64
		&& TransferMaxPerHostClamp( 0xFFFFFFFFull ) == 64;
}

static bool test_max_per_host_from_signed()
{
	return TransferMaxPerHostFromSigned( -1 ) == 1
		&& TransferMaxPerHostFromSigned( -999999 ) == 1
		&& TransferMaxPerHostFromSigned( 0 ) == 1
		&& TransferMaxPerHostFromSigned( 32 ) == 32
		&& TransferMaxPerHostFromSigned( 65 ) == 64;
}

static bool test_fair_use_implemented_opt_in()
{
	return TransferFairUseModeImplemented() == true
		&& TransferFairUseModeDefault() == false
		&& TransferFairUseSharePercent() == 10
		&& TransferFairUseGrantLimit() == 4096;
}

static bool test_fair_use_applies_only_to_complete_media()
{
	return TransferFairUseApplies( true, true, false, false ) == true
		&& TransferFairUseApplies( false, true, false, false ) == false
		&& TransferFairUseApplies( true, false, false, false ) == false
		&& TransferFairUseApplies( true, true, true, false ) == false
		&& TransferFairUseApplies( true, true, false, true ) == false
		&& TransferFairUseIsMedia( true, false ) == true
		&& TransferFairUseIsMedia( false, true ) == true
		&& TransferFairUseIsMedia( false, false ) == false;
}

static bool test_fair_use_max_bytes_ten_percent()
{
	return TransferFairUseMaxBytes( 0 ) == 0
		&& TransferFairUseMaxBytes( 1 ) == 1
		&& TransferFairUseMaxBytes( 9 ) == 1
		&& TransferFairUseMaxBytes( 10 ) == 1
		&& TransferFairUseMaxBytes( 100 ) == 10
		&& TransferFairUseMaxBytes( 1000 ) == 100
		&& TransferFairUseMaxBytes( 0x100000000ull ) == 0x100000000ull / 10ull;
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

static bool test_throttle_mode_default_average()
{
	return TransferThrottleModeDefault() == false;
}

static bool test_bandwidth_absent_key_loads_unlimited()
{
	DwordSettingStore store;
	return store.Has( L"Bandwidth", L"Uploads" ) == false
		&& LoadUploads( store ) == TransferBandwidthUnlimitedValue();
}

static bool test_bandwidth_save_reload_unlimited()
{
	DwordSettingStore store;
	store.SetDword( L"Bandwidth", L"Uploads", TransferBandwidthUnlimitedValue() );
	return LoadUploads( store ) == 0
		&& TransferBandwidthSettingIsUnlimited( LoadUploads( store ) );
}

static bool test_bandwidth_save_reload_limited()
{
	DwordSettingStore store;
	store.SetDword( L"Bandwidth", L"Uploads", 128000 );
	return LoadUploads( store ) == 128000;
}

static bool test_bandwidth_old_max_token_maps_to_zero()
{
	// Historical UI wrote ParseVolume("MAX") == 0 into Bandwidth.Uploads.
	DwordSettingStore store;
	store.SetDword( L"Bandwidth", L"Uploads", 0 );
	return TransferBandwidthTokenIsUnlimited( L"MAX" )
		&& LoadUploads( store ) == TransferBandwidthUnlimitedValue();
}

static bool test_max_per_host_absent_key_loads_default()
{
	DwordSettingStore store;
	return LoadMaxPerHost( store ) == TransferMaxPerHostDefault();
}

static bool test_max_per_host_save_reload()
{
	DwordSettingStore store;
	store.SetDword( L"Uploads", L"MaxPerHost", 8 );
	return LoadMaxPerHost( store ) == 8;
}

static bool test_max_per_host_invalid_registry_clamped()
{
	DwordSettingStore store;
	store.SetDword( L"Uploads", L"MaxPerHost", 0 );
	if ( LoadMaxPerHost( store ) != 1 )
		return false;
	store.SetDword( L"Uploads", L"MaxPerHost", 9999 );
	return LoadMaxPerHost( store ) == 64;
}

void register_transfer_settings_limits_smoke_tests(TestSuite& suite)
{
	suite.add_test( "transfer_bandwidth_unlimited_value_is_zero",
		test_bandwidth_unlimited_value_is_zero );
	suite.add_test( "transfer_bandwidth_display_token_unlimited",
		test_bandwidth_display_token_unlimited );
	suite.add_test( "transfer_bandwidth_token_empty_unlimited",
		test_bandwidth_token_empty_unlimited );
	suite.add_test( "transfer_bandwidth_token_legacy_max_none",
		test_bandwidth_token_legacy_max_none );
	suite.add_test( "transfer_bandwidth_token_unlimited_word",
		test_bandwidth_token_unlimited_word );
	suite.add_test( "transfer_bandwidth_token_localized_unlimited",
		test_bandwidth_token_localized_unlimited );
	suite.add_test( "transfer_bandwidth_token_numeric_is_limited",
		test_bandwidth_token_numeric_is_limited );
	suite.add_test( "transfer_bandwidth_token_unknown_not_unlimited",
		test_bandwidth_token_unknown_not_unlimited );
	suite.add_test( "transfer_bandwidth_bytes_to_setting_zero_unlimited",
		test_bandwidth_bytes_to_setting_zero_unlimited );
	suite.add_test( "transfer_bandwidth_bytes_to_setting_typical",
		test_bandwidth_bytes_to_setting_typical );
	suite.add_test( "transfer_bandwidth_bytes_to_setting_overflow_clamps",
		test_bandwidth_bytes_to_setting_overflow_clamps );
	suite.add_test( "transfer_max_per_host_defaults_and_range",
		test_max_per_host_defaults_and_range );
	suite.add_test( "transfer_max_per_host_clamp_bounds",
		test_max_per_host_clamp_bounds );
	suite.add_test( "transfer_max_per_host_from_signed",
		test_max_per_host_from_signed );
	suite.add_test( "transfer_fair_use_implemented_opt_in",
		test_fair_use_implemented_opt_in );
	suite.add_test( "transfer_fair_use_applies_only_to_complete_media",
		test_fair_use_applies_only_to_complete_media );
	suite.add_test( "transfer_fair_use_max_bytes_ten_percent",
		test_fair_use_max_bytes_ten_percent );
	suite.add_test( "transfer_fair_use_clip_first_request",
		test_fair_use_clip_first_request );
	suite.add_test( "transfer_fair_use_clip_remaining_then_deny",
		test_fair_use_clip_remaining_then_deny );
	suite.add_test( "transfer_fair_use_clip_keeps_requested_offset",
		test_fair_use_clip_keeps_requested_offset );
	suite.add_test( "transfer_fair_use_clip_past_eof_denied",
		test_fair_use_clip_past_eof_denied );
	suite.add_test( "transfer_throttle_mode_default_average",
		test_throttle_mode_default_average );
	suite.add_test( "transfer_bandwidth_absent_key_loads_unlimited",
		test_bandwidth_absent_key_loads_unlimited );
	suite.add_test( "transfer_bandwidth_save_reload_unlimited",
		test_bandwidth_save_reload_unlimited );
	suite.add_test( "transfer_bandwidth_save_reload_limited",
		test_bandwidth_save_reload_limited );
	suite.add_test( "transfer_bandwidth_old_max_token_maps_to_zero",
		test_bandwidth_old_max_token_maps_to_zero );
	suite.add_test( "transfer_max_per_host_absent_key_loads_default",
		test_max_per_host_absent_key_loads_default );
	suite.add_test( "transfer_max_per_host_save_reload",
		test_max_per_host_save_reload );
	suite.add_test( "transfer_max_per_host_invalid_registry_clamped",
		test_max_per_host_invalid_registry_clamped );
}
