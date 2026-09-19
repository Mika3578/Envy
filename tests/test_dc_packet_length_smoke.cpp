//
// test_dc_packet_length_smoke.cpp
//
// Smoke tests for NMDC/DC prefixed-payload length guards (#81) and
// $ADCGET / $ADCSND numeric token validation.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/DcPacketLengthValidate.h"
#include "../Envy/DcAdcGetValidate.h"

static bool test_dc_hubtopic_prefix_rejects_exact_prefix()
{
	// Compare can succeed at length==prefix; decode must still require '|'.
	return DcPrefixedPayloadLengthOk( DC_HUBTOPIC_PREFIX_LEN, DC_HUBTOPIC_PREFIX_LEN ) == FALSE
		&& DcPrefixedPayloadLengthOk( DC_HUBTOPIC_PREFIX_LEN + 1, DC_HUBTOPIC_PREFIX_LEN ) != FALSE
		&& DcPrefixedPayloadBytes( DC_HUBTOPIC_PREFIX_LEN + 1, DC_HUBTOPIC_PREFIX_LEN ) == 0;
}

static bool test_dc_hubname_prefix_rejects_exact_prefix()
{
	return DcPrefixedPayloadLengthOk( DC_HUBNAME_PREFIX_LEN, DC_HUBNAME_PREFIX_LEN ) == FALSE
		&& DcPrefixedPayloadLengthOk( DC_HUBNAME_PREFIX_LEN + 3, DC_HUBNAME_PREFIX_LEN ) != FALSE
		&& DcPrefixedPayloadBytes( DC_HUBNAME_PREFIX_LEN + 3, DC_HUBNAME_PREFIX_LEN ) == 2;
}

static bool test_dc_chat_angle_min_length()
{
	return DcChatAnglePayloadLengthOk( 1 ) == FALSE
		&& DcChatAnglePayloadLengthOk( 2 ) != FALSE
		&& DcChatAnglePayloadBytes( 5 ) == 3;
}

static bool test_dc_hubname_description_bounds()
{
	// Space at index 9: need at least one byte after for '|'.
	return DcHubNameDescriptionLengthOk( 10, 9 ) == FALSE
		&& DcHubNameDescriptionLengthOk( 11, 9 ) != FALSE
		&& DcHubNameDescriptionBytes( 11, 9 ) == 0
		&& DcHubNameDescriptionBytes( 14, 9 ) == 3
		&& DcHubNameDescriptionLengthOk( 10, -1 ) == FALSE;
}

static bool test_dc_hub_user_count_bounds()
{
	if (DC_HUB_USERS_MAX != 20000u)
		return false;
	return DcHubUserCountOk(0) == TRUE
		&& DcHubUserCountOk(19999u) == TRUE
		&& DcHubUserCountOk(20000u) == FALSE
		&& DcHubUserCountOk(20001u) == FALSE;
}

static bool test_dc_adc_offset_rejects_sign_and_junk()
{
	ULONGLONG n = 0;
	return DcParseAdcOffsetToken( "0", &n ) != FALSE && n == 0
		&& DcParseAdcOffsetToken( "42", &n ) != FALSE && n == 42
		&& DcParseAdcOffsetToken( "-1", &n ) == FALSE
		&& DcParseAdcOffsetToken( "123x", &n ) == FALSE
		&& DcParseAdcOffsetToken( "", &n ) == FALSE
		&& DcParseAdcOffsetToken( "+", &n ) == FALSE
		&& DcParseAdcOffsetToken( "01", &n ) != FALSE && n == 1;
}

static bool test_dc_adcget_length_allows_until_end_only()
{
	ULONGLONG n = 0;
	return DcParseAdcGetLengthToken( "-1", &n ) != FALSE && n == DC_ADC_LENGTH_UNTIL_END
		&& DcParseAdcGetLengthToken( "0", &n ) != FALSE && n == 0
		&& DcParseAdcGetLengthToken( "100", &n ) != FALSE && n == 100
		&& DcParseAdcGetLengthToken( "-2", &n ) == FALSE
		&& DcParseAdcGetLengthToken( "123x", &n ) == FALSE
		&& DcParseAdcGetLengthToken( "", &n ) == FALSE
		&& DcParseAdcGetLengthToken( "-1x", &n ) == FALSE
		&& DcParseAdcGetLengthToken( "--1", &n ) == FALSE;
}

static bool test_dc_adcsnd_length_rejects_until_end()
{
	ULONGLONG n = 0;
	return DcParseAdcSndLengthToken( "-1", &n ) == FALSE
		&& DcParseAdcSndLengthToken( "0", &n ) != FALSE && n == 0
		&& DcParseAdcSndLengthToken( "4096", &n ) != FALSE && n == 4096
		&& DcParseAdcSndLengthToken( "123x", &n ) == FALSE
		&& DcParseAdcSndLengthToken( "", &n ) == FALSE;
}

static bool test_dc_adc_u64_overflow_reject()
{
	ULONGLONG n = 0;
	const char kEmbeddedNul[] = { '1', '2', '3', '\0', 'x' };
	// 2^64 == 18446744073709551616 — one past max ULONGLONG
	// 2^64-1 is reserved as until-end sentinel; reject all-digits smuggle.
	return DcParseUnsignedDecimalU64( "18446744073709551616", &n ) == FALSE
		&& DcParseUnsignedDecimalU64( "18446744073709551615", &n ) == FALSE
		&& DcParseUnsignedDecimalU64( "18446744073709551614", &n ) != FALSE
		&& n == ( DC_ADC_LENGTH_UNTIL_END - 1ull )
		&& DcParseAdcOffsetToken( kEmbeddedNul, sizeof( kEmbeddedNul ), &n ) == FALSE
		&& DcParseAdcGetLengthToken( kEmbeddedNul, sizeof( kEmbeddedNul ), &n ) == FALSE
		&& DcParseAdcSndLengthToken( kEmbeddedNul, sizeof( kEmbeddedNul ), &n ) == FALSE
		&& DcParseAdcGetLengthToken( "-1", 2, &n ) != FALSE && n == DC_ADC_LENGTH_UNTIL_END;
}

static bool test_dc_adcsnd_length_matches_request()
{
	return DcAdcSndLengthMatchesRequest( 100, 100 ) != FALSE
		&& DcAdcSndLengthMatchesRequest( 100, 99 ) == FALSE
		&& DcAdcSndLengthMatchesRequest( 100, 101 ) == FALSE
		&& DcAdcSndLengthMatchesRequest( DC_ADC_LENGTH_UNTIL_END, 50 ) != FALSE
		&& DcAdcSndLengthMatchesRequest( DC_ADC_LENGTH_UNTIL_END, DC_ADC_LENGTH_UNTIL_END ) == FALSE
		&& DcAdcSndLengthMatchesRequest( 100, DC_ADC_LENGTH_UNTIL_END ) == FALSE;
}

void register_dc_packet_length_smoke_tests(TestSuite& suite)
{
	suite.add_test("dc_hubtopic_prefix_rejects_exact_prefix", test_dc_hubtopic_prefix_rejects_exact_prefix);
	suite.add_test("dc_hubname_prefix_rejects_exact_prefix", test_dc_hubname_prefix_rejects_exact_prefix);
	suite.add_test("dc_chat_angle_min_length", test_dc_chat_angle_min_length);
	suite.add_test("dc_hubname_description_bounds", test_dc_hubname_description_bounds);
	suite.add_test("dc_hub_user_count_bounds", test_dc_hub_user_count_bounds);
	suite.add_test("dc_adc_offset_rejects_sign_and_junk", test_dc_adc_offset_rejects_sign_and_junk);
	suite.add_test("dc_adcget_length_allows_until_end_only", test_dc_adcget_length_allows_until_end_only);
	suite.add_test("dc_adcsnd_length_rejects_until_end", test_dc_adcsnd_length_rejects_until_end);
	suite.add_test("dc_adc_u64_overflow_reject", test_dc_adc_u64_overflow_reject);
	suite.add_test("dc_adcsnd_length_matches_request", test_dc_adcsnd_length_matches_request);
}
