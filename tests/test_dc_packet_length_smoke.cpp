//
// test_dc_packet_length_smoke.cpp
//
// Smoke tests for NMDC/DC prefixed-payload length guards (#81).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/DcPacketLengthValidate.h"

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

void register_dc_packet_length_smoke_tests(TestSuite& suite)
{
	suite.add_test("dc_hubtopic_prefix_rejects_exact_prefix", test_dc_hubtopic_prefix_rejects_exact_prefix);
	suite.add_test("dc_hubname_prefix_rejects_exact_prefix", test_dc_hubname_prefix_rejects_exact_prefix);
	suite.add_test("dc_chat_angle_min_length", test_dc_chat_angle_min_length);
	suite.add_test("dc_hubname_description_bounds", test_dc_hubname_description_bounds);
	suite.add_test("dc_hub_user_count_bounds", test_dc_hub_user_count_bounds);
}
