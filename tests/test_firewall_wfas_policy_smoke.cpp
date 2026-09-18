//
// test_firewall_wfas_policy_smoke.cpp
//
// Smoke tests for WFAS profile bitmask helpers (#166).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/FirewallWfasPolicy.h"

static bool test_wfas_profile_bits()
{
	return WfasProfileBitEnabled( WFAS_PROFILE_PUBLIC, WFAS_PROFILE_PUBLIC ) != FALSE
		&& WfasProfileBitEnabled( WFAS_PROFILE_PRIVATE, WFAS_PROFILE_PUBLIC ) == FALSE
		&& WfasProfileBitEnabled( WFAS_PROFILE_ALL, WFAS_PROFILE_DOMAIN ) != FALSE;
}

static bool test_wfas_exceptions_empty_mask()
{
	return WfasExceptionsAllowedForMask( 0, TRUE, TRUE, TRUE ) == FALSE;
}

static bool test_wfas_exceptions_public_blocks()
{
	// Active Public profile with BlockAllInboundTraffic → not allowed.
	return WfasExceptionsAllowedForMask(
		WFAS_PROFILE_PUBLIC, TRUE, TRUE, FALSE ) == FALSE;
}

static bool test_wfas_exceptions_private_allows()
{
	return WfasExceptionsAllowedForMask(
		WFAS_PROFILE_PRIVATE, FALSE, TRUE, FALSE ) != FALSE;
}

static bool test_wfas_exceptions_mixed_active_blocks()
{
	// Domain+Public active; Public blocks → overall not allowed.
	return WfasExceptionsAllowedForMask(
		WFAS_PROFILE_DOMAIN | WFAS_PROFILE_PUBLIC, TRUE, TRUE, FALSE ) == FALSE;
}

void register_firewall_wfas_policy_smoke_tests( TestSuite& suite )
{
	suite.add_test( "wfas_profile_bits", test_wfas_profile_bits );
	suite.add_test( "wfas_exceptions_empty_mask", test_wfas_exceptions_empty_mask );
	suite.add_test( "wfas_exceptions_public_blocks", test_wfas_exceptions_public_blocks );
	suite.add_test( "wfas_exceptions_private_allows", test_wfas_exceptions_private_allows );
	suite.add_test( "wfas_exceptions_mixed_active_blocks", test_wfas_exceptions_mixed_active_blocks );
}
