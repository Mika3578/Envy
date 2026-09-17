//
// test_envy_thread_policy_smoke.cpp
//
// Smoke tests for EnvyThread forced-terminate policy (#92).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/EnvyThreadPolicy.h"

static bool test_envy_thread_forced_terminate_disabled()
{
	return EnvyThreadAllowForcedTerminate() == false;
}

void register_envy_thread_policy_smoke_tests( TestSuite& suite )
{
	suite.add_test( "envy_thread_forced_terminate_disabled",
		test_envy_thread_forced_terminate_disabled );
}
