//
// test_bt_tracker_log_redaction_smoke.cpp
//
// Regression smoke tests for BEP 27 tracker-URL log redaction (#317).
// Pure helper only - no MFC / network / client objects.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/BTTrackerLogRedaction.h"

#include <cwchar>

static bool test_log_length_strips_passkey_query()
{
	// Passkeys ride the announce query string and must not reach logs.
	return BtTrackerLogLength( L"http://tracker.example/announce?passkey=secret123" )
		== wcslen( L"http://tracker.example/announce" );
}

static bool test_log_length_keeps_queryless_url()
{
	return BtTrackerLogLength( L"udp://tracker.example:1337/announce" )
		== wcslen( L"udp://tracker.example:1337/announce" )
		&& BtTrackerLogLength( L"http://tracker.example/announce" ) > 0;
}

static bool test_log_length_strips_at_first_query()
{
	// Everything from the first '?' onward is dropped, not just one parameter.
	return BtTrackerLogLength( L"udp://t/announce?passkey=a&info_hash=b" )
		== wcslen( L"udp://t/announce" );
}

static bool test_log_length_query_only_empty()
{
	// Malformed: query with no URL part must redact everything.
	return BtTrackerLogLength( L"?passkey=secret" ) == 0;
}

static bool test_log_length_trailing_query_empty()
{
	return BtTrackerLogLength( L"udp://t/announce?" ) == wcslen( L"udp://t/announce" );
}

static bool test_log_length_null_and_empty_safe()
{
	return BtTrackerLogLength( NULL ) == 0 && BtTrackerLogLength( L"" ) == 0;
}

static bool test_log_length_query_before_path()
{
	// Malformed shape: '?' ahead of the path still removes the credential.
	return BtTrackerLogLength( L"udp://t?passkey=secret/announce" )
		== wcslen( L"udp://t" );
}

void register_bt_tracker_log_redaction_smoke_tests(TestSuite& suite)
{
	suite.add_test("BT tracker log length strips passkey query", test_log_length_strips_passkey_query);
	suite.add_test("BT tracker log length keeps queryless URL", test_log_length_keeps_queryless_url);
	suite.add_test("BT tracker log length strips at first query", test_log_length_strips_at_first_query);
	suite.add_test("BT tracker log length query-only redacts all", test_log_length_query_only_empty);
	suite.add_test("BT tracker log length trailing query redacted", test_log_length_trailing_query_empty);
	suite.add_test("BT tracker log length null and empty safe", test_log_length_null_and_empty_safe);
	suite.add_test("BT tracker log length query before path", test_log_length_query_before_path);
}
