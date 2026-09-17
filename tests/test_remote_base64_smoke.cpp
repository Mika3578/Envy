//
// test_remote_base64_smoke.cpp
//
// Smoke tests for RemoteBase64Encode empty-input / padding safety (#92).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/RemoteBase64.h"

static bool test_remote_base64_null_empty()
{
	return RemoteBase64Encode( nullptr, 0 ).empty()
		&& RemoteBase64Encode( nullptr, 5 ).empty()
		&& RemoteBase64Encode( reinterpret_cast< const uint8_t* >( "" ), 0 ).empty();
}

static bool test_remote_base64_known_vectors()
{
	const uint8_t one[] = { 'f' };
	const uint8_t two[] = { 'f', 'o' };
	const uint8_t three[] = { 'f', 'o', 'o' };
	return RemoteBase64Encode( one, 1 ) == "Zg=="
		&& RemoteBase64Encode( two, 2 ) == "Zm8="
		&& RemoteBase64Encode( three, 3 ) == "Zm9v";
}

static bool test_remote_base64_empty_no_padding_write()
{
	// Historical bug wrote '=' into encoded[size-1-i] when size==0.
	const std::string empty = RemoteBase64Encode( nullptr, 0 );
	return empty.empty() && empty.size() == 0;
}

void register_remote_base64_smoke_tests( TestSuite& suite )
{
	suite.add_test( "remote_base64_null_empty", test_remote_base64_null_empty );
	suite.add_test( "remote_base64_known_vectors", test_remote_base64_known_vectors );
	suite.add_test( "remote_base64_empty_no_padding_write", test_remote_base64_empty_no_padding_write );
}
