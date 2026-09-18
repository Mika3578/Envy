//
// test_remote_password_policy_smoke.cpp
//
// Smoke tests for Remote password-hash format predicates (#79).
// No CNG / MFC / live Remote login.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/RemotePasswordPolicy.h"

static bool test_remote_legacy_sha1_valid_40_hex()
{
	return RemoteLegacySha1HashLooksValid(
		"0123456789abcdef0123456789abcdef01234567", 40 ) != FALSE;
}

static bool test_remote_legacy_sha1_rejects_wrong_length()
{
	return RemoteLegacySha1HashLooksValid( "abc", 3 ) == FALSE
		&& RemoteLegacySha1HashLooksValid(
			"0123456789abcdef0123456789abcdef012345678", 41 ) == FALSE
		&& RemoteLegacySha1HashLooksValid( nullptr, 40 ) == FALSE;
}

static bool test_remote_legacy_sha1_rejects_non_hex()
{
	return RemoteLegacySha1HashLooksValid(
		"0123456789abcdef0123456789abcdef0123456g", 40 ) == FALSE;
}

static bool test_remote_needs_rehash_null_empty()
{
	return RemotePasswordNeedsRehash( nullptr ) != FALSE
		&& RemotePasswordNeedsRehash( "" ) != FALSE;
}

static bool test_remote_needs_rehash_legacy_and_fallback()
{
	return RemotePasswordNeedsRehash(
			"0123456789abcdef0123456789abcdef01234567" ) != FALSE
		&& RemotePasswordNeedsRehash( "sha256-salted:abc:def" ) != FALSE;
}

static bool test_remote_pbkdf2_prefix_no_rehash()
{
	return RemotePasswordNeedsRehash(
		"pbkdf2-sha256:100000:c2FsdA==:aGFzaA==" ) == FALSE;
}

void register_remote_password_policy_smoke_tests( TestSuite& suite )
{
	suite.add_test( "remote_legacy_sha1_valid_40_hex", test_remote_legacy_sha1_valid_40_hex );
	suite.add_test( "remote_legacy_sha1_rejects_wrong_length", test_remote_legacy_sha1_rejects_wrong_length );
	suite.add_test( "remote_legacy_sha1_rejects_non_hex", test_remote_legacy_sha1_rejects_non_hex );
	suite.add_test( "remote_needs_rehash_null_empty", test_remote_needs_rehash_null_empty );
	suite.add_test( "remote_needs_rehash_legacy_and_fallback", test_remote_needs_rehash_legacy_and_fallback );
	suite.add_test( "remote_pbkdf2_prefix_no_rehash", test_remote_pbkdf2_prefix_no_rehash );
}
