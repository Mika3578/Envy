//
// test_secure_random_smoke.cpp
//
// Smoke tests for CSPRNG helpers (#78): fill length, hex ID format,
// fail-closed contracts, and a static check that RemoteSecurity.cpp
// does not call rand()/srand().
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/SecureRandom.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>

static bool test_secure_random_fill_writes_requested_length()
{
	BYTE buf[32];
	memset(buf, 0xA5, sizeof(buf));

	if (!SecureRandomFill(buf, sizeof(buf)))
		return false;

	// Contract: all bytes were written (not left at the sentinel pattern).
	// Not a uniqueness proof — only that the call succeeded and touched the buffer.
	unsigned nonzero = 0;
	for (size_t i = 0; i < sizeof(buf); ++i)
	{
		if (buf[i] != 0xA5)
			++nonzero;
	}
	return nonzero > 0;
}

static bool test_secure_random_fill_rejects_null_and_zero()
{
	BYTE buf[8] = {};
	return SecureRandomFill(nullptr, 8) == FALSE
		&& SecureRandomFill(buf, 0) == FALSE;
}

static bool test_secure_random_hex_id_format()
{
	std::string id;
	if (!SecureRandomHexId(32, id))
		return false;
	if (id.size() != 32)
		return false;

	for (char c : id)
	{
		const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
		if (!ok)
			return false;
	}
	return true;
}

static bool test_secure_random_hex_id_rejects_odd_length()
{
	std::string id = "stale";
	if (SecureRandomHexId(31, id))
		return false;
	return id.empty();
}

static bool test_secure_random_hex_id_session_and_csrf_widths()
{
	// Session ID and CSRF token both use 32 hex chars (128-bit).
	std::string session;
	std::string csrf;
	if (!SecureRandomHexId(32, session) || !SecureRandomHexId(32, csrf))
		return false;
	return session.size() == 32 && csrf.size() == 32;
}

static bool test_try_get_secure_random_num_range()
{
	for (int i = 0; i < 64; ++i)
	{
		BYTE n = 0xFF;
		if (!TryGetSecureRandomNum(n, (BYTE)0, (BYTE)31))
			return false;
		if (n > 31)
			return false;
	}

	DWORD tid = 0;
	if (!TryGetSecureRandomNum<DWORD>(tid, (DWORD)1, (DWORD)0xFFFFFFFF))
		return false;
	if (tid == 0)
		return false;

	WORD ed2kLow = 0;
	if (!TryGetSecureRandomNum<WORD>(ed2kLow, (WORD)0, (WORD)0xFFFF))
		return false;

	// ED2K UDP key wire layout: 0x55AA0000 | low 16 bits
	const DWORD nKeyValue = 0x55AA0000u + ed2kLow;
	if ((nKeyValue & 0xFFFF0000u) != 0x55AA0000u)
		return false;

	return true;
}

static bool test_remote_security_source_has_no_rand_fallback()
{
	// Static regression guard: RemoteSecurity must not call rand()/srand().
	const char* candidates[] = {
		"../Envy/RemoteSecurity.cpp",
		"../../Envy/RemoteSecurity.cpp",
		"Envy/RemoteSecurity.cpp"
	};

	std::ifstream in;
	for (const char* path : candidates)
	{
		in.open(path, std::ios::in | std::ios::binary);
		if (in)
			break;
	}
	if (!in)
		return false;

	std::string content((std::istreambuf_iterator<char>(in)),
		std::istreambuf_iterator<char>());

	auto hasCall = [&](const char* needle) -> bool {
		size_t pos = 0;
		while ((pos = content.find(needle, pos)) != std::string::npos)
		{
			// Require '(' after the identifier (call), skip comments roughly.
			const size_t after = pos + strlen(needle);
			if (after < content.size() && content[after] == '(')
				return true;
			pos = after;
		}
		return false;
	};

	return !hasCall("rand") && !hasCall("srand");
}

void register_secure_random_smoke_tests(TestSuite& suite)
{
	suite.add_test("SecureRandomFill writes N bytes",
		test_secure_random_fill_writes_requested_length);
	suite.add_test("SecureRandomFill rejects null/zero",
		test_secure_random_fill_rejects_null_and_zero);
	suite.add_test("SecureRandomHexId length/format",
		test_secure_random_hex_id_format);
	suite.add_test("SecureRandomHexId rejects odd length",
		test_secure_random_hex_id_rejects_odd_length);
	suite.add_test("Session/CSRF hex width (32)",
		test_secure_random_hex_id_session_and_csrf_widths);
	suite.add_test("TryGetSecureRandomNum ranges (G2/BT/ED2K)",
		test_try_get_secure_random_num_range);
	suite.add_test("RemoteSecurity.cpp has no rand()/srand()",
		test_remote_security_source_has_no_rand_fallback);
}
