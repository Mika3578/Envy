//
// test_secureident_policy_smoke.cpp
//
// Smoke tests for the ED2K SecureIdent safe-disable policy (#75).
// Proves responses are never accepted and SecureIdent is not required
// for ED2K transfer. No live network / MFC client.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/SecureIdentPolicy.h"
#include "../HashLib/HashLib.h"

#include <cstring>

// Reproduce the historical Envy MD5(ClientID || challenge || random) prefix
// that the old non-zero verifier would have treated as a plausible response.
static void LegacyMd5SecureIdentPrefix(DWORD nClientID, const BYTE challenge[6],
	const BYTE random[6], BYTE outPrefix[6])
{
	BYTE hashInput[16];
	hashInput[0] = (BYTE)(nClientID & 0xFF);
	hashInput[1] = (BYTE)((nClientID >> 8) & 0xFF);
	hashInput[2] = (BYTE)((nClientID >> 16) & 0xFF);
	hashInput[3] = (BYTE)((nClientID >> 24) & 0xFF);
	memcpy(hashInput + 4, challenge, 6);
	memcpy(hashInput + 10, random, 6);

	CMD5 md5;
	md5.Add(hashInput, sizeof(hashInput));
	md5.Finish();
	BYTE digest[16];
	md5.GetHash(digest);
	memcpy(outPrefix, digest, 6);
}

static bool test_secureident_null_response_rejected()
{
	return Ed2kSecureIdentAcceptResponse(nullptr, 0) == FALSE
		&& Ed2kSecureIdentIsVerifiedState(ED2K_SECUREIDENT_STATE_VERIFIED) == FALSE;
}

static bool test_secureident_empty_response_rejected()
{
	BYTE empty[1] = { 0 };
	return Ed2kSecureIdentAcceptResponse(empty, 0) == FALSE;
}

static bool test_secureident_zero_fill_rejected()
{
	BYTE zeros[6] = {};
	return Ed2kSecureIdentAcceptResponse(zeros, 6) == FALSE;
}

static bool test_secureident_nonzero_arbitrary_rejected()
{
	BYTE arbitrary[6] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
	return Ed2kSecureIdentAcceptResponse(arbitrary, 6) == FALSE;
}

static bool test_secureident_legacy_md5_response_rejected()
{
	const BYTE challenge[6] = { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 };
	const BYTE random[6] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
	BYTE legacy[6];
	LegacyMd5SecureIdentPrefix(0x12345678u, challenge, random, legacy);

	// Old code accepted any non-zero 6-byte payload; legacy MD5 prefix is
	// almost certainly non-zero — still must be rejected now.
	bool anyNonZero = false;
	for (int i = 0; i < 6; ++i)
	{
		if ( legacy[i] != 0 )
			anyNonZero = true;
	}

	return anyNonZero
		&& Ed2kSecureIdentAcceptResponse(legacy, 6) == FALSE;
}

static bool test_secureident_state_after_reject_not_verified()
{
	const DWORD nState = Ed2kSecureIdentStateAfterRejectedResponse();
	return nState == ED2K_SECUREIDENT_STATE_NONE
		&& Ed2kSecureIdentIsVerifiedState(nState) == FALSE
		&& Ed2kSecureIdentIsVerifiedState(ED2K_SECUREIDENT_STATE_VERIFIED) == FALSE
		&& Ed2kSecureIdentIsVerifiedState(1) == FALSE
		&& Ed2kSecureIdentIsVerifiedState(2) == FALSE
		&& Ed2kSecureIdentIsVerifiedState(3) == FALSE;
}

static bool test_secureident_not_advertised()
{
	// Must stay in sync with ED2K_VERSION_SECUREID in EDPacket.h (= 0).
	return Ed2kSecureIdentAdvertisedVersion() == 0
		&& Ed2kSecureIdentIsImplemented() == FALSE;
}

static bool test_ed2k_transfer_without_secureident()
{
	// SecureIdent must never be a prerequisite for Hello / source / transfer.
	return Ed2kRequiresSecureIdentForTransfer() == FALSE;
}

static bool test_secureident_malformed_lengths_rejected()
{
	BYTE buf[64];
	memset(buf, 0x5A, sizeof(buf));
	return Ed2kSecureIdentAcceptResponse(buf, 1) == FALSE
		&& Ed2kSecureIdentAcceptResponse(buf, 5) == FALSE
		&& Ed2kSecureIdentAcceptResponse(buf, 7) == FALSE
		&& Ed2kSecureIdentAcceptResponse(buf, 64) == FALSE;
}

void register_secureident_policy_smoke_tests(TestSuite& suite)
{
	suite.add_test("secureident_null_response_rejected", test_secureident_null_response_rejected);
	suite.add_test("secureident_empty_response_rejected", test_secureident_empty_response_rejected);
	suite.add_test("secureident_zero_fill_rejected", test_secureident_zero_fill_rejected);
	suite.add_test("secureident_nonzero_arbitrary_rejected", test_secureident_nonzero_arbitrary_rejected);
	suite.add_test("secureident_legacy_md5_response_rejected", test_secureident_legacy_md5_response_rejected);
	suite.add_test("secureident_state_after_reject_not_verified", test_secureident_state_after_reject_not_verified);
	suite.add_test("secureident_not_advertised", test_secureident_not_advertised);
	suite.add_test("ed2k_transfer_without_secureident", test_ed2k_transfer_without_secureident);
	suite.add_test("secureident_malformed_lengths_rejected", test_secureident_malformed_lengths_rejected);
}
