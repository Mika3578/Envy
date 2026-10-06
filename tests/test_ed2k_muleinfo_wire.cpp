//
// test_ed2k_muleinfo_wire.cpp
//
// Deterministic checks for the legacy MuleInfo identity/version split (#378).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/Ed2kMuleInfoWire.h"

static bool test_muleinfo_legacy_header_golden()
{
	const Ed2kMuleInfoIdentity identity = Ed2kMakeMuleInfoIdentity(0x50u);
	return identity.legacyVersion == 0x50u &&
		identity.protocol == 0x01u &&
		identity.compatibleClient == 0x50u;
}

static bool test_muleinfo_version_is_independent_of_client_id()
{
	const Ed2kMuleInfoIdentity alternate = Ed2kMakeMuleInfoIdentity(0x28u);
	return alternate.legacyVersion == ED2K_MULEINFO_LEGACY_VERSION &&
		alternate.protocol == ED2K_MULEINFO_PROTOCOL &&
		alternate.compatibleClient == 0x28u;
}

static bool test_muleinfo_constants_match_legacy_contract()
{
	return ED2K_MULEINFO_LEGACY_VERSION == 0x50u &&
		ED2K_MULEINFO_PROTOCOL == 0x01u;
}

void register_ed2k_muleinfo_wire_tests(TestSuite& suite)
{
	suite.add_test("ED2K MuleInfo legacy header golden", test_muleinfo_legacy_header_golden);
	suite.add_test("ED2K MuleInfo version independent of client ID", test_muleinfo_version_is_independent_of_client_id);
	suite.add_test("ED2K MuleInfo legacy constants", test_muleinfo_constants_match_legacy_contract);
}
