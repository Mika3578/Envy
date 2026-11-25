// SPDX-License-Identifier: AGPL-3.0-or-later
#include "test_framework.h"
#include "../Envy/BTDiscoveryPolicy.h"

static bool test_private_torrent_discovery()
{
	return !BtAllowsPublicDiscovery(true) &&
	       BtSelectSingleTracker(true, false) == BtSingleTracker::Inactive &&
	       BtSelectSingleTracker(true, true) == BtSingleTracker::Announced;
}

static bool test_public_torrent_discovery()
{
	return BtAllowsPublicDiscovery(false) &&
	       BtSelectSingleTracker(false, false) == BtSingleTracker::PublicDefault &&
	       BtSelectSingleTracker(false, true) == BtSingleTracker::Announced;
}

void register_bt_discovery_policy_tests(TestSuite& suite)
{
	suite.add_test("bt_discovery_private_blocks_public_paths", test_private_torrent_discovery);
	suite.add_test("bt_discovery_public_preserves_discovery_and_fallback", test_public_torrent_discovery);
}
