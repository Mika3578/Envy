// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

enum class BtSingleTracker
{
	Announced,
	PublicDefault,
	Inactive
};

constexpr bool BtAllowsPublicDiscovery(bool privateTorrent) noexcept
{
	return !privateTorrent;
}

constexpr BtSingleTracker BtSelectSingleTracker(bool privateTorrent, bool usableAnnounce) noexcept
{
	if (usableAnnounce)
		return BtSingleTracker::Announced;
	return BtAllowsPublicDiscovery(privateTorrent) ? BtSingleTracker::PublicDefault : BtSingleTracker::Inactive;
}
