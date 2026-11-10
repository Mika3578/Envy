//
// test_search_filter_mask_smoke.cpp
//
// Regression tests for the persisted Settings.Search.FilterMask bit layout:
// the result list and the saved-filter defaults must decode Local and Reject
// from the same bits.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include "test_framework.h"
#include "../Envy/SearchFilterMask.h"

namespace
{
int CountSet(const SearchFilterMask::Flags& oFlags)
{
	return int(oFlags.bRegExp) + int(oFlags.bPush) + int(oFlags.bUnstable) + int(oFlags.bBusy) + int(oFlags.bLocal) + int(oFlags.bReject) + int(oFlags.bBogus) + int(oFlags.bDRM) + int(oFlags.bRestricted) + int(oFlags.bSuspicious) + int(oFlags.bAdult);
}
}

// The numeric positions are persisted in user settings: pin them.
static bool test_search_filter_mask_bit_positions()
{
	return SearchFilterMask::RegExp == 0x001u && SearchFilterMask::Push == 0x002u && SearchFilterMask::Unstable == 0x004u && SearchFilterMask::Busy == 0x008u && SearchFilterMask::Local == 0x010u && SearchFilterMask::Reject == 0x020u && SearchFilterMask::Bogus == 0x040u && SearchFilterMask::DRM == 0x080u && SearchFilterMask::Restricted == 0x100u && SearchFilterMask::Suspicious == 0x200u && SearchFilterMask::Adult == 0x400u && SearchFilterMask::Known == 0x7FFu;
}

static bool test_search_filter_mask_empty()
{
	const SearchFilterMask::Flags oFlags = SearchFilterMask::Decode(0);
	return CountSet(oFlags) == 0 && SearchFilterMask::Encode(oFlags) == 0u;
}

static bool test_search_filter_mask_local_only()
{
	const SearchFilterMask::Flags oFlags = SearchFilterMask::Decode(0x010u);
	return oFlags.bLocal && !oFlags.bReject && CountSet(oFlags) == 1 && SearchFilterMask::Encode(oFlags) == 0x010u;
}

static bool test_search_filter_mask_reject_only()
{
	const SearchFilterMask::Flags oFlags = SearchFilterMask::Decode(0x020u);
	return oFlags.bReject && !oFlags.bLocal && CountSet(oFlags) == 1 && SearchFilterMask::Encode(oFlags) == 0x020u;
}

static bool test_search_filter_mask_local_and_reject()
{
	const SearchFilterMask::Flags oFlags = SearchFilterMask::Decode(0x030u);
	return oFlags.bLocal && oFlags.bReject && CountSet(oFlags) == 2 && SearchFilterMask::Encode(oFlags) == 0x030u;
}

static bool test_search_filter_mask_default()
{
	const SearchFilterMask::Flags oFlags = SearchFilterMask::Decode(SearchFilterMask::Default);
	return SearchFilterMask::Default == 0x280u && oFlags.bDRM && oFlags.bSuspicious && CountSet(oFlags) == 2;
}

static bool test_search_filter_mask_all_known()
{
	const SearchFilterMask::Flags oFlags = SearchFilterMask::Decode(SearchFilterMask::Known);
	return CountSet(oFlags) == 11 && SearchFilterMask::Encode(oFlags) == SearchFilterMask::Known;
}

// Each single bit must map to exactly one option and back to the same bit.
static bool test_search_filter_mask_single_bit_round_trip()
{
	for (uint32_t nBit = 1; nBit <= SearchFilterMask::Adult; nBit <<= 1)
	{
		const SearchFilterMask::Flags oFlags = SearchFilterMask::Decode(nBit);
		if (CountSet(oFlags) != 1 || SearchFilterMask::Encode(oFlags) != nBit)
			return false;
	}
	return true;
}

static bool test_search_filter_mask_every_value_round_trip()
{
	for (uint32_t nMask = 0; nMask <= SearchFilterMask::Known; ++nMask)
	{
		if (SearchFilterMask::Encode(SearchFilterMask::Decode(nMask)) != nMask)
			return false;
	}
	return true;
}

static bool test_search_filter_mask_unknown_bits_ignored()
{
	const SearchFilterMask::Flags oFlags = SearchFilterMask::Decode(0xFFFFF800u | SearchFilterMask::Local);
	return oFlags.bLocal && CountSet(oFlags) == 1 && SearchFilterMask::Encode(oFlags) == SearchFilterMask::Local;
}

void register_search_filter_mask_smoke_tests(TestSuite& suite)
{
	suite.add_test("search_filter_mask_bit_positions", test_search_filter_mask_bit_positions);
	suite.add_test("search_filter_mask_empty", test_search_filter_mask_empty);
	suite.add_test("search_filter_mask_local_only", test_search_filter_mask_local_only);
	suite.add_test("search_filter_mask_reject_only", test_search_filter_mask_reject_only);
	suite.add_test("search_filter_mask_local_and_reject", test_search_filter_mask_local_and_reject);
	suite.add_test("search_filter_mask_default", test_search_filter_mask_default);
	suite.add_test("search_filter_mask_all_known", test_search_filter_mask_all_known);
	suite.add_test("search_filter_mask_single_bit_round_trip", test_search_filter_mask_single_bit_round_trip);
	suite.add_test("search_filter_mask_every_value_round_trip", test_search_filter_mask_every_value_round_trip);
	suite.add_test("search_filter_mask_unknown_bits_ignored", test_search_filter_mask_unknown_bits_ignored);
}
