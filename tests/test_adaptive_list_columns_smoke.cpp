//
// test_adaptive_list_columns_smoke.cpp
//
// Deterministic adaptive report-list column allocation.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/AdaptiveListColumns.h"

#include <array>
#include <cstddef>

template<std::size_t N>
static bool widths_non_negative(const std::array<int, N>& pW)
{
	for (std::size_t i = 0; i < N; ++i)
	{
		if (pW[i] < 0)
			return false;
	}
	return true;
}

template<std::size_t N>
static int sum_widths(const std::array<int, N>& pW)
{
	int nSum = 0;
	for (std::size_t i = 0; i < N; ++i)
		nSum += pW[i];
	return nSum;
}

static bool test_null_and_empty()
{
	std::array<int, 2> nOut{ -1, -1 };
	if (AdaptiveAllocateColumns(100, 100, nullptr, 2, nOut.data()))
		return false;
	AdaptiveColumnSpec s = {};
	if (AdaptiveAllocateColumns(100, 100, &s, 0, nOut.data()))
		return false;
	if (AdaptiveAllocateColumns(100, 100, &s, 1, nullptr))
		return false;
	return true;
}

static bool test_zero_and_tiny_width()
{
	std::array<AdaptiveColumnSpec, 3> cols{};
	cols[0] = { AdaptiveColumnFixed, 40, 40, 40, 0, FALSE, 0, FALSE };
	cols[1] = { AdaptiveColumnFlexible, 100, 40, INT_MAX, 1, FALSE, 0, FALSE };
	cols[2] = { AdaptiveColumnBounded, 80, 40, 160, 0, FALSE, 0, FALSE };

	std::array<int, 3> nOut{};
	if (!AdaptiveAllocateColumns(0, 100, cols.data(), 3, nOut.data()))
		return false;
	if (!widths_non_negative(nOut))
		return false;
	// At width 0, columns stay at preferred mins after shrink attempt
	if (nOut[0] != 40 || nOut[1] != 40 || nOut[2] != 40)
		return false;

	if (!AdaptiveAllocateColumns(50, 100, cols.data(), 3, nOut.data()))
		return false;
	if (!widths_non_negative(nOut))
		return false;
	if (nOut[0] != 40 || nOut[1] != 40 || nOut[2] != 40)
		return false;
	return true;
}

static bool test_normal_and_wide_fill()
{
	std::array<AdaptiveColumnSpec, 4> cols{};
	cols[0] = { AdaptiveColumnFixed, 60, 60, 60, 0, FALSE, 0, FALSE };
	cols[1] = { AdaptiveColumnBounded, 140, 80, 220, 0, FALSE, 0, FALSE };
	cols[2] = { AdaptiveColumnFlexible, 140, 60, INT_MAX, 2, FALSE, 0, FALSE };
	cols[3] = { AdaptiveColumnFlexible, 140, 60, INT_MAX, 1, FALSE, 0, FALSE };

	std::array<int, 4> nOut{};
	const int nNormal = 60 + 140 + 140 + 140; // 480
	if (!AdaptiveAllocateColumns(nNormal, 100, cols.data(), 4, nOut.data()))
		return false;
	if (sum_widths(nOut) != nNormal)
		return false;
	if (nOut[0] != 60 || nOut[1] != 140)
		return false;

	const int nWide = 900;
	if (!AdaptiveAllocateColumns(nWide, 100, cols.data(), 4, nOut.data()))
		return false;
	if (sum_widths(nOut) != nWide)
		return false;
	if (nOut[0] != 60 || nOut[1] != 140)
		return false;
	// Extra 420 → weight 2:1 → 280 / 140
	if (nOut[2] != 140 + 280 || nOut[3] != 140 + 140)
		return false;
	return true;
}

static bool test_ultrawide_and_hidden()
{
	std::array<AdaptiveColumnSpec, 3> cols{};
	cols[0] = { AdaptiveColumnFixed, 50, 50, 50, 0, FALSE, 0, FALSE };
	cols[1] = { AdaptiveColumnFlexible, 100, 40, INT_MAX, 1, FALSE, 0, FALSE };
	cols[2] = { AdaptiveColumnFixed, 0, 0, 0, 0, FALSE, 0, TRUE }; // hidden

	std::array<int, 3> nOut{};
	if (!AdaptiveAllocateColumns(2000, 100, cols.data(), 3, nOut.data()))
		return false;
	if (nOut[2] != 0)
		return false;
	if (nOut[0] != 50 || nOut[1] != 1950)
		return false;
	return true;
}

static bool test_sticky_and_reorder_safe()
{
	std::array<AdaptiveColumnSpec, 3> cols{};
	cols[0] = { AdaptiveColumnFixed, 60, 60, 60, 0, FALSE, 0, FALSE };
	cols[1] = { AdaptiveColumnFlexible, 100, 40, INT_MAX, 1, TRUE, 250, FALSE };
	cols[2] = { AdaptiveColumnFlexible, 100, 40, INT_MAX, 1, FALSE, 0, FALSE };

	std::array<int, 3> nOut{};
	if (!AdaptiveAllocateColumns(500, 100, cols.data(), 3, nOut.data()))
		return false;
	if (nOut[1] != 250)
		return false;
	if (nOut[0] != 60)
		return false;
	if (nOut[2] != 500 - 60 - 250)
		return false;
	return true;
}

static bool test_scale_factors()
{
	std::array<AdaptiveColumnSpec, 2> cols{};
	cols[0] = { AdaptiveColumnFixed, 100, 100, 100, 0, FALSE, 0, FALSE };
	cols[1] = { AdaptiveColumnFlexible, 100, 50, INT_MAX, 1, FALSE, 0, FALSE };

	std::array<int, 2> nOut{};
	// Below 110%: no scale
	if (!AdaptiveAllocateColumns(300, 100, cols.data(), 2, nOut.data()))
		return false;
	if (nOut[0] != 100 || nOut[1] != 200)
		return false;

	if (!AdaptiveAllocateColumns(300, 109, cols.data(), 2, nOut.data()))
		return false;
	if (nOut[0] != 100)
		return false;

	// 150%: fixed becomes 150
	if (!AdaptiveAllocateColumns(450, 150, cols.data(), 2, nOut.data()))
		return false;
	if (nOut[0] != 150)
		return false;
	if (nOut[1] != 300)
		return false;

	// 200%
	if (!AdaptiveAllocateColumns(600, 200, cols.data(), 2, nOut.data()))
		return false;
	if (nOut[0] != 200 || nOut[1] != 400)
		return false;

	// Clamp scale input
	if (!AdaptiveAllocateColumns(300, 50, cols.data(), 2, nOut.data()))
		return false;
	if (nOut[0] != 100)
		return false;

	// Large design px must scale correctly (not early-return INT_MAX/100).
	if (AdaptiveScalePx(20000000, 200) != 40000000)
		return false;
	// Product exceeds INT_MAX → saturate
	if (AdaptiveScalePx(1200000000, 200) != INT_MAX)
		return false;
	return true;
}

static bool test_multiple_flexible_and_narrow_degrade()
{
	std::array<AdaptiveColumnSpec, 5> cols{};
	cols[0] = { AdaptiveColumnFixed, 42, 42, 42, 0, FALSE, 0, FALSE };
	cols[1] = { AdaptiveColumnBounded, 110, 80, 200, 0, FALSE, 0, FALSE };
	cols[2] = { AdaptiveColumnFlexible, 100, 40, INT_MAX, 1, FALSE, 0, FALSE };
	cols[3] = { AdaptiveColumnFlexible, 100, 40, INT_MAX, 1, FALSE, 0, FALSE };
	cols[4] = { AdaptiveColumnBounded, 54, 40, 80, 0, FALSE, 0, FALSE };

	std::array<int, 5> nOut{};
	const int nMinSum = 42 + 80 + 40 + 40 + 40; // 242
	if (!AdaptiveAllocateColumns(200, 100, cols.data(), 5, nOut.data()))
		return false;
	if (!widths_non_negative(nOut))
		return false;
	if (nOut[0] != 42)
		return false;
	if (nOut[2] < 40 || nOut[3] < 40)
		return false;
	// Cannot fit under true min sum — widths stay at mins (scroll)
	if (sum_widths(nOut) != nMinSum)
		return false;
	return true;
}

static bool test_hostcache_like_defaults_wide()
{
	// Mirrors Host Cache preferred defaults (10 visible columns)
	std::array<AdaptiveColumnSpec, 10> cols{};
	cols[0] = { AdaptiveColumnBounded, 140, 100, 280, 0, FALSE, 0, FALSE };     // Address
	cols[1] = { AdaptiveColumnFixed, 60, 48, 60, 0, FALSE, 0, FALSE };          // Port
	cols[2] = { AdaptiveColumnBounded, 128, 96, 180, 0, FALSE, 0, FALSE };      // Last Seen
	cols[3] = { AdaptiveColumnFixed, 60, 48, 60, 0, FALSE, 0, FALSE };          // Failures
	cols[4] = { AdaptiveColumnFixed, 60, 48, 60, 0, FALSE, 0, FALSE };          // CurUsers
	cols[5] = { AdaptiveColumnFixed, 60, 48, 60, 0, FALSE, 0, FALSE };          // MaxUsers
	cols[6] = { AdaptiveColumnFlexible, 140, 80, INT_MAX, 2, FALSE, 0, FALSE }; // Name
	cols[7] = { AdaptiveColumnFlexible, 140, 80, INT_MAX, 3, FALSE, 0, FALSE }; // Description
	cols[8] = { AdaptiveColumnBounded, 100, 72, 160, 0, FALSE, 0, FALSE };      // Client
	cols[9] = { AdaptiveColumnBounded, 60, 48, 100, 0, FALSE, 0, FALSE };       // Country

	std::array<int, 10> nOut{};
	const int nPref = 140 + 60 + 128 + 60 + 60 + 60 + 140 + 140 + 100 + 60; // 948
	if (!AdaptiveAllocateColumns(nPref, 100, cols.data(), 10, nOut.data()))
		return false;
	if (sum_widths(nOut) != nPref)
		return false;

	if (!AdaptiveAllocateColumns(1400, 100, cols.data(), 10, nOut.data()))
		return false;
	if (sum_widths(nOut) != 1400)
		return false;
	const int nExpectedFixedBound = 140 + 60 + 128 + 60 + 60 + 60 + 100 + 60; // 668
	if (const int nFixedBound = 1400 - nOut[6] - nOut[7];
	    nFixedBound != nExpectedFixedBound)
		return false;
	if (nOut[6] <= 140 || nOut[7] <= 140)
		return false;
	// Description weight 3 vs Name 2
	if (nOut[7] <= nOut[6])
		return false;
	return true;
}

static bool test_flex_remainder_after_capped_peer()
{
	// Weight 1 / 100; second flex saturates at 100 — leftover must fill the first.
	std::array<AdaptiveColumnSpec, 2> cols{};
	cols[0] = { AdaptiveColumnFlexible, 100, 80, INT_MAX, 1, FALSE, 0, FALSE };
	cols[1] = { AdaptiveColumnFlexible, 100, 80, 100, 100, FALSE, 0, FALSE };
	std::array<int, 2> nOut{};
	if (!AdaptiveAllocateColumns(1200, 100, cols.data(), 2, nOut.data()))
		return false;
	if (sum_widths(nOut) != 1200)
		return false;
	if (nOut[1] != 100)
		return false;
	if (nOut[0] != 1100)
		return false;
	return true;
}

void register_adaptive_list_columns_smoke_tests(TestSuite& suite)
{
	suite.add_test("adaptive_cols_null_empty", test_null_and_empty);
	suite.add_test("adaptive_cols_zero_tiny", test_zero_and_tiny_width);
	suite.add_test("adaptive_cols_normal_wide_fill", test_normal_and_wide_fill);
	suite.add_test("adaptive_cols_ultrawide_hidden", test_ultrawide_and_hidden);
	suite.add_test("adaptive_cols_sticky", test_sticky_and_reorder_safe);
	suite.add_test("adaptive_cols_scale_100_150_200", test_scale_factors);
	suite.add_test("adaptive_cols_narrow_degrade", test_multiple_flexible_and_narrow_degrade);
	suite.add_test("adaptive_cols_hostcache_wide", test_hostcache_like_defaults_wide);
	suite.add_test("adaptive_cols_flex_remainder_capped", test_flex_remainder_after_capped_peer);
}
