//
// test_skin_engine_p0_smoke.cpp
//
// Smoke tests for skin-engine P0 fixes (SkinEngineP0.h):
// StatusbarHeight member targeting, strict metric parse/clamp, point+size
// rect parse, part-name suffix truncate, roundRect size validation, and
// LoadFromXML success aggregation (non-transactional).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/SkinEngineP0.h"

#include <cwchar>
#include <string>

static bool test_statusbar_targets_distinct_member()
{
	SkinBarHeightMembers o = {};
	o.MenubarHeight = 28;
	o.StatusbarHeight = 0;

	if ( SkinStatusbarHeightUsesCorrectMember( &o.MenubarHeight, o ) )
		return false;
	if ( ! SkinStatusbarHeightUsesCorrectMember( &o.StatusbarHeight, o ) )
		return false;

	const DWORD nMenuBefore = o.MenubarHeight;
	if ( ! ApplySkinMetric( L"22", o.StatusbarHeight, SkinMetricBarMin, SkinMetricBarMax ) )
		return false;
	return o.StatusbarHeight == 22 && o.MenubarHeight == nMenuBefore;
}

static bool test_point_size_rect()
{
	SkinParsedRect rc = {};
	if ( ! ParseSkinPointSizeRect( L"10,20", L"30,40", rc ) )
		return false;
	return rc.left == 10 && rc.top == 20 && rc.right == 40 && rc.bottom == 60;
}

static bool test_part_name_no_hda_not_truncated()
{
	if ( SkinPartNameNeedsSuffixTruncate( L"Close" ) )
		return false;

	wchar_t szOut[ 64 ] = {};
	const bool bTruncated = TruncateSkinPartNameSuffix( L"Close", szOut, _countof( szOut ) );
	return ! bTruncated && wcscmp( szOut, L"Close" ) == 0;
}

static bool test_part_name_hover_truncated()
{
	if ( ! SkinPartNameNeedsSuffixTruncate( L"CloseHover" ) )
		return false;

	wchar_t szOut[ 64 ] = {};
	if ( ! TruncateSkinPartNameSuffix( L"CloseHover", szOut, _countof( szOut ) ) )
		return false;
	return wcscmp( szOut, L"Close" ) == 0;
}

static bool test_roundrect_invalid_rejected()
{
	int w = 99;
	int h = 99;
	if ( ParseSkinRoundRectSize( NULL, w, h ) )
		return false;
	if ( w != 0 || h != 0 )
		return false;

	w = h = 99;
	if ( ParseSkinRoundRectSize( L"", w, h ) )
		return false;
	if ( ParseSkinRoundRectSize( L"4", w, h ) )
		return false;
	if ( ParseSkinRoundRectSize( L"-1,4", w, h ) )
		return false;
	if ( ParseSkinRoundRectSize( L"4,-2", w, h ) )
		return false;
	if ( ! ParseSkinRoundRectSize( L"4,4", w, h ) )
		return false;
	return w == 4 && h == 4;
}

static bool test_load_section_failure_fails_aggregate()
{
	SkinLoadSuccessState o;
	o.OnSectionResult( true );
	o.OnSectionResult( false );
	o.OnSectionResult( true );
	return o.bSuccess == false;
}

static bool test_load_unknown_root_fails_aggregate()
{
	SkinLoadSuccessState o;
	o.OnSectionResult( true );
	o.OnUnknownRootElement();
	return o.bSuccess == false;
}

static bool test_load_invalid_manifest_fails_aggregate()
{
	SkinLoadSuccessState o;
	o.OnInvalidManifest();
	return o.bSuccess == false;
}

static bool test_metric_negative_clamped()
{
	DWORD n = 28;
	if ( ! ApplySkinMetric( L"-1", n, SkinMetricBarMin, SkinMetricBarMax ) )
		return false;
	return n == 0;
}

static bool test_metric_over_max_clamped()
{
	DWORD n = 28;
	if ( ! ApplySkinMetric( L"5000", n, SkinMetricBarMin, SkinMetricBarMax ) )
		return false;
	return n == 100;
}

static bool test_metric_non_numeric_keeps_current()
{
	DWORD n = 28;
	if ( ApplySkinMetric( L"abc", n, SkinMetricBarMin, SkinMetricBarMax ) )
		return false;
	if ( n != 28 )
		return false;
	if ( ApplySkinMetric( L"12px", n, SkinMetricBarMin, SkinMetricBarMax ) )
		return false;
	return n == 28;
}

static bool test_metric_splitter_zero_clamped_to_min()
{
	DWORD n = 6;
	if ( ! ApplySkinMetric( L"0", n, SkinMetricSplitterMin, SkinMetricSplitterMax ) )
		return false;
	return n == 1;
}

static bool test_metric_valid_zero_statusbar()
{
	DWORD n = 22;
	if ( ! ApplySkinMetric( L"0", n, SkinMetricBarMin, SkinMetricBarMax ) )
		return false;
	return n == 0;
}

static bool test_metric_sidebar_and_libicons_bounds()
{
	DWORD nSidebar = 200;
	if ( ! ApplySkinMetric( L"-20", nSidebar, SkinMetricSidebarMin, SkinMetricSidebarMax ) )
		return false;
	if ( nSidebar != 0 )
		return false;

	DWORD nLibX = 220;
	if ( ! ApplySkinMetric( L"10", nLibX, SkinMetricLibIconsXMin, SkinMetricLibIconsXMax ) )
		return false;
	if ( nLibX != 30 )
		return false;

	DWORD nRow = 17;
	if ( ! ApplySkinMetric( L"50", nRow, SkinMetricRowSizeMin, SkinMetricRowSizeMax ) )
		return false;
	return nRow == 40;
}

void register_skin_engine_p0_smoke_tests( TestSuite& suite )
{
	suite.add_test( "SkinP0: StatusbarHeight targets distinct member",
		test_statusbar_targets_distinct_member );
	suite.add_test( "SkinP0: point+size rect becomes (10,20)-(40,60)",
		test_point_size_rect );
	suite.add_test( "SkinP0: name without .HDA is not truncated",
		test_part_name_no_hda_not_truncated );
	suite.add_test( "SkinP0: CloseHover truncates to Close",
		test_part_name_hover_truncated );
	suite.add_test( "SkinP0: invalid roundRect size rejected",
		test_roundrect_invalid_rejected );
	suite.add_test( "SkinP0: section failure fails LoadFromXML aggregate",
		test_load_section_failure_fails_aggregate );
	suite.add_test( "SkinP0: unknown root fails LoadFromXML aggregate",
		test_load_unknown_root_fails_aggregate );
	suite.add_test( "SkinP0: invalid manifest fails LoadFromXML aggregate",
		test_load_invalid_manifest_fails_aggregate );
	suite.add_test( "SkinP0: metric -1 clamped to min",
		test_metric_negative_clamped );
	suite.add_test( "SkinP0: metric over max clamped",
		test_metric_over_max_clamped );
	suite.add_test( "SkinP0: non-numeric metric keeps current",
		test_metric_non_numeric_keeps_current );
	suite.add_test( "SkinP0: Splitter 0 clamped to 1",
		test_metric_splitter_zero_clamped_to_min );
	suite.add_test( "SkinP0: Statusbar 0 is valid",
		test_metric_valid_zero_statusbar );
	suite.add_test( "SkinP0: Sidebar/LibIcons/RowSize bounds",
		test_metric_sidebar_and_libicons_bounds );
}
