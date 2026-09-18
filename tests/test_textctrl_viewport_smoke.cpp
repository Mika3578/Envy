//
// test_textctrl_viewport_smoke.cpp
//
// Deterministic viewport/scroll math for CTextCtrl (top-aligned log).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/TextCtrlViewport.h"

static bool test_page_lines_and_max_position()
{
	// 200px client, 20px lines → 10 visible
	if ( TextCtrlPageLines( 200, 20 ) != 10 )
		return false;
	// Remainder pixels do not invent a full line
	if ( TextCtrlPageLines( 209, 20 ) != 10 )
		return false;
	if ( TextCtrlPageLines( 19, 20 ) != 1 )
		return false;
	if ( TextCtrlMaxPosition( 3, 10 ) != 0 )
		return false;
	if ( TextCtrlMaxPosition( 10, 10 ) != 0 )
		return false;
	if ( TextCtrlMaxPosition( 11, 10 ) != 1 )
		return false;
	if ( TextCtrlMaxPosition( 100, 10 ) != 90 )
		return false;
	return true;
}

static bool test_short_log_top_aligned_geometry()
{
	// 3 visual lines in a tall window: content ends at 3*height, empty below
	const int nTotal = 3;
	const int nPos = 0;
	const int nHeight = 16;
	if ( TextCtrlContentBottomY( nTotal, nPos, nHeight ) != 48 )
		return false;
	if ( ! TextCtrlIsAtBottom( 0, 3, 20 ) )
		return false;
	return true;
}

static bool test_follow_bottom_only_when_pinned()
{
	const int nPage = 10;
	// Was at bottom with 10 lines; one more arrives → stay at new bottom
	if ( TextCtrlFollowBottom( TRUE, 0, 11, nPage ) != 1 )
		return false;
	// User scrolled up (pos=2 of 20); new line must not jump to bottom
	if ( TextCtrlFollowBottom( FALSE, 2, 21, nPage ) != 2 )
		return false;
	// Scrolled up but total shrinks past position → clamp
	if ( TextCtrlFollowBottom( FALSE, 50, 12, nPage ) != 2 )
		return false;
	return true;
}

static bool test_scroll_range_win32()
{
	int nMin = -1, nMax = -1, nPage = -1;
	TextCtrlScrollRange( 100, 10, nMin, nMax, nPage );
	if ( nMin != 0 || nPage != 10 || nMax != 99 )
		return false;
	// max thumb = nMax - nPage + 1 == 90 == TextCtrlMaxPosition
	if ( ( nMax - nPage + 1 ) != TextCtrlMaxPosition( 100, 10 ) )
		return false;

	TextCtrlScrollRange( 3, 10, nMin, nMax, nPage );
	if ( nMin != 0 || nPage != 10 || nMax != 9 )
		return false;
	if ( ( nMax - nPage + 1 ) != 0 )
		return false;

	TextCtrlScrollRange( 0, 10, nMin, nMax, nPage );
	if ( nMin != 0 || nPage != 10 || nMax != 9 )
		return false;
	return true;
}

static bool test_clamp_and_home_end()
{
	if ( TextCtrlClampPosition( -5, 50, 10 ) != 0 )
		return false;
	if ( TextCtrlClampPosition( 999, 50, 10 ) != 40 )
		return false;
	if ( TextCtrlClampPosition( 0, 0, 10 ) != 0 )
		return false;
	return true;
}

void register_textctrl_viewport_smoke_tests( TestSuite& suite )
{
	suite.add_test( "textctrl_page_lines_and_max_position", test_page_lines_and_max_position );
	suite.add_test( "textctrl_short_log_top_aligned_geometry", test_short_log_top_aligned_geometry );
	suite.add_test( "textctrl_follow_bottom_only_when_pinned", test_follow_bottom_only_when_pinned );
	suite.add_test( "textctrl_scroll_range_win32", test_scroll_range_win32 );
	suite.add_test( "textctrl_clamp_and_home_end", test_clamp_and_home_end );
}
