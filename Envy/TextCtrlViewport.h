//
// TextCtrlViewport.h
//
// Pure viewport / scroll math for CTextCtrl (System/Network log).
// Shared with EnvyTests — no MFC dependency beyond windows.h BOOL.
//
// Semantics: nPosition is the first visible visual line (0-based),
// top-aligned when content fits; follow-bottom only when already at end.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <windows.h>

// Full visual lines that fit in the client (at least 1 when height known).
inline int TextCtrlPageLines( int nClientHeight, int nLineHeight )
{
	if ( nLineHeight <= 0 )
		return 1;
	const int nPage = nClientHeight / nLineHeight;
	return ( nPage > 0 ) ? nPage : 1;
}

// Maximum scroll position: first visible line when pinned to the bottom.
inline int TextCtrlMaxPosition( int nTotal, int nPage )
{
	if ( nPage <= 0 )
		nPage = 1;
	return ( nTotal > nPage ) ? ( nTotal - nPage ) : 0;
}

inline int TextCtrlClampPosition( int nPosition, int nTotal, int nPage )
{
	const int nMax = TextCtrlMaxPosition( nTotal, nPage );
	if ( nPosition < 0 )
		return 0;
	if ( nPosition > nMax )
		return nMax;
	return nPosition;
}

inline BOOL TextCtrlIsAtBottom( int nPosition, int nTotal, int nPage )
{
	return nPosition >= TextCtrlMaxPosition( nTotal, nPage );
}

// After nTotal changes: stay pinned to bottom only if the view was already there.
inline int TextCtrlFollowBottom( BOOL bWasAtBottom, int nPosition, int nTotal, int nPage )
{
	if ( bWasAtBottom )
		return TextCtrlMaxPosition( nTotal, nPage );
	return TextCtrlClampPosition( nPosition, nTotal, nPage );
}

// Client Y of the bottom edge of the last visual line when line 0 is at Y=0
// and nPosition is the first visible visual line.
inline int TextCtrlContentBottomY( int nTotal, int nPosition, int nLineHeight )
{
	if ( nLineHeight <= 0 )
		return 0;
	return ( nTotal - nPosition ) * nLineHeight;
}

// Win32 SCROLLINFO range so max thumb position == TextCtrlMaxPosition.
// nMax - nPage + 1 == max(0, nTotal - nPage) when nMax = max(nTotal, nPage) - 1.
inline void TextCtrlScrollRange( int nTotal, int nPage, int& nMin, int& nMax, int& nPageOut )
{
	nMin = 0;
	nPageOut = ( nPage > 0 ) ? nPage : 1;
	if ( nTotal <= 0 && nPageOut <= 0 )
	{
		nMax = 0;
		return;
	}
	const int nSpan = ( nTotal > nPageOut ) ? nTotal : nPageOut;
	nMax = ( nSpan > 0 ) ? ( nSpan - 1 ) : 0;
}
