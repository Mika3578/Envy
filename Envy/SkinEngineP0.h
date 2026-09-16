//
// SkinEngineP0.h
//
// Pure skin-engine P0 helpers (no MFC skin objects). Shared by Skin.cpp /
// SkinWindow.cpp and EnvyTests smoke coverage.
//
// Scope: strict metric parse+clamp, point/size rect parse, part-name suffix
// truncation, roundRect corner validation, and LoadFromXML success aggregate.
// Does not implement HiDPI / logical-unit scaling (P1+).
//
// LoadFromXML is not transactional: a failed section fails the file load but
// mutations already applied by earlier sections are not rolled back.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <cwchar>
#include <windows.h>

//////////////////////////////////////////////////////////////////////
// Settings registration targets (StatusbarHeight must not alias MenubarHeight)

struct SkinBarHeightMembers
{
	DWORD MenubarHeight;
	DWORD StatusbarHeight;
};

inline LPCTSTR SkinMenubarHeightSettingName()
{
	return L"MenubarHeight";
}

inline LPCTSTR SkinStatusbarHeightSettingName()
{
	return L"StatusbarHeight";
}

// True only when the registered StatusbarHeight pointer is the statusbar
// member (the historical bug bound StatusbarHeight to MenubarHeight).
inline bool SkinStatusbarHeightUsesCorrectMember(
	DWORD* pRegisteredStatusbar,
	SkinBarHeightMembers& oMembers )
{
	return pRegisteredStatusbar == &oMembers.StatusbarHeight
		&& pRegisteredStatusbar != &oMembers.MenubarHeight;
}

//////////////////////////////////////////////////////////////////////
// Metric bounds (must stay aligned with Settings.cpp Skin.* Add ranges)

enum SkinMetricBounds : int
{
	SkinMetricBarMin			= 0,
	SkinMetricBarMax			= 100,
	SkinMetricTaskbarTabMin		= 0,
	SkinMetricTaskbarTabMax		= 1000,
	SkinMetricSidebarMin		= 0,
	SkinMetricSidebarMax		= 800,
	SkinMetricMonitorbarMin		= 0,
	SkinMetricMonitorbarMax		= 1000,
	SkinMetricSplitterMin		= 1,
	SkinMetricSplitterMax		= 100,
	SkinMetricButtonEdgeMin		= 0,
	SkinMetricButtonEdgeMax		= 100,
	SkinMetricLibIconsXMin		= 30,
	SkinMetricLibIconsXMax		= 500,
	SkinMetricLibIconsYMin		= 30,
	SkinMetricLibIconsYMax		= 100,
	SkinMetricRowSizeMin		= 16,
	SkinMetricRowSizeMax		= 40,
	SkinMetricDropMenuLabelMin	= 0,
	SkinMetricDropMenuLabelMax	= 100
};

// Strict integer parse: optional whitespace, optional +/- , digits only,
// optional trailing whitespace. Rejects empty, non-numeric, and trailing junk
// (unlike _wtoi, which maps L"abc" to 0).
// On success writes the clamped value and returns true.
// On syntax error leaves nCurrent unchanged and returns false.
inline bool ApplySkinMetric(
	LPCWSTR pszText,
	DWORD& nCurrent,
	int nMin,
	int nMax )
{
	if ( pszText == NULL || *pszText == L'\0' )
		return false;

	const wchar_t* p = pszText;
	while ( *p == L' ' || *p == L'\t' )
		++p;

	if ( *p == L'\0' )
		return false;

	wchar_t* pEnd = NULL;
	const long nParsed = wcstol( p, &pEnd, 10 );
	if ( pEnd == p )
		return false;

	while ( *pEnd == L' ' || *pEnd == L'\t' )
		++pEnd;
	if ( *pEnd != L'\0' )
		return false;

	long nClamped = nParsed;
	if ( nClamped < nMin )
		nClamped = nMin;
	else if ( nClamped > nMax )
		nClamped = nMax;

	nCurrent = static_cast<DWORD>( nClamped );
	return true;
}

//////////////////////////////////////////////////////////////////////
// point + size → CRect-like corners (left, top, right, bottom)

struct SkinParsedRect
{
	int left;
	int top;
	int right;
	int bottom;
};

// Parses point="x,y" and size="cx,cy" into inclusive-origin + extent corners:
// right = left + cx, bottom = top + cy.
// Returns false if either attribute is missing/malformed.
inline bool ParseSkinPointSizeRect(
	LPCWSTR pszPoint,
	LPCWSTR pszSize,
	SkinParsedRect& oRect )
{
	if ( pszPoint == NULL || pszSize == NULL )
		return false;

	int x = 0;
	int y = 0;
	int cx = 0;
	int cy = 0;

	if ( swscanf_s( pszPoint, L"%i,%i", &x, &y ) != 2 )
		return false;
	if ( swscanf_s( pszSize, L"%i,%i", &cx, &cy ) != 2 )
		return false;

	oRect.left = x;
	oRect.top = y;
	oRect.right = x + cx;
	oRect.bottom = y + cy;
	return true;
}

//////////////////////////////////////////////////////////////////////
// Part name suffix truncation (. / Hover / Down / Alt markers)

// Mirrors historical FindOneOf(L".HDA") truncation used to recover the base
// part name (e.g. CloseHover → Close). Returns false when no truncate index
// exists (including FindOneOf == -1 and index 0).
inline bool TruncateSkinPartNameSuffix( LPCWSTR pszName, wchar_t* pszOut, size_t cchOut )
{
	if ( pszName == NULL || pszOut == NULL || cchOut == 0 )
		return false;

	const size_t nLen = wcslen( pszName );
	if ( nLen == 0 || nLen >= cchOut )
		return false;

	const wchar_t* const pHit = wcspbrk( pszName, L".HDA" );
	if ( pHit == NULL )
	{
		wcsncpy_s( pszOut, cchOut, pszName, _TRUNCATE );
		return false;
	}

	const size_t nTruncate = static_cast<size_t>( pHit - pszName );
	if ( nTruncate == 0 )
	{
		wcsncpy_s( pszOut, cchOut, pszName, _TRUNCATE );
		return false;
	}

	wcsncpy_s( pszOut, cchOut, pszName, nTruncate );
	return true;
}

inline bool SkinPartNameNeedsSuffixTruncate( LPCWSTR pszName )
{
	if ( pszName == NULL || *pszName == L'\0' )
		return false;

	const wchar_t* const pHit = wcspbrk( pszName, L".HDA" );
	if ( pHit == NULL )
		return false;

	return ( pHit - pszName ) > 0;
}

//////////////////////////////////////////////////////////////////////
// roundRect corner radii

inline bool ParseSkinRoundRectSize( LPCWSTR pszSize, int& nWidth, int& nHeight )
{
	nWidth = 0;
	nHeight = 0;

	if ( pszSize == NULL || *pszSize == L'\0' )
		return false;

	int w = 0;
	int h = 0;
	if ( swscanf_s( pszSize, L"%i,%i", &w, &h ) != 2 )
		return false;
	if ( w < 0 || h < 0 )
		return false;

	nWidth = w;
	nHeight = h;
	return true;
}

//////////////////////////////////////////////////////////////////////
// LoadFromXML success aggregation (non-transactional)

struct SkinLoadSuccessState
{
	bool bSuccess;

	SkinLoadSuccessState()
		: bSuccess( true )
	{
	}

	void OnSectionResult( bool bSectionOk )
	{
		bSuccess = bSuccess && bSectionOk;
	}

	void OnUnknownRootElement()
	{
		bSuccess = false;
	}

	void OnInvalidManifest()
	{
		bSuccess = false;
	}
};
