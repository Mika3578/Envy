//
// DcHublistSources.h
//
// Default DC++ hublist URL and Update Servers dialog mode helpers.
// Shared by Settings registration, CUpdateServersDlg, and EnvyTests.
// No network I/O.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <cwchar>
#include <windows.h>

// Public HTTPS hublist documented by dchublist.org for current DC++ clients
// (NMDC rows; ImportHubList already skips adc:// and adcs://).
inline LPCTSTR DcDefaultHubListUrl()
{
	return L"https://dchublist.org/hublist.xml.bz2";
}

enum class UpdateServersDlgMode
{
	eDonkey,
	DC
};

inline LPCTSTR UpdateServersDlgEd2kSkinName()
{
	return L"CUpdateServersDlg";
}

inline LPCTSTR UpdateServersDlgDcSkinName()
{
	return L"CUpdateHubListDlg";
}

inline LPCTSTR UpdateServersDlgSkinName( UpdateServersDlgMode nMode )
{
	return ( nMode == UpdateServersDlgMode::DC )
		? UpdateServersDlgDcSkinName()
		: UpdateServersDlgEd2kSkinName();
}

// English STRINGTABLE fallbacks. Must stay in sync with Envy.rc.
inline LPCTSTR DcHublistDialogTitleEn()
{
	return L"Download a DC++ Hub List";
}

inline LPCTSTR DcHublistDialogTextEn()
{
	return L"You can download a public DC++ hub list to update the hub cache.\nHub list URL:";
}

inline bool DcHublistDialogTitleLooksLikeHublist( LPCTSTR pszTitle )
{
	if ( ! pszTitle || ! *pszTitle )
		return false;
	if ( wcsstr( pszTitle, L"Server.met" ) != nullptr
		|| wcsstr( pszTitle, L"server.met" ) != nullptr )
		return false;
	return wcsstr( pszTitle, L"DC++" ) != nullptr
		|| wcsstr( pszTitle, L"Hub List" ) != nullptr
		|| wcsstr( pszTitle, L"hub list" ) != nullptr;
}
