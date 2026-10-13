//
// test_dc_hublist_sources_smoke.cpp
//
// Offline smoke tests for the default DC hublist URL and Update Servers
// dialog mode/skin names. No live HTTP.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "test_envy_rc_fixture.h"
#include "../Envy/DcHublistSources.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static bool ReadDefaultServices( std::string& out )
{
	const char* paths[] = {
		"Data/DefaultServices.dat",
		"../Data/DefaultServices.dat",
		"../../Data/DefaultServices.dat",
		"../../../Data/DefaultServices.dat",
		"../../../../Data/DefaultServices.dat"
	};
	for ( const char* path : paths )
	{
		if ( TestReadTextFile( path, out ) )
			return true;
	}
	std::fputs( "default_services_dc_hublists: Data/DefaultServices.dat not found from cwd\n", stderr );
	return false;
}

static int CountActiveHublistLines( const std::string& text )
{
	int nCount = 0;
	size_t i = 0;
	while ( i < text.size() )
	{
		size_t j = text.find( '\n', i );
		if ( j == std::string::npos )
			j = text.size();
		std::string line = text.substr( i, j - i );
		if ( ! line.empty() && line.back() == '\r' )
			line.pop_back();
		if ( line.size() >= 2 && line[0] == 'H' && line[1] == ' ' )
			++nCount;
		i = ( j < text.size() ) ? j + 1 : text.size();
	}
	return nCount;
}

static bool LineStartsWithH( const std::string& text, const char* url )
{
	const std::string needle = std::string( "H " ) + url;
	size_t pos = 0;
	while ( pos < text.size() )
	{
		size_t j = text.find( '\n', pos );
		if ( j == std::string::npos )
			j = text.size();
		std::string line = text.substr( pos, j - pos );
		if ( ! line.empty() && line.back() == '\r' )
			line.pop_back();
		if ( line == needle )
			return true;
		pos = ( j < text.size() ) ? j + 1 : text.size();
	}
	return false;
}

static bool AllActiveHublistsAreHttps( const std::string& text )
{
	size_t pos = 0;
	bool bSaw = false;
	while ( pos < text.size() )
	{
		size_t j = text.find( '\n', pos );
		if ( j == std::string::npos )
			j = text.size();
		std::string line = text.substr( pos, j - pos );
		if ( ! line.empty() && line.back() == '\r' )
			line.pop_back();
		if ( line.size() >= 2 && line[0] == 'H' && line[1] == ' ' )
		{
			bSaw = true;
			if ( line.size() < 10 || line.compare( 2, 8, "https://" ) != 0 )
				return false;
		}
		pos = ( j < text.size() ) ? j + 1 : text.size();
	}
	return bSaw;
}

static bool Utf8Contains( const std::string& hay, const char* needle )
{
	return hay.find( needle ) != std::string::npos;
}

static bool WideFromUtf8( const std::string& utf8, std::wstring& out )
{
	if ( utf8.empty() )
	{
		out.clear();
		return true;
	}
	const int nNeeded = MultiByteToWideChar( CP_UTF8, 0, utf8.data(),
		static_cast<int>( utf8.size() ), nullptr, 0 );
	if ( nNeeded <= 0 )
		return false;
	out.assign( static_cast<size_t>( nNeeded ), L'\0' );
	return MultiByteToWideChar( CP_UTF8, 0, utf8.data(), static_cast<int>( utf8.size() ),
			   &out[0], nNeeded ) == nNeeded;
}

static bool test_dc_default_hublist_url_is_https_org()
{
	const wchar_t* psz = DcDefaultHubListUrl();
	return psz != nullptr
		&& wcscmp( psz, L"https://dchublist.org/hublist.xml.bz2" ) == 0
		&& wcsstr( psz, L"dchublist.com" ) == nullptr
		&& wcsncmp( psz, L"https://", 8 ) == 0;
}

static bool test_update_servers_skin_names_by_mode()
{
	return wcscmp( UpdateServersDlgSkinName( UpdateServersDlgMode::eDonkey ),
			UpdateServersDlgEd2kSkinName() ) == 0
		&& wcscmp( UpdateServersDlgSkinName( UpdateServersDlgMode::DC ),
			UpdateServersDlgDcSkinName() ) == 0
		&& wcscmp( UpdateServersDlgEd2kSkinName(), L"CUpdateServersDlg" ) == 0
		&& wcscmp( UpdateServersDlgDcSkinName(), L"CUpdateHubListDlg" ) == 0;
}

static bool test_dc_dialog_title_is_not_server_met()
{
	std::string rc;
	if ( ! TestReadEnvyRc( rc, "dc_dialog_title_is_not_server_met: Envy/Envy.rc not found from cwd\n" ) )
		return false;

	std::string titleUtf8;
	std::string textUtf8;
	if ( ! TestExtractRcQuotedString( rc, "IDS_UPDATE_DC_HUBLIST_TITLE", titleUtf8 )
		|| ! TestExtractRcQuotedString( rc, "IDS_UPDATE_DC_HUBLIST_TEXT", textUtf8 ) )
		return false;

	std::wstring title;
	std::wstring text;
	if ( ! WideFromUtf8( titleUtf8, title ) || ! WideFromUtf8( textUtf8, text ) )
		return false;

	// Keep header helpers aligned with Envy.rc STRINGTABLE.
	if ( wcscmp( title.c_str(), DcHublistDialogTitleEn() ) != 0 )
		return false;
	if ( wcscmp( text.c_str(), DcHublistDialogTextEn() ) != 0 )
		return false;

	return DcHublistDialogTitleLooksLikeHublist( title.c_str() )
		&& ! DcHublistDialogTitleLooksLikeHublist( L"Download Server.met File" )
		&& ! DcHublistDialogTitleLooksLikeHublist( L"T\u00E9l\u00E9charger un fichier Server.met" )
		&& wcsstr( text.c_str(), L"server.met" ) == nullptr
		&& wcsstr( text.c_str(), L"eDonkey" ) == nullptr
		&& wcsstr( text.c_str(), L"Hub list URL:" ) != nullptr
		&& ! Utf8Contains( titleUtf8, "Server.met" )
		&& ! Utf8Contains( textUtf8, "server.met" );
}

static bool test_default_services_dc_hublists()
{
	std::string text;
	if ( ! ReadDefaultServices( text ) )
		return false;
	return LineStartsWithH( text, "https://dchublist.org/hublist.xml.bz2" )
		&& LineStartsWithH( text, "https://hublist.pwiam.com/hublist.xml.bz2" )
		&& LineStartsWithH( text, "https://dchublist.ru/hublist.xml.bz2" )
		&& AllActiveHublistsAreHttps( text )
		&& CountActiveHublistLines( text ) >= 2;
}

void register_dc_hublist_sources_smoke_tests( TestSuite& suite )
{
	suite.add_test( "dc_default_hublist_url_is_https_org", test_dc_default_hublist_url_is_https_org );
	suite.add_test( "update_servers_skin_names_by_mode", test_update_servers_skin_names_by_mode );
	suite.add_test( "dc_dialog_title_is_not_server_met", test_dc_dialog_title_is_not_server_met );
	suite.add_test( "default_services_dc_hublists", test_default_services_dc_hublists );
}
