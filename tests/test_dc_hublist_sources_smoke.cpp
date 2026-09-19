//
// test_dc_hublist_sources_smoke.cpp
//
// Offline smoke tests for the default DC hublist URL and Update Servers
// dialog mode/skin names. No live HTTP.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
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
		"../../../Data/DefaultServices.dat"
	};
	for ( const char* path : paths )
	{
		FILE* fp = nullptr;
		if ( fopen_s( &fp, path, "rb" ) != 0 || ! fp )
			continue;
		if ( fseek( fp, 0, SEEK_END ) != 0 )
		{
			fclose( fp );
			continue;
		}
		const long nSize = ftell( fp );
		if ( nSize < 0 || nSize > 1024 * 1024 )
		{
			fclose( fp );
			continue;
		}
		if ( fseek( fp, 0, SEEK_SET ) != 0 )
		{
			fclose( fp );
			continue;
		}
		std::vector<char> buf( static_cast<size_t>( nSize ) + 1u, '\0' );
		const size_t nRead = fread( buf.data(), 1, static_cast<size_t>( nSize ), fp );
		fclose( fp );
		if ( nRead != static_cast<size_t>( nSize ) )
			continue;
		out.assign( buf.data(), nRead );
		return true;
	}
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
	return text.find( needle ) != std::string::npos;
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
	return DcHublistDialogTitleLooksLikeHublist( DcHublistDialogTitleEn() )
		&& ! DcHublistDialogTitleLooksLikeHublist( L"Download Server.met File" )
		&& ! DcHublistDialogTitleLooksLikeHublist( L"T\x00e9l\x00e9charger un fichier Server.met" )
		&& wcsstr( DcHublistDialogTextEn(), L"server.met" ) == nullptr
		&& wcsstr( DcHublistDialogTextEn(), L"eDonkey" ) == nullptr
		&& wcsstr( DcHublistDialogTextEn(), L"Hub list URL:" ) != nullptr;
}

static bool test_default_services_dc_hublists()
{
	std::string text;
	if ( ! ReadDefaultServices( text ) )
		return false;
	return LineStartsWithH( text, "https://dchublist.org/hublist.xml.bz2" )
		&& LineStartsWithH( text, "https://hublist.pwiam.com/hublist.xml.bz2" )
		&& LineStartsWithH( text, "https://dchublist.ru/hublist.xml.bz2" )
		&& text.find( "H http://dchublist.com/" ) == std::string::npos
		&& text.find( "H http://tankafett.biz" ) == std::string::npos
		&& CountActiveHublistLines( text ) >= 2;
}

void register_dc_hublist_sources_smoke_tests( TestSuite& suite )
{
	suite.add_test( "dc_default_hublist_url_is_https_org", test_dc_default_hublist_url_is_https_org );
	suite.add_test( "update_servers_skin_names_by_mode", test_update_servers_skin_names_by_mode );
	suite.add_test( "dc_dialog_title_is_not_server_met", test_dc_dialog_title_is_not_server_met );
	suite.add_test( "default_services_dc_hublists", test_default_services_dc_hublists );
}
