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

static bool ReadTextFile( const char* path, std::string& out )
{
	FILE* fp = nullptr;
	if ( fopen_s( &fp, path, "rb" ) != 0 || ! fp )
		return false;
	if ( fseek( fp, 0, SEEK_END ) != 0 )
	{
		fclose( fp );
		return false;
	}
	const long nSize = ftell( fp );
	if ( nSize < 0 || nSize > 1024 * 1024 )
	{
		fclose( fp );
		return false;
	}
	if ( fseek( fp, 0, SEEK_SET ) != 0 )
	{
		fclose( fp );
		return false;
	}
	std::vector<char> buf( static_cast<size_t>( nSize ) + 1u, '\0' );
	const size_t nRead = fread( buf.data(), 1, static_cast<size_t>( nSize ), fp );
	fclose( fp );
	if ( nRead != static_cast<size_t>( nSize ) )
		return false;
	out.assign( buf.data(), nRead );
	return true;
}

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
		if ( ReadTextFile( path, out ) )
			return true;
	}
	std::fputs( "default_services_dc_hublists: Data/DefaultServices.dat not found from cwd\n", stderr );
	return false;
}

static bool ReadEnvyRc( std::string& out )
{
	const char* paths[] = {
		"Envy/Envy.rc",
		"../Envy/Envy.rc",
		"../../Envy/Envy.rc",
		"../../../Envy/Envy.rc",
		"../../../../Envy/Envy.rc"
	};
	for ( const char* path : paths )
	{
		if ( ReadTextFile( path, out ) )
			return true;
	}
	std::fputs( "dc_dialog_title_is_not_server_met: Envy/Envy.rc not found from cwd\n", stderr );
	return false;
}

static bool ExtractRcQuotedString( const std::string& text, const char* id, std::string& value )
{
	const std::string key = std::string( id );
	size_t pos = 0;
	while ( ( pos = text.find( key, pos ) ) != std::string::npos )
	{
		if ( pos > 0 )
		{
			const char prev = text[pos - 1];
			if ( ( prev >= 'A' && prev <= 'Z' ) || ( prev >= 'a' && prev <= 'z' ) ||
				 ( prev >= '0' && prev <= '9' ) || prev == '_' )
			{
				pos += key.size();
				continue;
			}
		}
		size_t i = pos + key.size();
		while ( i < text.size() && ( text[i] == ' ' || text[i] == '\t' ) )
			++i;
		if ( i >= text.size() || text[i] != '"' )
		{
			pos += key.size();
			continue;
		}
		++i;
		std::string out;
		while ( i < text.size() )
		{
			const char c = text[i++];
			if ( c == '"' )
			{
				value.swap( out );
				return true;
			}
			if ( c == '\\' && i < text.size() )
			{
				const char esc = text[i++];
				if ( esc == 'n' )
					out.push_back( '\n' );
				else if ( esc == 't' )
					out.push_back( '\t' );
				else if ( esc == 'r' )
					out.push_back( '\r' );
				else
					out.push_back( esc );
				continue;
			}
			out.push_back( c );
		}
		return false;
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
	if ( ! ReadEnvyRc( rc ) )
		return false;

	std::string titleUtf8;
	std::string textUtf8;
	if ( ! ExtractRcQuotedString( rc, "IDS_UPDATE_DC_HUBLIST_TITLE", titleUtf8 )
		|| ! ExtractRcQuotedString( rc, "IDS_UPDATE_DC_HUBLIST_TEXT", textUtf8 ) )
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
		&& ! LineStartsWithH( text, "http://dchublist.com/hublist.xml.bz2" )
		&& ! LineStartsWithH( text, "http://tankafett.biz/hublist.xml.bz2" )
		&& CountActiveHublistLines( text ) >= 2;
}

void register_dc_hublist_sources_smoke_tests( TestSuite& suite )
{
	suite.add_test( "dc_default_hublist_url_is_https_org", test_dc_default_hublist_url_is_https_org );
	suite.add_test( "update_servers_skin_names_by_mode", test_update_servers_skin_names_by_mode );
	suite.add_test( "dc_dialog_title_is_not_server_met", test_dc_dialog_title_is_not_server_met );
	suite.add_test( "default_services_dc_hublists", test_default_services_dc_hublists );
}
