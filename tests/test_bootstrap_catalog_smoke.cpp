//
// test_bootstrap_catalog_smoke.cpp
//
// Offline parser tests for Data/DefaultServices.dat and DefaultServers.dat.
// No live P2P or HTTP.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/BootstrapCatalog.h"

#include <cstdio>
#include <string>
#include <cwchar>

namespace {

struct ServiceRow
{
	wchar_t type;
	std::wstring endpoint;
};

struct ServerRow
{
	wchar_t type;
	bool priority;
	std::wstring host;
};

BootstrapParseStatus ParseService(const wchar_t* line, ServiceRow* row)
{
	wchar_t cType = 0;
	const wchar_t* psz = nullptr;
	size_t n = 0;
	const BootstrapParseStatus st = BootstrapParseServiceLine(
		line, line ? wcslen( line ) : 0, &cType, &psz, &n );
	if ( st == BootstrapParseStatus::Ok && row )
	{
		row->type = cType;
		row->endpoint.assign( psz, n );
	}
	return st;
}

BootstrapParseStatus ParseServer(const wchar_t* line, ServerRow* row)
{
	wchar_t cType = 0;
	bool bPri = false;
	const wchar_t* psz = nullptr;
	size_t n = 0;
	const BootstrapParseStatus st = BootstrapParseServerLine(
		line, line ? wcslen( line ) : 0, &cType, &bPri, &psz, &n );
	if ( st == BootstrapParseStatus::Ok && row )
	{
		row->type = cType;
		row->priority = bPri;
		row->host.assign( psz, n );
	}
	return st;
}

const wchar_t* kShippedServices =
	L"M http://midian.jayl.de/g2/bazooka.php\n"
	L"M http://bj.ddns.net/beacon/gwc.php\n"
	L"M http://gweb3.4octets.co.uk/gwc.php\n"
	L"2 http://dkac.trillinux.org/dkac/dkac.php\n"
	L"U uhc:useast.gnutella.dyslexicfish.net:3558\n"
	L"U uhc:uswest.gnutella.dyslexicfish.net:3558\n"
	L"U uhc:uk.gnutella.dyslexicfish.net:3558\n"
	L"U uhc:au.gnutella.dyslexicfish.net:3558\n"
	L"U uhc:1.uhc.gtk-gnutella.nl:19104\n"
	L"U uhc:2.uhc.gtk-gnutella.nl:4876\n"
	L"D https://upd.emule-security.org/server.met\n"
	L"D https://shortypower.org/server.met\n"
	L"H https://dchublist.org/hublist.xml.bz2\n"
	L"H https://dchublist.ru/hublist.xml.bz2\n"
	L"H https://te-home.net/?do=hublist&get=hublist.xml.bz2\n";

void CountServices(const wchar_t* blob, int* nWeb, int* nG2, int* nG1, int* nMet, int* nHub)
{
	*nWeb = *nG2 = *nG1 = *nMet = *nHub = 0;
	const wchar_t* p = blob;
	while ( p && *p )
	{
		const wchar_t* eol = wcschr( p, L'\n' );
		const size_t nLine = eol ? static_cast< size_t >( eol - p ) : wcslen( p );
		std::wstring line( p, nLine );
		wchar_t cType = 0;
		const wchar_t* psz = nullptr;
		size_t n = 0;
		if ( BootstrapParseServiceLine( line.c_str(), line.size(), &cType, &psz, &n )
			== BootstrapParseStatus::Ok )
		{
			const BootstrapServiceClass cls = BootstrapClassifyServiceType( cType );
			if ( cls == BootstrapServiceClass::MultiGwc ||
				 cls == BootstrapServiceClass::G2Gwc ||
				 cls == BootstrapServiceClass::G1Gwc )
				++(*nWeb);
			if ( cls == BootstrapServiceClass::MultiGwc ||
				 cls == BootstrapServiceClass::G2Gwc )
				++(*nG2);
			if ( cls == BootstrapServiceClass::MultiGwc ||
				 cls == BootstrapServiceClass::G1Gwc )
				++(*nG1);
			if ( cls == BootstrapServiceClass::GnutellaUdp )
			{
				// UHC counts as G1 in EnoughServices.
				if ( n >= 4 && wcsncmp( psz, L"uhc:", 4 ) == 0 )
					++(*nG1);
				if ( n >= 5 && wcsncmp( psz, L"ukhl:", 5 ) == 0 )
					++(*nG2);
			}
			if ( cls == BootstrapServiceClass::Ed2kMet )
				++(*nMet);
			if ( cls == BootstrapServiceClass::DcHublist )
				++(*nHub);
		}
		p = eol ? eol + 1 : p + nLine;
		if ( !eol )
			break;
	}
}

} // namespace

static bool test_service_valid_https()
{
	ServiceRow row{};
	return ParseService( L"D https://upd.emule-security.org/server.met", &row )
		== BootstrapParseStatus::Ok
		&& row.type == L'D'
		&& row.endpoint == L"https://upd.emule-security.org/server.met";
}

static bool test_service_comment()
{
	return ParseService( L"# M http://example.invalid/gwc", nullptr )
		== BootstrapParseStatus::Skip;
}

static bool test_service_blank()
{
	return ParseService( L"   \t", nullptr ) == BootstrapParseStatus::Skip;
}

static bool test_service_unknown_type()
{
	return ParseService( L"Q http://example.invalid/gwc", nullptr )
		== BootstrapParseStatus::Invalid;
}

static bool test_service_invalid_url()
{
	return ParseService( L"D ftp://upd.emule-security.org/server.met", nullptr )
		== BootstrapParseStatus::Invalid;
}

static bool test_service_whitespace_endpoint()
{
	ServiceRow row{};
	return ParseService( L"2   http://dkac.trillinux.org/dkac/dkac.php", &row )
		== BootstrapParseStatus::Ok
		&& row.endpoint == L"http://dkac.trillinux.org/dkac/dkac.php";
}

static bool test_service_uhc()
{
	ServiceRow row{};
	return ParseService( L"U uhc:1.uhc.gtk-gnutella.nl:19104", &row )
		== BootstrapParseStatus::Ok
		&& BootstrapClassifyServiceType( row.type ) == BootstrapServiceClass::GnutellaUdp;
}

static bool test_server_valid_dht()
{
	ServerRow row{};
	return ParseServer( L"B dht.libtorrent.org:25401", &row )
		== BootstrapParseStatus::Ok
		&& row.type == L'B'
		&& !row.priority
		&& row.host == L"dht.libtorrent.org:25401";
}

static bool test_server_priority_and_comment()
{
	ServerRow row{};
	return ParseServer( L"B* dht.transmissionbt.com:6881\t# Transmission", &row )
		== BootstrapParseStatus::Ok
		&& row.priority
		&& row.host == L"dht.transmissionbt.com:6881";
}

static bool test_server_comment_line()
{
	return ParseServer( L"# B router.bitcomet.com:6881", nullptr )
		== BootstrapParseStatus::Skip;
}

static bool test_server_missing_port()
{
	return ParseServer( L"B router.bittorrent.com", nullptr )
		== BootstrapParseStatus::Invalid;
}

static bool test_server_unknown_type()
{
	return ParseServer( L"Z 1.2.3.4:1234", nullptr )
		== BootstrapParseStatus::Invalid;
}

static bool test_dedup_case_insensitive()
{
	const wchar_t* a = L"https://ShortyPower.org/server.met";
	const wchar_t* b = L"https://shortypower.org/server.met";
	const wchar_t* other = L"https://other.example/server.met";
	return BootstrapWideEqualsNoCase( a, wcslen( a ), b, wcslen( b ) )
		&& ! BootstrapWideEqualsNoCase( a, wcslen( a ), other, wcslen( other ) );
}

static bool test_shipped_catalogue_meets_minima()
{
	int nWeb = 0, nG2 = 0, nG1 = 0, nMet = 0, nHub = 0;
	CountServices( kShippedServices, &nWeb, &nG2, &nG1, &nMet, &nHub );
	return nWeb >= BootstrapMinWebCaches
		&& nG2 >= BootstrapMinG2Services
		&& nG1 >= BootstrapMinG1Services
		&& nMet >= BootstrapMinEd2kMet
		&& nHub >= BootstrapMinDcHublists;
}

static bool test_shipped_catalogue_no_static_ed2k_ip()
{
	return wcsstr( kShippedServices, L"176.103." ) == nullptr
		&& wcsstr( kShippedServices, L"91.226.212.11" ) == nullptr;
}

static bool test_shipped_catalogue_no_getenvy_gwc()
{
	return wcsstr( kShippedServices, L"cache.getenvy.com" ) == nullptr
		&& wcsstr( kShippedServices, L"dchublist.com/" ) == nullptr
		&& wcsstr( kShippedServices, L"tankafett.biz" ) == nullptr;
}

static bool test_optional_data_file_if_present()
{
	const char* paths[] = {
		"Data/DefaultServices.dat",
		"../Data/DefaultServices.dat",
		"../../Data/DefaultServices.dat",
		"../../../Data/DefaultServices.dat"
	};
	FILE* fp = nullptr;
	for ( const char* path : paths )
	{
		fp = fopen( path, "rb" );
		if ( fp )
			break;
	}
	if ( ! fp )
		return true;	// parser tests above still run; file may be absent from test cwd

	std::string bytes;
	char buf[ 4096 ];
	size_t nRead;
	while ( ( nRead = fread( buf, 1, sizeof( buf ), fp ) ) > 0 )
		bytes.append( buf, nRead );
	fclose( fp );

	std::wstring wide;
	wide.reserve( bytes.size() );
	for ( unsigned char ch : bytes )
		wide.push_back( static_cast< wchar_t >( ch ) );

	int nWeb = 0, nG2 = 0, nG1 = 0, nMet = 0, nHub = 0;
	CountServices( wide.c_str(), &nWeb, &nG2, &nG1, &nMet, &nHub );
	const bool bMinima = nWeb >= BootstrapMinWebCaches
		&& nG2 >= BootstrapMinG2Services
		&& nG1 >= BootstrapMinG1Services
		&& nMet >= BootstrapMinEd2kMet
		&& nHub >= BootstrapMinDcHublists;
	const bool bHttpsMet = wide.find( L"https://upd.emule-security.org/server.met" ) != std::wstring::npos;
	const bool bNoStaticEd2k = wide.find( L"176.103.48.36" ) == std::wstring::npos;
	return bMinima && bHttpsMet && bNoStaticEd2k;
}

void register_bootstrap_catalog_smoke_tests( TestSuite& suite )
{
	suite.add_test( "bootstrap_service_valid_https", test_service_valid_https );
	suite.add_test( "bootstrap_service_comment", test_service_comment );
	suite.add_test( "bootstrap_service_blank", test_service_blank );
	suite.add_test( "bootstrap_service_unknown_type", test_service_unknown_type );
	suite.add_test( "bootstrap_service_invalid_url", test_service_invalid_url );
	suite.add_test( "bootstrap_service_whitespace_endpoint", test_service_whitespace_endpoint );
	suite.add_test( "bootstrap_service_uhc", test_service_uhc );
	suite.add_test( "bootstrap_server_valid_dht", test_server_valid_dht );
	suite.add_test( "bootstrap_server_priority_and_comment", test_server_priority_and_comment );
	suite.add_test( "bootstrap_server_comment_line", test_server_comment_line );
	suite.add_test( "bootstrap_server_missing_port", test_server_missing_port );
	suite.add_test( "bootstrap_server_unknown_type", test_server_unknown_type );
	suite.add_test( "bootstrap_dedup_case_insensitive", test_dedup_case_insensitive );
	suite.add_test( "bootstrap_shipped_catalogue_meets_minima", test_shipped_catalogue_meets_minima );
	suite.add_test( "bootstrap_shipped_catalogue_no_static_ed2k_ip", test_shipped_catalogue_no_static_ed2k_ip );
	suite.add_test( "bootstrap_shipped_catalogue_no_getenvy_gwc", test_shipped_catalogue_no_getenvy_gwc );
	suite.add_test( "bootstrap_optional_data_file_if_present", test_optional_data_file_if_present );
}
