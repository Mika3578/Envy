//
// test_magnet_builder_smoke.cpp
//
// Regression tests for magnet exact-topic generation.
//
// These tests cover BuildMagnetQuery itself; the CLibraryFile::PrepareDoc
// call site maps each file hash to its positional parameter there, and
// that mapping is MFC-bound so it is reviewed rather than unit-tested
// here.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/MagnetBuilder.h"

#include <string>

static bool contains( const std::wstring& strHaystack, const wchar_t* pszNeedle )
{
	return strHaystack.find( pszNeedle ) != std::wstring::npos;
}

// A BitTorrent info-hash must never be built from the MD5 bytes: the btih
// topic is generated from the BTH and nothing else.
static bool test_magnet_btih_uses_bth_not_md5()
{
	const std::wstring strMagnet = BuildMagnetQuery(
		L"File%20Name.zip", L"1234",
		NULL, NULL, NULL,
		L"0123456789abcdef0123456789abcdef",	// MD5 (wrong bytes historically)
		L"fedcba9876543210fedcba9876543210fedcba98" );	// BTH

	if ( ! contains( strMagnet, L"xt=urn:btih:fedcba9876543210fedcba9876543210fedcba98" ) )
		return false;
	if ( contains( strMagnet, L"urn:btih:0123456789abcdef" ) )
		return false;

	return contains( strMagnet, L"xt=urn:md5:0123456789abcdef0123456789abcdef" );
}

// With both hashes present the two exact topics stay distinct and correct.
static bool test_magnet_md5_and_btih_distinct()
{
	const std::wstring strMagnet = BuildMagnetQuery(
		L"f", L"1", NULL, NULL, NULL,
		L"0123456789abcdef0123456789abcdef",
		L"fedcba9876543210fedcba9876543210fedcba98" );

	const size_t nMD5 = strMagnet.find( L"xt=urn:md5:0123456789abcdef0123456789abcdef" );
	const size_t nBTH = strMagnet.find( L"xt=urn:btih:fedcba9876543210fedcba9876543210fedcba98" );

	return nMD5 != std::wstring::npos && nBTH != std::wstring::npos && nMD5 < nBTH;
}

// No BTH means no btih topic at all: no empty or mislabeled exact topic.
static bool test_magnet_no_btih_without_bth()
{
	const std::wstring strMagnet = BuildMagnetQuery(
		L"f", L"1", NULL, NULL, NULL,
		L"0123456789abcdef0123456789abcdef", NULL );

	return ! contains( strMagnet, L"urn:btih" );
}

// A bitprint supersedes lone SHA-1 or Tiger topics; SHA-1 alone still emits.
static bool test_magnet_bitprint_priority()
{
	const std::wstring strBoth = BuildMagnetQuery(
		L"f", L"1",
		L"1111111111111111111111111111111111111111",
		L"2222222222222222222222222222222222222222222222222222222222222222",
		NULL, NULL, NULL );

	if ( ! contains( strBoth, L"xt=urn:bitprint:1111111111111111111111111111111111111111.2222222222222222222222222222222222222222222222222222222222222222" ) )
		return false;
	if ( contains( strBoth, L"urn:sha1:" ) || contains( strBoth, L"urn:tree:tiger" ) )
		return false;

	const std::wstring strSHA1Only = BuildMagnetQuery(
		L"f", L"1", L"1111111111111111111111111111111111111111", NULL, NULL, NULL, NULL );

	return contains( strSHA1Only, L"xt=urn:sha1:1111111111111111111111111111111111111111" );
}

// Empty input yields the bare magnet shell with the display name, and the
// ED2K/MD5/BTH topics keep their historical append order with XML-escaped
// separators plus the length suffix.
static bool test_magnet_shape_and_order()
{
	const std::wstring strEmpty = BuildMagnetQuery(
		L"n", L"", NULL, NULL, NULL, NULL, NULL );

	if ( strEmpty != L"magnet:?&amp;dn=n" ) return false;

	const std::wstring strFull = BuildMagnetQuery(
		L"n", L"9",
		NULL, NULL,
		L"edededededededededededededededed",
		L"0123456789abcdef0123456789abcdef",
		L"fedcba9876543210fedcba9876543210fedcba98" );

	if ( ! contains( strFull, L"xt=urn:ed2khash:edededededededededededededededed" ) )
		return false;
	if ( ! contains( strFull, L"&amp;xl=9" ) )
		return false;

	const size_t nED2K = strFull.find( L"urn:ed2khash:" );
	const size_t nMD5 = strFull.find( L"urn:md5:" );
	const size_t nBTH = strFull.find( L"urn:btih:" );
	const size_t nXL = strFull.find( L"&amp;xl=9" );
	const size_t nDN = strFull.find( L"&amp;dn=n" );

	return nED2K < nMD5 && nMD5 < nBTH && nBTH < nXL && nXL < nDN;
}

void register_magnet_builder_smoke_tests( TestSuite& suite )
{
	suite.add_test( "magnet_btih_uses_bth_not_md5",
		test_magnet_btih_uses_bth_not_md5 );
	suite.add_test( "magnet_md5_and_btih_distinct",
		test_magnet_md5_and_btih_distinct );
	suite.add_test( "magnet_no_btih_without_bth",
		test_magnet_no_btih_without_bth );
	suite.add_test( "magnet_bitprint_priority",
		test_magnet_bitprint_priority );
	suite.add_test( "magnet_shape_and_order",
		test_magnet_shape_and_order );
}
