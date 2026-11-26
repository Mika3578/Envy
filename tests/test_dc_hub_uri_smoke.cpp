//
// test_dc_hub_uri_smoke.cpp
//
// Regression tests for Direct Connect hublist URI classification.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/DcHubUri.h"

#include <string>

static bool parses_to( const wchar_t* pszAddress, DcHubUriStatus nExpected, const wchar_t* pszHostPort )
{
	std::wstring strOut;
	const DcHubUriStatus nStatus = DcClassifyHubUri( pszAddress, &strOut );
	if ( nStatus != nExpected ) return false;
	if ( ! pszHostPort ) return strOut.empty();
	return strOut == pszHostPort;
}

static bool test_dchub_supported()
{
	return parses_to( L"dchub://example.org:411", DcHubUriStatus::NmdcDchub, L"example.org:411" )
		&& parses_to( L"DCHUB://Example.ORG", DcHubUriStatus::NmdcDchub, L"Example.ORG" )
		&& parses_to( L"dchub://192.0.2.7:7654/", DcHubUriStatus::NmdcDchub, L"192.0.2.7:7654" );
}

// Plain nmdc:// is accepted as a plaintext NMDC alias (no new transport).
static bool test_nmdc_alias_accepted()
{
	return parses_to( L"nmdc://example.org:411", DcHubUriStatus::NmdcAlias, L"example.org:411" )
		&& parses_to( L"NMDC://Hub.Name", DcHubUriStatus::NmdcAlias, L"Hub.Name" );
}

// The regression at the heart of the issue: a secure NMDC URI must never
// reach DNS as the literal host "nmdcs", and must not fall back to plaintext.
static bool test_nmdc_secure_rejected_no_dns()
{
	return parses_to( L"nmdcs://example.org:411", DcHubUriStatus::NmdcSecure, NULL )
		&& parses_to( L"NMDCS://example.org", DcHubUriStatus::NmdcSecure, NULL );
}

// ADC/ADCS stay outside the NMDC parser until that protocol is supported.
static bool test_adc_schemes_skipped()
{
	return parses_to( L"adc://example.org:411", DcHubUriStatus::Adc, NULL )
		&& parses_to( L"adcs://example.org:411", DcHubUriStatus::Adcs, NULL );
}

static bool test_plain_forms()
{
	return parses_to( L"example.org:411", DcHubUriStatus::PlainHost, L"example.org:411" )
		&& parses_to( L"example.org", DcHubUriStatus::PlainHost, L"example.org" )
		&& parses_to( L"192.0.2.7:411", DcHubUriStatus::PlainHost, L"192.0.2.7:411" )
		&& parses_to( L"  example.org:411  ", DcHubUriStatus::PlainHost, L"example.org:411" );
}

// The DC path resolves IPv4 only, so bracketed authorities are rejected at
// import instead of being stored as entries that can never connect.
static bool test_bracketed_authorities_rejected()
{
	return parses_to( L"dchub://[2001:db8::1]:411", DcHubUriStatus::Malformed, NULL )
		&& parses_to( L"[2001:db8::1]", DcHubUriStatus::Malformed, NULL )
		&& parses_to( L"[not-an-ip]:411", DcHubUriStatus::Malformed, NULL )
		&& parses_to( L"[[::1]]", DcHubUriStatus::Malformed, NULL );
}

// A scheme name without "//" must not become a hostname: the resolver would
// cut nmdcs:411 at the colon and repeatedly resolve the literal "nmdcs".
static bool test_bare_scheme_tokens_rejected()
{
	return parses_to( L"nmdcs:411", DcHubUriStatus::Malformed, NULL )
		&& parses_to( L"nmdc:hub.example", DcHubUriStatus::Malformed, NULL )
		&& parses_to( L"dchub:411", DcHubUriStatus::Malformed, NULL )
		&& parses_to( L"adc:hub.example", DcHubUriStatus::Malformed, NULL )
		&& parses_to( L"DCHUB://nmdcs:411", DcHubUriStatus::Malformed, NULL );
}

static bool test_malformed_forms_rejected()
{
	// Missing host / empty forms
	if ( ! parses_to( L"", DcHubUriStatus::Malformed, NULL ) ) return false;
	if ( ! parses_to( L"dchub://", DcHubUriStatus::Malformed, NULL ) ) return false;
	if ( ! parses_to( L":411", DcHubUriStatus::Malformed, NULL ) ) return false;
	if ( ! parses_to( NULL, DcHubUriStatus::Malformed, NULL ) ) return false;

	// Bad ports: empty, zero, overflow, non-numeric, leading zero
	if ( ! parses_to( L"example.org:", DcHubUriStatus::Malformed, NULL ) ) return false;
	if ( ! parses_to( L"example.org:0", DcHubUriStatus::Malformed, NULL ) ) return false;
	if ( ! parses_to( L"example.org:65536", DcHubUriStatus::Malformed, NULL ) ) return false;
	if ( ! parses_to( L"example.org:999999", DcHubUriStatus::Malformed, NULL ) ) return false;
	if ( ! parses_to( L"example.org:41a1", DcHubUriStatus::Malformed, NULL ) ) return false;
	if ( ! parses_to( L"example.org:0411", DcHubUriStatus::Malformed, NULL ) ) return false;

	// Extra colons / ambiguous unbracketed IPv6 with port
	if ( ! parses_to( L"example.org:411:extra", DcHubUriStatus::Malformed, NULL ) ) return false;
	if ( ! parses_to( L"2001:db8::1", DcHubUriStatus::Malformed, NULL ) ) return false;

	// Unclosed bracket and internal whitespace
	if ( ! parses_to( L"dchub://[2001:db8::1:411", DcHubUriStatus::Malformed, NULL ) ) return false;
	if ( ! parses_to( L"example .org:411", DcHubUriStatus::Malformed, NULL ) ) return false;

	// Path, query and fragment suffixes cannot be part of an authority
	if ( ! parses_to( L"dchub://example.org/path", DcHubUriStatus::Malformed, NULL ) ) return false;
	if ( ! parses_to( L"dchub://example.org:411/extra", DcHubUriStatus::Malformed, NULL ) ) return false;
	if ( ! parses_to( L"dchub://example.org:411?list=1", DcHubUriStatus::Malformed, NULL ) ) return false;
	if ( ! parses_to( L"dchub://example.org:411#frag", DcHubUriStatus::Malformed, NULL ) ) return false;

	return true;
}

// Hosts must be valid dotted IPv4 literals or DNS names; anything else is
// stored unresolved and only feeds async DNS with garbage.
static bool test_host_labels_validated()
{
	// Hyphens may not start or end a label; labels are non-empty
	if ( ! parses_to( L"dchub://-bad", DcHubUriStatus::Malformed, NULL ) ) return false;
	if ( ! parses_to( L"dchub://bad-", DcHubUriStatus::Malformed, NULL ) ) return false;
	if ( ! parses_to( L"dchub://bad-.example.org", DcHubUriStatus::Malformed, NULL ) ) return false;

	// Empty labels and a trailing dot are not DNS names
	if ( ! parses_to( L"dchub://hub..example:411", DcHubUriStatus::Malformed, NULL ) ) return false;
	if ( ! parses_to( L"dchub://.example.org:411", DcHubUriStatus::Malformed, NULL ) ) return false;
	if ( ! parses_to( L"dchub://example.org.:411", DcHubUriStatus::Malformed, NULL ) ) return false;

	// Dotted literals must be exactly four decimal octets without leading
	// zeros (the resolver reads octal meaning into them)
	if ( ! parses_to( L"dchub://1.2.3.4.5:411", DcHubUriStatus::Malformed, NULL ) ) return false;
	if ( ! parses_to( L"dchub://1.2.3:411", DcHubUriStatus::Malformed, NULL ) ) return false;
	if ( ! parses_to( L"dchub://256.1.1.1:411", DcHubUriStatus::Malformed, NULL ) ) return false;
	if ( ! parses_to( L"dchub://010.1.1.1:411", DcHubUriStatus::Malformed, NULL ) ) return false;

	// Underscores and other symbols are not host characters
	if ( ! parses_to( L"dchub://hub_name:411", DcHubUriStatus::Malformed, NULL ) ) return false;

	// Valid forms still pass
	return parses_to( L"dchub://hub-1.example.com:411", DcHubUriStatus::NmdcDchub, L"hub-1.example.com:411" )
		&& parses_to( L"dchub://192.0.2.255:411", DcHubUriStatus::NmdcDchub, L"192.0.2.255:411" );
}

// Unknown schemes are unsupported and must never become hostnames; the
// stored host can never be a bare scheme token.
static bool test_unknown_scheme_never_a_host()
{
	if ( ! parses_to( L"ftp://example.org", DcHubUriStatus::Unsupported, NULL ) ) return false;
	if ( ! parses_to( L"nmdcss://example.org", DcHubUriStatus::Unsupported, NULL ) ) return false;

	std::wstring strOut;
	(void)DcClassifyHubUri( L"nmdcs://example.org:411", &strOut );
	return strOut.empty(); // no host extraction for rejected schemes
}

// Overlong host or URI forms are rejected, not truncated.
static bool test_overlong_rejected()
{
	std::wstring strHost( DC_HUB_HOST_MAX + 1, L'a' );
	std::wstring strUri = L"dchub://" + strHost;
	if ( ! parses_to( strUri.c_str(), DcHubUriStatus::Malformed, NULL ) ) return false;

	std::wstring strLong( DC_HUB_URI_MAX + 1, L'a' );
	return parses_to( strLong.c_str(), DcHubUriStatus::Malformed, NULL );
}

void register_dc_hub_uri_smoke_tests( TestSuite& suite )
{
	suite.add_test( "dc_hub_dchub_supported", test_dchub_supported );
	suite.add_test( "dc_hub_nmdc_alias_accepted", test_nmdc_alias_accepted );
	suite.add_test( "dc_hub_nmdc_secure_rejected_no_dns", test_nmdc_secure_rejected_no_dns );
	suite.add_test( "dc_hub_adc_schemes_skipped", test_adc_schemes_skipped );
	suite.add_test( "dc_hub_plain_forms", test_plain_forms );
	suite.add_test( "dc_hub_bracketed_authorities_rejected", test_bracketed_authorities_rejected );
	suite.add_test( "dc_hub_bare_scheme_tokens_rejected", test_bare_scheme_tokens_rejected );
	suite.add_test( "dc_hub_malformed_forms_rejected", test_malformed_forms_rejected );
	suite.add_test( "dc_hub_host_labels_validated", test_host_labels_validated );
	suite.add_test( "dc_hub_unknown_scheme_never_a_host", test_unknown_scheme_never_a_host );
	suite.add_test( "dc_hub_overlong_rejected", test_overlong_rejected );
}
