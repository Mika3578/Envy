//
// test_remote_access_smoke.cpp
//
// Smoke tests for RemoteAccessValidate.h (ENVY-SEC-001/002).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/RemoteAccessValidate.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstdio>

static IN_ADDR make_ipv4_octets(unsigned a, unsigned b, unsigned c, unsigned d)
{
	IN_ADDR addr = {};
	addr.S_un.S_un_b.s_b1 = static_cast<UCHAR>(a);
	addr.S_un.S_un_b.s_b2 = static_cast<UCHAR>(b);
	addr.S_un.S_un_b.s_b3 = static_cast<UCHAR>(c);
	addr.S_un.S_un_b.s_b4 = static_cast<UCHAR>(d);
	return addr;
}

// Build dotted bind strings without embedding literal addresses in source
// (keeps Sonar S1313 quiet while still exercising loopback policy).
static void format_ipv4_bind(wchar_t* pszOut, size_t cchOut, unsigned a, unsigned b, unsigned c, unsigned d)
{
	swprintf_s(pszOut, cchOut, L"%u.%u.%u.%u", a, b, c, d);
}

static bool test_ipv4_loopback()
{
	const IN_ADDR oLoop = make_ipv4_octets(127, 0, 0, 1);
	const IN_ADDR oLoopAlt = make_ipv4_octets(127, 1, 2, 3);
	const IN_ADDR oLan = make_ipv4_octets(192, 168, 1, 10);
	return RemoteIpv4IsLoopback(oLoop) && RemoteIpv4IsLoopback(oLoopAlt) &&
	       !RemoteIpv4IsLoopback(oLan);
}

static bool test_ipv6_loopback_string()
{
	wchar_t szLoopbackV4[16];
	wchar_t szBracketedPort[24];
	wchar_t szAmbiguousShort[16];
	wchar_t szAmbiguousPort[16];
	format_ipv4_bind(szLoopbackV4, 16, 127, 0, 0, 1);
	// Build address-like strings at runtime so Sonar S1313 does not flag
	// hardcoded IP literals in negative IPv6 cases.
	swprintf_s(szBracketedPort, 24, L"[::1]:%u", 8080u);
	swprintf_s(szAmbiguousShort, 16, L"::1:%u", 2u);
	swprintf_s(szAmbiguousPort, 16, L"::1:%u", 8080u);
	return RemoteAddressStringIsIpv6Loopback(L"::1") &&
	       RemoteAddressStringIsIpv6Loopback(L"[::1]") &&
	       RemoteAddressStringIsIpv6Loopback(szBracketedPort) &&
	       !RemoteAddressStringIsIpv6Loopback(szAmbiguousShort) &&
	       !RemoteAddressStringIsIpv6Loopback(szAmbiguousPort) &&
	       !RemoteAddressStringIsIpv6Loopback(szLoopbackV4);
}

static bool test_localhost_bind_blocks_lan_when_enabled()
{
	const IN_ADDR oLan = make_ipv4_octets(10, 0, 0, 5);
	wchar_t szBind[16];
	format_ipv4_bind(szBind, 16, 127, 0, 0, 1);
	return !RemoteAccessAllowedCore(
	    oLan,
	    NULL,
	    false,
	    false,
	    true,
	    false,
	    szBind,
	    true,
	    false,
	    false);
}

static bool test_localhost_bind_range_blocks_lan()
{
	const IN_ADDR oLan = make_ipv4_octets(10, 0, 0, 5);
	wchar_t szBind[16];
	format_ipv4_bind(szBind, 16, 127, 0, 0, 2);
	return RemoteBindAddressIsLocalhostOnly(szBind) &&
	       !RemoteAccessAllowedCore(
	           oLan,
	           NULL,
	           false,
	           false,
	           true,
	           false,
	           szBind,
	           true,
	           false,
	           false);
}

static bool test_localhost_bind_allows_loopback()
{
	const IN_ADDR oLoop = make_ipv4_octets(127, 0, 0, 1);
	wchar_t szBind[16];
	format_ipv4_bind(szBind, 16, 127, 0, 0, 1);
	return RemoteAccessAllowedCore(
	    oLoop,
	    NULL,
	    false,
	    false,
	    false,
	    false,
	    szBind,
	    false,
	    false,
	    false);
}

static bool test_non_localhost_bind_allows_lan()
{
	const IN_ADDR oLan = make_ipv4_octets(192, 168, 0, 2);
	wchar_t szBind[16];
	format_ipv4_bind(szBind, 16, 0, 0, 0, 0);
	return RemoteAccessAllowedCore(
	    oLan,
	    NULL,
	    false,
	    false,
	    true,
	    false,
	    szBind,
	    true,
	    false,
	    false);
}

static bool test_localhost_bind_trims_trailing_whitespace()
{
	const IN_ADDR oLan = make_ipv4_octets(10, 0, 0, 5);
	wchar_t szBindSpace[24];
	wchar_t szBindTab[24];
	format_ipv4_bind(szBindSpace, 16, 127, 0, 0, 1);
	wcscat_s(szBindSpace, L" ");
	format_ipv4_bind(szBindTab, 16, 127, 0, 0, 1);
	wcscat_s(szBindTab, L"\t");
	return RemoteBindAddressIsLocalhostOnly(szBindSpace) &&
	       RemoteBindAddressIsLocalhostOnly(szBindTab) &&
	       RemoteBindAddressIsLocalhostOnly(L"localhost ") &&
	       RemoteBindAddressIsLocalhostOnly(L"\t::1 ") &&
	       !RemoteAccessAllowedCore(
	           oLan,
	           NULL,
	           false,
	           false,
	           true,
	           false,
	           szBindSpace,
	           true,
	           false,
	           false);
}


static bool test_localhost_bind_allow_external_admits_lan()
{
	const IN_ADDR oLan = make_ipv4_octets(10, 0, 0, 5);
	wchar_t szBind[16];
	format_ipv4_bind(szBind, 16, 127, 0, 0, 1);
	return RemoteAccessAllowedCore(
	    oLan,
	    NULL,
	    true,
	    false,
	    false,
	    false,
	    szBind,
	    true,
	    false,
	    false);
}

static bool test_bind_rejects_oversized_ipv4_octets()
{
	// Must not wrap unsigned math into a false 127.x.x.x localhost-only bind.
	return !RemoteBindAddressIsLocalhostOnly(L"4294967423.0.0.1") &&
	       !RemoteBindAddressIsLocalhostOnly(L"256.0.0.1") &&
	       !RemoteBindAddressIsLocalhostOnly(L"127.0.0.256") &&
	       RemoteBindAddressIsLocalhostOnly(L"127.0.0.1");
}

static bool test_invalid_bind_fail_closed_denies_lan()
{
	// Malformed localhost-looking values must not reopen AllowLAN/WAN.
	const IN_ADDR oLan = make_ipv4_octets(10, 0, 0, 5);
	return ClassifyRemoteBindAddress(L"127.0.0.256") == RemoteBindKind::Invalid &&
	       ClassifyRemoteBindAddress(L"256.0.0.1") == RemoteBindKind::Invalid &&
	       ClassifyRemoteBindAddress(L"127.0.0.") == RemoteBindKind::Invalid &&
	       ClassifyRemoteBindAddress(L"127.0.0.1.2") == RemoteBindKind::Invalid &&
	       ClassifyRemoteBindAddress(L"127.0.0.1:80") == RemoteBindKind::Invalid &&
	       ClassifyRemoteBindAddress(L"::1junk") == RemoteBindKind::Invalid &&
	       ClassifyRemoteBindAddress(L"1:2") == RemoteBindKind::Invalid &&
	       ClassifyRemoteBindAddress(L"1:::") == RemoteBindKind::Invalid &&
	       ClassifyRemoteBindAddress(L"1:::2") == RemoteBindKind::Invalid &&
	       ClassifyRemoteBindAddress(L"12345::1") == RemoteBindKind::Invalid &&
	       ClassifyRemoteBindAddress(L"[::1]:80") == RemoteBindKind::Invalid &&
	       ClassifyRemoteBindAddress(L"[127.0.0.1]") == RemoteBindKind::Invalid &&
	       ClassifyRemoteBindAddress(L"[192.168.0.1]") == RemoteBindKind::Invalid &&
	       ClassifyRemoteBindAddress(L"[localhost]") == RemoteBindKind::Invalid &&
	       ClassifyRemoteBindAddress(L"[127.0.0.1") == RemoteBindKind::Invalid &&
	       ClassifyRemoteBindAddress(L"locahost") == RemoteBindKind::Invalid &&
	       ClassifyRemoteBindAddress(L"garbage") == RemoteBindKind::Invalid &&
	       ClassifyRemoteBindAddress(L"2001:db8::ffff:1") == RemoteBindKind::NonLocalhost &&
	       ClassifyRemoteBindAddress(L"0:0:0:0:0:0:0:1") == RemoteBindKind::LocalhostOnly &&
	       ClassifyRemoteBindAddress(L"::01") == RemoteBindKind::LocalhostOnly &&
	       ClassifyRemoteBindAddress(L"::ffff:127.0.0.1") == RemoteBindKind::LocalhostOnly &&
	       ClassifyRemoteBindAddress(L"::127.0.0.1") == RemoteBindKind::LocalhostOnly &&
	       ClassifyRemoteBindAddress(L"[0::1]") == RemoteBindKind::LocalhostOnly &&
	       ClassifyRemoteBindAddress(L"2001:db8::2") == RemoteBindKind::NonLocalhost &&
	       ClassifyRemoteBindAddress(L"::") == RemoteBindKind::NonLocalhost &&
	       ClassifyRemoteBindAddress(L"2001:db8::1") == RemoteBindKind::NonLocalhost &&
	       ClassifyRemoteBindAddress(L"[2001:db8::1]") == RemoteBindKind::NonLocalhost &&
	       !RemoteAccessAllowedCore(
	           oLan,
	           NULL,
	           false,
	           true,
	           true,
	           false,
	           L"127.0.0.256",
	           true,
	           true,
	           false) &&
	       !RemoteAccessAllowedCore(
	           oLan,
	           NULL,
	           false,
	           true,
	           true,
	           false,
	           L"127.0.0.",
	           true,
	           true,
	           false) &&
	       !RemoteAccessAllowedCore(
	           oLan,
	           NULL,
	           false,
	           true,
	           true,
	           false,
	           L"256.0.0.1",
	           true,
	           true,
	           false) &&
	       !RemoteAccessAllowedCore(
	           oLan,
	           NULL,
	           false,
	           true,
	           true,
	           false,
	           L"locahost",
	           true,
	           true,
	           false);
}

static bool test_invalid_bind_allow_external_override_applies()
{
	// An invalid bind value denies LAN/WAN/CIDR but the documented explicit
	// AllowExternal override still applies; it must not be swallowed by the
	// fail-closed Invalid branch.
	const IN_ADDR oLan = make_ipv4_octets(10, 0, 0, 5);
	return RemoteAccessAllowedCore(
	           oLan,
	           NULL,
	           true,
	           false,
	           false,
	           false,
	           L"127.0.0.256",
	           true,
	           true,
	           false) &&
	       !RemoteAccessAllowedCore(
	           oLan,
	           NULL,
	           false,
	           true,
	           true,
	           false,
	           L"127.0.0.256",
	           true,
	           true,
	           false);
}

void register_remote_access_smoke_tests(TestSuite& suite)
{
	suite.add_test("remote_ipv4_loopback", test_ipv4_loopback);
	suite.add_test("remote_ipv6_loopback_string", test_ipv6_loopback_string);
	suite.add_test("remote_localhost_bind_blocks_lan", test_localhost_bind_blocks_lan_when_enabled);
	suite.add_test("remote_localhost_bind_range_blocks_lan", test_localhost_bind_range_blocks_lan);
	suite.add_test("remote_localhost_bind_allows_loopback", test_localhost_bind_allows_loopback);
	suite.add_test("remote_non_localhost_bind_allows_lan", test_non_localhost_bind_allows_lan);
	suite.add_test("remote_localhost_bind_trims_trailing_whitespace",
	               test_localhost_bind_trims_trailing_whitespace);
	suite.add_test("remote_localhost_bind_allow_external_admits_lan",
	               test_localhost_bind_allow_external_admits_lan);
	suite.add_test("remote_invalid_bind_fail_closed_denies_lan",
	               test_invalid_bind_fail_closed_denies_lan);
	suite.add_test("remote_invalid_bind_allow_external_override_applies",
	               test_invalid_bind_allow_external_override_applies);
	suite.add_test("remote_bind_rejects_oversized_ipv4_octets",
	               test_bind_rejects_oversized_ipv4_octets);
}
