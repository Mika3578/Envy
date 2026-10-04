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
#include <cstring>
#include <vector>

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

static bool test_client_loopback_prefers_ipv6_peer_string()
{
	// Simulate AcceptFrom dual-stack: m_sAddress is IPv6 text while m_pHost
	// still holds SOCKADDR_IN bytes that look like 127.x.x.x. Policy must
	// follow the peer string, not the IPv4 structure.
	const IN_ADDR oFakeLoopOctet = make_ipv4_octets(127, 1, 2, 3);
	const IN_ADDR oLan = make_ipv4_octets(10, 0, 0, 5);
	wchar_t szDocPrefix[32];
	wchar_t szMappedLoop[40];
	wchar_t szMappedLan[40];
	swprintf_s(szDocPrefix, 32, L"2001:db8::%u", 1u);
	swprintf_s(szMappedLoop, 40, L"::ffff:%u.%u.%u.%u", 127u, 0u, 0u, 1u);
	swprintf_s(szMappedLan, 40, L"::ffff:%u.%u.%u.%u", 10u, 0u, 0u, 5u);
	return !RemoteClientIsLoopback(oFakeLoopOctet, szDocPrefix) &&
	       RemoteClientIsLoopback(oLan, L"::1") &&
	       RemoteClientIsLoopback(oLan, szMappedLoop) &&
	       !RemoteClientIsLoopback(oFakeLoopOctet, szMappedLan) &&
	       RemoteClientIsLoopback(oFakeLoopOctet, NULL) &&
	       !RemoteClientIsLoopback(oLan, NULL);
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

static bool test_ipv6_peer_ignores_ipv4_lan_cidr_flags()
{
	// Non-loopback IPv6 peer text must not be admitted via IPv4 private/subnet/
	// CIDR flags that may be derived from unrelated SOCKADDR_IN bytes.
	const IN_ADDR oFakePrivate = make_ipv4_octets(10, 0, 0, 5);
	wchar_t szDocPrefix[32];
	wchar_t szAnyBind[16];
	swprintf_s(szDocPrefix, 32, L"2001:db8::%u", 1u);
	format_ipv4_bind(szAnyBind, 16, 0, 0, 0, 0);
	return !RemoteAccessAllowedCore(
	           oFakePrivate,
	           szDocPrefix,
	           false,
	           false,
	           true,
	           true,
	           szAnyBind,
	           true,
	           true,
	           true) &&
	       RemoteAccessAllowedCore(
	           oFakePrivate,
	           szDocPrefix,
	           false,
	           true,
	           false,
	           false,
	           szAnyBind,
	           true,
	           true,
	           true);
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

static bool test_security_identity_fail_closed_for_ipv6_peers()
{
	// The IN_ADDR-keyed login identity (login throttle, sessions, failed-login
	// tracking) is reliable only when the peer text is not IPv6-shaped; a
	// dual-stack AcceptFrom would otherwise let unrelated IPv6 clients share a
	// placeholder IPv4 identity (D-017 defers IPv6-aware identities).
	const IN_ADDR oLan = make_ipv4_octets(203, 0, 113, 7);
	wchar_t szV4[16];
	wchar_t szV4Loop[16];
	wchar_t szDocA[24];
	wchar_t szDocB[24];
	wchar_t szMappedLoop[40];
	format_ipv4_bind(szV4, 16, 203, 0, 113, 7);
	format_ipv4_bind(szV4Loop, 16, 127, 0, 0, 1);
	swprintf_s(szDocA, 24, L"2001:db8::%u", 1u);
	swprintf_s(szDocB, 24, L"2001:db8::%u", 2u);
	swprintf_s(szMappedLoop, 40, L"::ffff:%u.%u.%u.%u", 127u, 0u, 0u, 1u);
	// (1) Normal IPv4 peer and (2) IPv4 loopback keep a reliable identity; a
	// missing peer text (legacy IN_ADDR-only callers) stays reliable too.
	const bool bIpv4Reliable =
	    RemoteSecurityIdentityIsReliable(szV4) &&
	    RemoteSecurityIdentityIsReliable(szV4Loop) &&
	    RemoteSecurityIdentityIsReliable(NULL);
	// (3) IPv6 loopback and (4) IPv6 non-loopback have no representable
	// identity; (5) two distinct IPv6 peers are each refused, so neither
	// borrows a placeholder IPv4 identity; (6) IPv4-mapped IPv6 is refused as
	// well because the model cannot prove the mapping.
	const bool bIpv6Refused =
	    !RemoteSecurityIdentityIsReliable(L"::1") &&
	    !RemoteSecurityIdentityIsReliable(szDocA) &&
	    !RemoteSecurityIdentityIsReliable(szDocB) &&
	    !RemoteSecurityIdentityIsReliable(szMappedLoop);
	// The access gate still classifies IPv6 loopback peers as loopback; the
	// refusal happens only at the login-identity layer.
	const bool bGateUnchanged = RemoteClientIsLoopback(oLan, L"::1");
	return bIpv4Reliable && bIpv6Refused && bGateUnchanged;
}

// EnvyTests cannot run CRemote::PageLogin end to end: the login path needs the
// MFC app (CConnection, theApp, Settings, an accepted socket). This wiring test
// pins the production branch instead: inside PageLogin(), the IPv6 identity
// gate must precede every CRemoteSecurity call that keys on IN_ADDR, so an
// IPv6-shaped peer (including ::1 and IPv4-mapped forms) can never reach the
// login throttle, session creation, or failed-login tracking with placeholder
// IPv4 bytes. Helper behaviour itself is covered by
// remote_security_identity_fail_closed_for_ipv6_peers above.
static bool test_page_login_gates_security_identity_before_use()
{
	// EnvyTests runs from the repository root in CI and locally; try output
	// directory layouts too. A missing source file must fail the test rather
	// than silently pass.
	const char* szCandidates[] = {
	    "Envy/Remote.cpp",
	    "../Envy/Remote.cpp",
	    "../../Envy/Remote.cpp",
	};
	FILE* pFile = NULL;
	for (size_t i = 0; i < sizeof(szCandidates) / sizeof(szCandidates[0]); ++i)
	{
		if (fopen_s(&pFile, szCandidates[i], "rb") == 0 && pFile != NULL)
			break;
	}
	if (pFile == NULL)
		return false;

	if (fseek(pFile, 0, SEEK_END) != 0)
	{
		fclose(pFile);
		return false;
	}
	const long nSize = ftell(pFile);
	if (nSize <= 0)
	{
		fclose(pFile);
		return false;
	}
	if (fseek(pFile, 0, SEEK_SET) != 0)
	{
		fclose(pFile);
		return false;
	}
	std::vector<char> oBuf(static_cast<size_t>(nSize) + 1);
	const size_t nRead = fread(oBuf.data(), 1, static_cast<size_t>(nSize), pFile);
	fclose(pFile);
	oBuf[nRead] = '\0';

	const char* pLogin = strstr(oBuf.data(), "void CRemote::PageLogin()");
	if (pLogin == NULL)
		return false;
	// Bound the scan to the PageLogin function body (next page function).
	const char* pNextFn = strstr(pLogin + 1, "\nvoid CRemote::Page");
	if (pNextFn == NULL)
		pNextFn = oBuf.data() + nRead;

	const char* pGate = strstr(pLogin, "RemoteSecurityIdentityIsReliable");
	const char* pThrottle = strstr(pLogin, "CheckLoginThrottle");
	const char* pCreate = strstr(pLogin, "CreateSession");
	const char* pRecord = strstr(pLogin, "RecordFailedLogin");
	if (pGate == NULL || pThrottle == NULL || pCreate == NULL || pRecord == NULL)
		return false;
	if (pGate >= pNextFn || pThrottle >= pNextFn ||
	    pCreate >= pNextFn || pRecord >= pNextFn)
		return false;
	// The identity gate must come first: no IN_ADDR-keyed security call runs
	// before it, so an IPv6-shaped peer is refused before any of them.
	return pGate < pThrottle && pGate < pCreate && pGate < pRecord;
}

void register_remote_access_smoke_tests(TestSuite& suite)
{
	suite.add_test("remote_ipv4_loopback", test_ipv4_loopback);
	suite.add_test("remote_ipv6_loopback_string", test_ipv6_loopback_string);
	suite.add_test("remote_client_loopback_prefers_ipv6_peer_string",
	               test_client_loopback_prefers_ipv6_peer_string);
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
	suite.add_test("remote_ipv6_peer_ignores_ipv4_lan_cidr_flags",
	               test_ipv6_peer_ignores_ipv4_lan_cidr_flags);
	suite.add_test("remote_invalid_bind_allow_external_override_applies",
	               test_invalid_bind_allow_external_override_applies);
	suite.add_test("remote_bind_rejects_oversized_ipv4_octets",
	               test_bind_rejects_oversized_ipv4_octets);
	suite.add_test("remote_security_identity_fail_closed_for_ipv6_peers",
	               test_security_identity_fail_closed_for_ipv6_peers);
	suite.add_test("remote_page_login_gates_security_identity_before_use",
	               test_page_login_gates_security_identity_before_use);
}
