//
// RemoteAccessValidate.h
//
// Testable Remote HTML access policy helpers (loopback / bind semantics).
// Keep Winsock types only; avoid requiring ws2_32 at EnvyTests link time.
// Part of Envy (getenvy.com) © 2016-2026
//

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <cstring>
#include <tchar.h>

inline bool RemoteIpv4IsLoopback(const IN_ADDR& clientIP)
{
	// Full IPv4 loopback range 127.0.0.0/8. Read the first network-order
	// octet without ntohl so EnvyTests need not link ws2_32.
	const unsigned char* const pOctets =
	    reinterpret_cast<const unsigned char*>(&clientIP.s_addr);
	return pOctets[0] == 127u;
}

// Host must be exactly ::1, or bracketed [::1] with optional :port.
// Unbracketed "::1:…" is rejected: it is ambiguous with non-loopback IPv6
// addresses such as ::1:2.
inline bool RemoteAddressStringIsIpv6Loopback(LPCTSTR pszClientAddress)
{
	if (pszClientAddress == NULL || *pszClientAddress == 0)
		return false;

	if (_tcscmp(pszClientAddress, L"::1") == 0)
		return true;

	if (_tcsncmp(pszClientAddress, L"[::1]", 5) != 0)
		return false;

	LPCTSTR psz = pszClientAddress + 5;
	if (*psz == 0)
		return true;
	if (*psz != L':')
		return false;
	++psz;
	if (*psz == 0)
		return false;
	while (*psz)
	{
		if (*psz < L'0' || *psz > L'9')
			return false;
		++psz;
	}
	return true;
}

// Trim leading/trailing space and tab. Returns the start pointer; nLen is the
// trimmed character count (may be 0). Callers must not read past nLen.
inline LPCTSTR RemoteTrimBindAddressWhitespace(LPCTSTR pszBindAddress, size_t& nLen)
{
	nLen = 0;
	if (pszBindAddress == NULL)
		return NULL;
	while (*pszBindAddress == L' ' || *pszBindAddress == L'\t')
		++pszBindAddress;
	nLen = _tcslen(pszBindAddress);
	while (nLen > 0 &&
	       (pszBindAddress[nLen - 1] == L' ' || pszBindAddress[nLen - 1] == L'\t'))
	{
		--nLen;
	}
	return pszBindAddress;
}

// Strict dotted-quad parse for an IPv6 embedded IPv4 tail (four octets 0-255).
inline bool RemoteParseDottedQuad(LPCTSTR psz, size_t nLen, unsigned& nAddress)
{
	size_t i = 0;
	nAddress = 0;
	for (int octet = 0; octet < 4; ++octet)
	{
		unsigned value = 0;
		int nDigits = 0;
		while (i < nLen && psz[i] >= L'0' && psz[i] <= L'9')
		{
			value = value * 10u + static_cast<unsigned>(psz[i] - L'0');
			if (++nDigits > 3 || value > 255u)
				return false;
			++i;
		}
		if (nDigits == 0)
			return false;
		nAddress = (nAddress << 8) | value;
		if (octet < 3)
		{
			if (i >= nLen || psz[i] != L'.')
				return false;
			++i;
		}
	}
	return i == nLen;
}

// Full IPv6 literal syntax into eight 16-bit groups: at most one "::", an
// optional IPv4 tail in the last 32 bits, no zone id and no port.
inline bool RemoteParseIpv6Literal(LPCTSTR psz, size_t nLen, unsigned short (&groups)[8])
{
	unsigned short head[8] = {};
	unsigned short tail[8] = {};
	int nHead = 0;
	int nTail = 0;
	bool bDouble = false;
	size_t i = 0;

	if (nLen < 2)
		return false;
	if (psz[0] == L':')
	{
		if (psz[1] != L':')
			return false;
		bDouble = true;
		i = 2;
	}

	while (i < nLen)
	{
		const size_t nStart = i;
		bool bDot = false;
		while (i < nLen && psz[i] != L':')
		{
			if (psz[i] == L'.')
				bDot = true;
			++i;
		}
		const size_t nTok = i - nStart;
		if (nTok == 0)
			return false;

		unsigned short* const pGroups = bDouble ? tail : head;
		int& nCount = bDouble ? nTail : nHead;

		if (bDot)
		{
			unsigned nV4 = 0;
			if (i != nLen || nCount > 6 || !RemoteParseDottedQuad(psz + nStart, nTok, nV4))
				return false;
			pGroups[nCount++] = static_cast<unsigned short>(nV4 >> 16);
			pGroups[nCount++] = static_cast<unsigned short>(nV4 & 0xFFFFu);
			break;
		}

		if (nTok > 4 || nCount > 7)
			return false;
		unsigned value = 0;
		for (size_t k = nStart; k < i; ++k)
		{
			const TCHAR ch = psz[k];
			unsigned digit;
			if (ch >= L'0' && ch <= L'9')
				digit = static_cast<unsigned>(ch - L'0');
			else if (ch >= L'a' && ch <= L'f')
				digit = static_cast<unsigned>(ch - L'a') + 10u;
			else if (ch >= L'A' && ch <= L'F')
				digit = static_cast<unsigned>(ch - L'A') + 10u;
			else
				return false;
			value = (value << 4) | digit;
		}
		pGroups[nCount++] = static_cast<unsigned short>(value);

		if (i == nLen)
			break;
		++i; // skip ':'
		if (i == nLen)
			return false; // trailing single colon
		if (psz[i] == L':')
		{
			if (bDouble)
				return false;
			bDouble = true;
			++i;
			if (i < nLen && psz[i] == L':')
				return false; // reject ::: and other empty segments
		}
	}

	const int nTotal = nHead + nTail;
	if (bDouble ? nTotal > 7 : nTotal != 8)
		return false;

	for (int g = 0; g < 8; ++g)
		groups[g] = 0;
	for (int g = 0; g < nHead; ++g)
		groups[g] = head[g];
	for (int g = 0; g < nTail; ++g)
		groups[8 - nTail + g] = tail[g];
	return true;
}

// Any spelling of ::1, ::ffff:127.x.x.x or ::127.x.x.x (loopback).
inline bool RemoteIpv6GroupsAreLoopback(const unsigned short (&groups)[8])
{
	for (int g = 0; g < 5; ++g)
	{
		if (groups[g] != 0)
			return false;
	}
	if (groups[5] == 0 && groups[6] == 0 && groups[7] == 1)
		return true;
	if (groups[5] == 0xFFFFu || groups[5] == 0)
		return (groups[6] >> 8) == 127u;
	return false;
}

inline bool RemoteClientIsLoopback(const IN_ADDR& clientIP, LPCTSTR pszClientAddress)
{
	// Prefer IPv6-shaped peer text. AcceptFrom may fill m_sAddress via InetNtop
	// while m_pHost remains SOCKADDR_IN; those IPv4 bytes are not an IPv4 peer
	// for dual-stack sockets and must not classify a non-loopback IPv6 peer as
	// loopback when they coincidentally start with 127 (D-017).
	if (pszClientAddress != NULL && _tcschr(pszClientAddress, L':') != NULL)
	{
		if (RemoteAddressStringIsIpv6Loopback(pszClientAddress))
			return true;
		// InetNtop may emit mapped/canonical forms (::ffff:127.0.0.1, ::01,
		// 0:0:0:0:0:0:0:1) that the narrow ::1 helper rejects; reuse the same
		// group classification as BindAddress.
		size_t nLen = 0;
		LPCTSTR psz = RemoteTrimBindAddressWhitespace(pszClientAddress, nLen);
		if (psz == NULL || nLen == 0)
			return false;
		if (nLen >= 2 && psz[0] == L'[' && psz[nLen - 1] == L']')
		{
			++psz;
			nLen -= 2;
		}
		unsigned short groups[8];
		if (!RemoteParseIpv6Literal(psz, nLen, groups))
			return false;
		return RemoteIpv6GroupsAreLoopback(groups);
	}
	return RemoteIpv4IsLoopback(clientIP);
}

// The Remote login security model (login throttle, sessions, failed-login
// tracking) keys on IN_ADDR. When AcceptFrom stored an IPv6 peer string in
// m_sAddress, the m_pHost SOCKADDR_IN bytes are not the peer (D-017); using
// them would silently substitute unrelated IPv4 bytes and can make unrelated
// IPv6 clients share one placeholder security identity. Callers must fail
// closed until D-017 makes the identity model IPv6-aware. IPv4-mapped forms
// (::ffff:x.x.x.x) contain ':' and are refused too: proving a safe mapping
// back to IPv4 is D-017 work.
inline bool RemoteSecurityIdentityIsReliable(LPCTSTR pszClientAddress)
{
	return pszClientAddress == NULL || _tcschr(pszClientAddress, _T(':')) == NULL;
}

// BindAddress classification for fail-closed authorization.
// Invalid/oversized values must not fall through as "non-localhost" and
// reopen AllowLAN/WAN/CIDR for non-loopback clients.
enum class RemoteBindKind
{
	LocalhostOnly,
	NonLocalhost,
	Invalid
};

inline RemoteBindKind ClassifyRemoteBindAddress(LPCTSTR pszBindAddress)
{
	size_t nLen = 0;
	pszBindAddress = RemoteTrimBindAddressWhitespace(pszBindAddress, nLen);
	if (pszBindAddress == NULL || nLen == 0)
		return RemoteBindKind::LocalhostOnly;

	// Null-terminated trimmed copy so string helpers and IPv4 parsing agree
	// for values such as "127.0.0.1 " / "localhost\t".
	TCHAR szTrimmed[128];
	if (nLen >= _countof(szTrimmed))
		return RemoteBindKind::Invalid;
	memcpy(szTrimmed, pszBindAddress, nLen * sizeof(TCHAR));
	szTrimmed[nLen] = 0;
	pszBindAddress = szTrimmed;

	if (_tcsicmp(pszBindAddress, L"localhost") == 0)
		return RemoteBindKind::LocalhostOnly;
	if (_tcscmp(pszBindAddress, L"::1") == 0)
		return RemoteBindKind::LocalhostOnly;
	// Bind parser accepts IPv6 literals only (no [::1]:port); client helpers may
	// accept bracketed loopback with a port, but bind values must not.
	if (_tcsncmp(pszBindAddress, L"[::1]:", 6) == 0 && pszBindAddress[6] != 0)
		return RemoteBindKind::Invalid;

	// Colon-containing values must be complete IPv6 literals (optionally
	// bracketed, optionally with an embedded IPv4 tail). Dotted forms with a
	// port (e.g. 127.0.0.1:80) and junk suffixes (e.g. ::1junk) are Invalid so
	// AllowLAN/WAN cannot reopen. Valid non-loopback IPv6 is NonLocalhost.
	if (_tcschr(pszBindAddress, L':') != nullptr)
	{
		LPCTSTR psz = pszBindAddress;
		size_t nIpv6Len = nLen;
		if (nIpv6Len >= 2 && psz[0] == L'[' && psz[nIpv6Len - 1] == L']')
		{
			++psz;
			nIpv6Len -= 2;
		}
		unsigned short groups[8];
		if (!RemoteParseIpv6Literal(psz, nIpv6Len, groups))
			return RemoteBindKind::Invalid;
		return RemoteIpv6GroupsAreLoopback(groups) ? RemoteBindKind::LocalhostOnly
		                                           : RemoteBindKind::NonLocalhost;
	}

	// Dotted IPv4: once the value starts with a digit, treat syntax errors as
	// Invalid (fail closed) rather than NonLocalhost so AllowWAN/LAN cannot
	// reopen. BindAddress is an IP/policy value only: the sole accepted name
	// is "localhost" (handled above). Typos such as "locahost" or other
	// non-IP text are Invalid so AllowLAN/WAN/CIDR cannot reopen.
	// Bracketed forms are only valid for IPv6 literals, which always contain
	// ':' (handled above). A bracketed value here (e.g. "[127.0.0.1]") is
	// not a valid bind address: fail closed instead of treating it as a
	// hostname, so AllowLAN/WAN/CIDR cannot reopen through it.
	unsigned octets[4] = {};
	LPCTSTR psz = pszBindAddress;
	if (*psz == L'[')
		return RemoteBindKind::Invalid;
	if (*psz < L'0' || *psz > L'9')
		return RemoteBindKind::Invalid;

	for (int i = 0; i < 4; ++i)
	{
		if (*psz < L'0' || *psz > L'9')
			return RemoteBindKind::Invalid;
		unsigned value = 0;
		int nDigits = 0;
		while (*psz >= L'0' && *psz <= L'9')
		{
			const unsigned digit = static_cast<unsigned>(*psz - L'0');
			// Reject before multiply so oversized digit runs cannot wrap
			// unsigned and be misclassified as 127.x.x.x (e.g. 4294967423...).
			if (nDigits >= 3 || value > 25u || (value == 25u && digit > 5u))
				return RemoteBindKind::Invalid;
			value = value * 10u + digit;
			++nDigits;
			++psz;
		}
		if (nDigits == 0)
			return RemoteBindKind::Invalid;
		octets[i] = value;
		if (i < 3)
		{
			if (*psz != L'.')
				return RemoteBindKind::Invalid;
			++psz;
		}
	}
	if (*psz != 0)
		return RemoteBindKind::Invalid;
	return octets[0] == 127u ? RemoteBindKind::LocalhostOnly
	                         : RemoteBindKind::NonLocalhost;
}

inline bool RemoteBindAddressIsLocalhostOnly(LPCTSTR pszBindAddress)
{
	return ClassifyRemoteBindAddress(pszBindAddress) == RemoteBindKind::LocalhostOnly;
}

// Core policy with explicit inputs (unit-tested). Does not consult Settings.
inline bool RemoteAccessAllowedCore(
    const IN_ADDR& clientIP,
    LPCTSTR pszClientAddress,
    bool bAllowExternal,
    bool bAllowWAN,
    bool bAllowLAN,
    bool bHasCidrWhitelist,
    LPCTSTR pszBindAddress,
    bool bIsPrivateIP,
    bool bIsLocalSubnet,
    bool bIsInCidrList)
{
	if (RemoteClientIsLoopback(clientIP, pszClientAddress))
		return true;

	// IPv4 private/subnet/CIDR flags are meaningless for an IPv6 peer string
	// (AcceptFrom / InetNtop). Fail closed until D-017 adds IPv6-aware checks.
	bool bPrivate = bIsPrivateIP;
	bool bSubnet = bIsLocalSubnet;
	bool bInCidr = bIsInCidrList;
	if (pszClientAddress != NULL && _tcschr(pszClientAddress, L':') != NULL)
	{
		bPrivate = false;
		bSubnet = false;
		bInCidr = false;
	}

	// BindAddress is not applied to a socket (D-017). When it names localhost only,
	// non-loopback clients cannot use AllowLAN/WAN/CIDR unless AllowExternal is set.
	// Malformed/oversized bind values deny LAN/WAN/CIDR (fail closed), but the
	// explicit AllowExternal override still applies to them as documented.
	const RemoteBindKind bindKind = ClassifyRemoteBindAddress(pszBindAddress);
	if (!bAllowExternal)
	{
		if (bindKind == RemoteBindKind::Invalid || bindKind == RemoteBindKind::LocalhostOnly)
			return false;
	}

	if (bAllowExternal)
		return true;
	if (bAllowWAN)
		return true;
	if (bAllowLAN && (bPrivate || bSubnet))
		return true;
	if (bHasCidrWhitelist && bInCidr)
		return true;

	return false;
}
