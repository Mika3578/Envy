//
// DcHubUri.h
//
// Direct Connect hublist Address classification and parsing.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#pragma once

#include <string>

// Hublist rows are untrusted input: lengths are bounded and malformed
// forms fail closed. A URI scheme must never reach DNS as a hostname.
constexpr size_t DC_HUB_URI_MAX = 512;
constexpr size_t DC_HUB_HOST_MAX = 255;

enum class DcHubUriStatus : unsigned char
{
	PlainHost,   // No scheme: host[:port] stored as-is
	NmdcDchub,   // dchub://: supported legacy NMDC
	NmdcAlias,   // nmdc://: accepted as a plaintext NMDC alias
	NmdcSecure,  // nmdcs://: no TLS transport exists, reject
	Adc,         // adc://: ADC/ADCS stay outside the NMDC path
	Adcs,        // adcs://: ADC/ADCS stay outside the NMDC path
	Unsupported, // Another scheme: never resolve
	Malformed    // Missing host, bad port, bad labels, overlong, whitespace
};

// A host equal to a scheme name would feed the resolver the literal token
// when written without "//" (nmdcs:411 resolves "nmdcs"), so no supported
// authority may carry one.
inline bool DcHubUriIsSchemeToken(const std::wstring& strHost)
{
	if (strHost.size() < 3 || strHost.size() > 5) return false;
	std::wstring strLower(strHost);
	for (wchar_t& ch : strLower)
	{
		if (ch >= L'A' && ch <= L'Z') ch += L'a' - L'A';
	}
	return strLower == L"dchub" || strLower == L"nmdc" || strLower == L"nmdcs" ||
	       strLower == L"adc" || strLower == L"adcs";
}

// The DC path resolves IPv4 dotted literals (inet_addr gives octal meaning
// to leading zeros) and DNS names (async lookups of malformed labels waste
// retries), so both forms are validated strictly and nothing else passes.
inline bool DcHubUriIsValidHost(const std::wstring& strHost)
{
	bool bDotted = (strHost.find(L'.') != std::wstring::npos);
	bool bOnlyDigitsAndDots = bDotted;
	for (wchar_t ch : strHost)
	{
		if (ch == L'.' || (ch >= L'0' && ch <= L'9')) continue;
		bOnlyDigitsAndDots = false;
	}

	if (bOnlyDigitsAndDots)
	{
		// IPv4 literal: exactly four decimal octets without leading zeros.
		size_t nStart = 0;
		unsigned nOctets = 0;
		for (;;)
		{
			const size_t nEnd = strHost.find(L'.', nStart);
			const size_t nLen = (nEnd == std::wstring::npos)
			                        ? strHost.size() - nStart
			                        : nEnd - nStart;
			if (nLen == 0 || nLen > 3) return false;
			if (nLen > 1 && strHost[nStart] == L'0') return false;
			unsigned nOctet = 0;
			for (size_t i = 0; i < nLen; i++)
				nOctet = nOctet * 10u + unsigned(strHost[nStart + i] - L'0');
			if (nOctet > 255u) return false;
			nOctets++;
			if (nEnd == std::wstring::npos) break;
			nStart = nEnd + 1;
			if (nStart == strHost.size()) return false; // Trailing dot
		}
		return nOctets == 4u;
	}

	// DNS name: non-empty [A-Za-z0-9-] labels of at most 63 characters,
	// separated by single dots, without leading or trailing hyphens or dots.
	size_t nLabel = 0;
	wchar_t chPrev = 0;
	for (size_t i = 0;; i++)
	{
		const wchar_t ch = (i < strHost.size()) ? strHost[i] : L'.';
		if (ch == L'.')
		{
			if (nLabel == 0 || nLabel > 63) return false;
			if (chPrev == L'-') return false;
			if (i == strHost.size()) break; // No trailing dot
			nLabel = 0;
		}
		else
		{
			const bool bDigit = (ch >= L'0' && ch <= L'9');
			const bool bAlpha = (ch >= L'a' && ch <= L'z') || (ch >= L'A' && ch <= L'Z');
			if (!bDigit && !bAlpha && ch != L'-') return false;
			if (nLabel == 0 && ch == L'-') return false;
			nLabel++;
		}
		chPrev = ch;
	}
	return true;
}

// Classifies a hublist Address attribute and, for the supported plaintext
// forms, writes the host[:port] authority (scheme stripped, one trailing
// slash tolerated) into *pOutHostPort. nmdcs:// is rejected explicitly:
// secure NMDC must not fall back to plaintext and must not touch DNS.
inline DcHubUriStatus DcClassifyHubUri(const wchar_t* pszAddress, std::wstring* pOutHostPort)
{
	if (pOutHostPort) pOutHostPort->clear();
	if (!pszAddress) return DcHubUriStatus::Malformed;

	std::wstring str(pszAddress);
	if (str.size() > DC_HUB_URI_MAX) return DcHubUriStatus::Malformed;

	const wchar_t* pszSpace = L" \t\r\n";
	const size_t nFirst = str.find_first_not_of(pszSpace);
	if (nFirst == std::wstring::npos) return DcHubUriStatus::Malformed;
	const size_t nLast = str.find_last_not_of(pszSpace);
	str = str.substr(nFirst, nLast - nFirst + 1);

	std::wstring strRest;
	DcHubUriStatus nScheme = DcHubUriStatus::PlainHost;

	const size_t nSep = str.find(L"://");
	if (nSep != std::wstring::npos)
	{
		std::wstring strName = str.substr(0, nSep);
		for (wchar_t& ch : strName)
		{
			if (ch >= L'A' && ch <= L'Z') ch += L'a' - L'A';
		}
		strRest = str.substr(nSep + 3);

		// Longer schemes first: nmdcs:// and adcs:// prefix nmdc:// and adc://.
		if (strName == L"dchub") nScheme = DcHubUriStatus::NmdcDchub;
		else if (strName == L"nmdcs") nScheme = DcHubUriStatus::NmdcSecure;
		else if (strName == L"nmdc") nScheme = DcHubUriStatus::NmdcAlias;
		else if (strName == L"adcs") nScheme = DcHubUriStatus::Adcs;
		else if (strName == L"adc") nScheme = DcHubUriStatus::Adc;
		else nScheme = DcHubUriStatus::Unsupported;
	}
	else
		strRest = str;

	if (nScheme != DcHubUriStatus::PlainHost &&
	    nScheme != DcHubUriStatus::NmdcDchub &&
	    nScheme != DcHubUriStatus::NmdcAlias)
		return nScheme;

	// One trailing slash is tolerated; any further path, query or fragment
	// makes the authority unusable as a hub address.
	if (!strRest.empty() && strRest.back() == L'/') strRest.pop_back();
	if (strRest.empty()) return DcHubUriStatus::Malformed;
	if (strRest.find_first_of(L"/?#") != std::wstring::npos ||
	    strRest.find_first_of(pszSpace) != std::wstring::npos)
		return DcHubUriStatus::Malformed;

	// Bracketed IPv6 literals cannot be resolved by the IPv4-only DC path,
	// so they are rejected here instead of being stored unconnectable.
	if (strRest.front() == L'[') return DcHubUriStatus::Malformed;

	std::wstring strHost;
	std::wstring strPort;
	bool bHasPort = false;

	const size_t nColon = strRest.find(L':');
	if (nColon != std::wstring::npos)
	{
		strHost = strRest.substr(0, nColon);
		strPort = strRest.substr(nColon + 1);
		bHasPort = true;
		// Only one unbracketed colon is meaningful; anything else cannot
		// be split into host and port without guessing.
		if (strPort.find(L':') != std::wstring::npos)
			return DcHubUriStatus::Malformed;
	}
	else
		strHost = strRest;

	if (strHost.empty() || strHost.size() > DC_HUB_HOST_MAX)
		return DcHubUriStatus::Malformed;

	if (DcHubUriIsSchemeToken(strHost) || !DcHubUriIsValidHost(strHost))
		return DcHubUriStatus::Malformed;

	if (bHasPort)
	{
		// Leading zeros are rejected because the resolver reads the port
		// with %i and would parse 0411 as octal 265.
		if (strPort.empty() || strPort.size() > 5 ||
		    (strPort.size() > 1 && strPort[0] == L'0'))
			return DcHubUriStatus::Malformed;
		unsigned nPort = 0;
		for (wchar_t ch : strPort)
		{
			if (ch < L'0' || ch > L'9') return DcHubUriStatus::Malformed;
			nPort = nPort * 10u + unsigned(ch - L'0');
			if (nPort > 65535u) return DcHubUriStatus::Malformed;
		}
		if (nPort == 0u) return DcHubUriStatus::Malformed;
	}

	if (pOutHostPort) *pOutHostPort = strRest;
	return nScheme;
}
