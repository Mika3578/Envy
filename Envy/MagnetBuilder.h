//
// MagnetBuilder.h
//
// Magnet URI body composition for collection and export templates (#313).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <string>

// Composes the magnet URI for collection/export templates from a file's
// exact-topic hash strings. An empty string means the hash is absent.
//
// The branch order reproduces the historical template behavior: a bitprint
// supersedes a lone SHA-1 or Tiger topic, later hashes append. Separators
// are XML-escaped ("&amp;") because the templates embed the result in
// HTML/XML documents. Each exact topic is built from its own hash, never a
// different hash's bytes (BEP 9: xt=urn:btih carries the v1 info-hash).
inline std::wstring BuildMagnetQuery(
	const wchar_t* pszNameURI, const wchar_t* pszSize,
	const wchar_t* pszSHA1, const wchar_t* pszTiger,
	const wchar_t* pszED2K, const wchar_t* pszMD5, const wchar_t* pszBTH)
{
	std::wstring strMagnet;

	if ( pszSHA1 && *pszSHA1 )
		strMagnet = std::wstring( L"xt=urn:sha1:" ) + pszSHA1;

	if ( pszTiger && *pszTiger )
		strMagnet = std::wstring( L"xt=urn:tree:tiger/:" ) + pszTiger;

	if ( pszSHA1 && *pszSHA1 && pszTiger && *pszTiger )
		strMagnet = std::wstring( L"xt=urn:bitprint:" ) + pszSHA1 + L'.' + pszTiger;

	if ( pszED2K && *pszED2K )
	{
		if ( ! strMagnet.empty() ) strMagnet += L"&amp;";
		strMagnet += std::wstring( L"xt=urn:ed2khash:" ) + pszED2K;
	}

	if ( pszMD5 && *pszMD5 )
	{
		if ( ! strMagnet.empty() ) strMagnet += L"&amp;";
		strMagnet += std::wstring( L"xt=urn:md5:" ) + pszMD5;
	}

	if ( pszBTH && *pszBTH )
	{
		if ( ! strMagnet.empty() ) strMagnet += L"&amp;";
		strMagnet += std::wstring( L"xt=urn:btih:" ) + pszBTH;
	}

	if ( ! strMagnet.empty() )
		strMagnet += std::wstring( L"&amp;xl=" ) + ( pszSize ? pszSize : L"" );

	return std::wstring( L"magnet:?" ) + strMagnet + L"&amp;dn=" + ( pszNameURI ? pszNameURI : L"" );
}
