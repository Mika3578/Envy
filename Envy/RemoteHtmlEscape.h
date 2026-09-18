//
// RemoteHtmlEscape.h
//
// HTML-entity escape for Remote UI substitution values (#76).
// Mirrors the XSS-relevant mapping in Strings.cpp Escape() for & < > " '
// so EnvyTests can cover the contract without linking MFC Strings.cpp.
// CRemote::Add() uses Escape() (same entities) at runtime.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <windows.h>
#include <cstring>
#include <string>

// Escape &, <, >, ", ' for HTML text/attribute contexts.
// Returns empty string when psz is null.
inline std::wstring RemoteHtmlEscape( const wchar_t* psz )
{
	if ( psz == nullptr )
		return std::wstring();

	std::wstring out;
	out.reserve( wcslen( psz ) );
	for ( const wchar_t* p = psz; *p; ++p )
	{
		switch ( *p )
		{
		case L'&':
			out += L"&amp;";
			break;
		case L'<':
			out += L"&lt;";
			break;
		case L'>':
			out += L"&gt;";
			break;
		case L'\"':
			out += L"&quot;";
			break;
		case L'\'':
			out += L"&apos;";
			break;
		default:
			out += *p;
			break;
		}
	}
	return out;
}

inline BOOL RemoteHtmlEscapeNeutralizesXssPayload( const wchar_t* pszPayload )
{
	if ( pszPayload == nullptr )
		return TRUE;
	const std::wstring escaped = RemoteHtmlEscape( pszPayload );
	// Raw markup must not survive; entity forms are expected.
	return ( escaped.find( L'<' ) == std::wstring::npos )
		&& ( escaped.find( L'>' ) == std::wstring::npos )
		&& ( escaped.find( L'\"' ) == std::wstring::npos )
		&& ( escaped.find( L'\'' ) == std::wstring::npos );
}
