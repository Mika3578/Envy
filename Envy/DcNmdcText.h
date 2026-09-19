//
// DcNmdcText.h
//
// NMDC hub text encode/decode using an explicit Windows code page.
// Default 0 resolves to CP_ACP (system ANSI), matching DC++ blank hub encoding.
// ADC/ADCS is out of scope — never apply these helpers to ADC UTF-8 framing.
//
// Pure helpers (std::wstring / std::string) so EnvyTests can cover them without MFC.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <windows.h>

#include <cstring>
#include <string>

// 0 means "use the Windows ANSI code page" (DC++ default when hub encoding is blank).
inline UINT DcResolveNmdcCodePage(UINT nCodePage)
{
	return nCodePage == 0 ? static_cast<UINT>(CP_ACP) : nCodePage;
}

// Decode nInput bytes (not necessarily NUL-terminated) with the hub code page.
// nInput <= 0 or a null pointer yields an empty string. Does not scan past nInput.
inline std::wstring DecodeNmdcText(__in_bcount(nInput) LPCSTR psInput, __in int nInput, __in UINT nCodePage)
{
	std::wstring strWide;
	if (psInput == nullptr || nInput <= 0)
		return strWide;

	const UINT cp = DcResolveNmdcCodePage(nCodePage);
	int nWide = ::MultiByteToWideChar(cp, 0, psInput, nInput, nullptr, 0);
	if (nWide <= 0)
		return strWide;

	strWide.resize(static_cast<size_t>(nWide));
	nWide = ::MultiByteToWideChar(cp, 0, psInput, nInput, &strWide[0], nWide);
	if (nWide <= 0)
	{
		strWide.clear();
		return strWide;
	}
	strWide.resize(static_cast<size_t>(nWide));
	return strWide;
}

// Decode a NUL-terminated C string (legacy strchr-split NMDC fields).
inline std::wstring DecodeNmdcText(__in LPCSTR psInput, __in UINT nCodePage)
{
	if (psInput == nullptr || *psInput == 0)
		return std::wstring();
	return DecodeNmdcText(psInput, static_cast<int>(strlen(psInput)), nCodePage);
}

// Encode Unicode to the hub code page.
// Policy for characters that cannot be represented: substitute ASCII '?' (default char).
// WC_NO_BEST_FIT_CHARS is used for non-UTF-8 pages so we do not silently remap glyphs.
inline std::string EncodeNmdcText(__in LPCWSTR pszString, __in UINT nCodePage)
{
	std::string strBytes;
	if (pszString == nullptr || *pszString == 0)
		return strBytes;

	const UINT cp = DcResolveNmdcCodePage(nCodePage);
	const int nWide = static_cast<int>(wcslen(pszString));
	BOOL bUsedDefault = FALSE;
	// lpDefaultChar "?" — deterministic substitution when a glyph is missing in the code page.
	// (UTF-8 ignores lpDefaultChar; every Unicode scalar is representable.)
	const char* pszDefault = (cp == CP_UTF8) ? nullptr : "?";
	BOOL* pbUsed = (cp == CP_UTF8) ? nullptr : &bUsedDefault;

	int nByte = ::WideCharToMultiByte(cp, 0, pszString, nWide, nullptr, 0, pszDefault, pbUsed);
	if (nByte <= 0)
		return strBytes;

	strBytes.resize(static_cast<size_t>(nByte));
	nByte = ::WideCharToMultiByte(cp, 0, pszString, nWide, &strBytes[0], nByte, pszDefault, pbUsed);
	if (nByte <= 0)
	{
		strBytes.clear();
		return strBytes;
	}
	strBytes.resize(static_cast<size_t>(nByte));
	return strBytes;
}
