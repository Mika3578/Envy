//
// DcBrowse.h
//
// NMDC file-list browse helpers: hub+nick identity, dchub:// URL, and
// files.xml.bz2 request naming. Shared by HostBrowser / downloads / tests.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include "DcNickList.h"

#include <string.h>
#include <wchar.h>

#include <string>

constexpr const char* DC_FILELIST_ADCGET_NAME = "files.xml.bz2";
constexpr const wchar_t* DC_FILELIST_ADCGET_NAME_W = L"files.xml.bz2";

// Display / library name for a remote file list: "Files of <nick>.xml.bz2"
inline BOOL DcIsFileListDownloadNameW(const wchar_t* pszName)
{
	if (pszName == NULL || *pszName == 0)
		return FALSE;
	if (wcscmp(pszName, DC_FILELIST_ADCGET_NAME_W) == 0 || wcscmp(pszName, L"files.xml") == 0)
		return TRUE;
	// "Files of " ... ".xml.bz2"
	const wchar_t* pszPrefix = L"Files of ";
	const wchar_t* pszSuffix = L".xml.bz2";
	const size_t nPrefix = 9;
	const size_t nSuffix = 8;
	const size_t nLen = wcslen(pszName);
	if (nLen <= nPrefix + nSuffix)
		return FALSE;
	if (wcsncmp(pszName, pszPrefix, nPrefix) != 0)
		return FALSE;
	return wcscmp(pszName + nLen - nSuffix, pszSuffix) == 0;
}

inline BOOL DcBrowsePortOk(unsigned nPort)
{
	return nPort > 0 && nPort <= 65535u;
}

inline BOOL DcBrowseHubIpOk(const char* pszIp)
{
	if (pszIp == NULL || *pszIp == 0)
		return FALSE;
	const size_t n = strlen(pszIp);
	if (n < 7 || n > 15)
		return FALSE;
	for (size_t i = 0; i < n; ++i)
	{
		const char c = pszIp[i];
		if ((c < '0' || c > '9') && c != '.')
			return FALSE;
	}
	return TRUE;
}

// Percent-encode a UTF-8 nick for the dchub:// userinfo (must encode '@').
inline void DcPercentEncodeUtf8(std::string& out, const char* p, size_t n)
{
	static const char szHex[] = "0123456789ABCDEF";
	static const char szUnsafe[] = "<>#%{}|/\\\"^~,[]+?&@=:$";
	for (size_t i = 0; i < n; ++i)
	{
		const unsigned char c = static_cast<unsigned char>(p[i]);
		if (c <= 32 || c >= 127 || strchr(szUnsafe, static_cast<char>(c)) != NULL)
		{
			out.push_back('%');
			out.push_back(szHex[c >> 4]);
			out.push_back(szHex[c & 15]);
		}
		else
			out.push_back(static_cast<char>(c));
	}
}

// dchub://<urlencoded-nick>@<ipv4>:<port>/files.xml.bz2
inline BOOL DcFormatFileListUrl(const char* pszNick, size_t nNick,
                                const char* pszHubIp, unsigned nPort, std::string& sUrl)
{
	sUrl.clear();
	if (!DcNickBytesOk(pszNick, nNick) || !DcBrowseHubIpOk(pszHubIp) || !DcBrowsePortOk(nPort))
		return FALSE;
	sUrl = "dchub://";
	DcPercentEncodeUtf8(sUrl, pszNick, nNick);
	sUrl.push_back('@');
	sUrl += pszHubIp;
	sUrl.push_back(':');
	sUrl += std::to_string(nPort);
	sUrl += "/";
	sUrl += DC_FILELIST_ADCGET_NAME;
	return TRUE;
}

inline BOOL DcFormatFileListUrl(const char* pszNick, const char* pszHubIp,
                                unsigned nPort, std::string& sUrl)
{
	if (pszNick == NULL)
		return FALSE;
	return DcFormatFileListUrl(pszNick, strlen(pszNick), pszHubIp, nPort, sUrl);
}

// Two hub+nick pairs are distinct even when the nick string matches.
inline BOOL DcBrowseTargetsEqual(const char* pszNickA, const char* pszHubA, unsigned nPortA,
                                 const char* pszNickB, const char* pszHubB, unsigned nPortB)
{
	std::string sA, sB;
	if (!DcFormatFileListUrl(pszNickA, pszHubA, nPortA, sA))
		return FALSE;
	if (!DcFormatFileListUrl(pszNickB, pszHubB, nPortB, sB))
		return FALSE;
	return sA == sB;
}
