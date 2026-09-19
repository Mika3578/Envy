//
// DcFileListValidate.h
//
// Hostile NMDC FileListing (files.xml / files.xml.bz2) bounds. Used by
// CHostBrowser::LoadDC and EnvyTests. Invalid lists are rejected; entries
// are never silently coerced into a valid listing.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>

#include <string>
#include <vector>

// Must match CBUFFER_UNBZIP_MAX (PacketLengthValidate.h). EnvyTests assert equality.
constexpr DWORD DC_FILELIST_BYTES_MAX = 32u * 1024u * 1024u;

constexpr DWORD DC_FILELIST_DEPTH_MAX = 32u;
constexpr DWORD DC_FILELIST_ENTRIES_MAX = 100000u;
constexpr DWORD DC_FILELIST_NAME_MAX = 255u;
constexpr DWORD DC_FILELIST_PATH_MAX = 1024u;
constexpr DWORD DC_FILELIST_TTH_LEN = 39u;

enum DcFileListStatus
{
	dcFileListOk = 0,
	dcFileListEmpty,
	dcFileListMalformed,
	dcFileListTruncated,
	dcFileListTooDeep,
	dcFileListTooMany,
	dcFileListBadName,
	dcFileListBadSize,
	dcFileListBadTth,
	dcFileListTraversal,
	dcFileListTooLarge
};

inline BOOL DcFileListUncompressedOk(std::uint64_t nBytes)
{
	return nBytes > 0 && nBytes <= DC_FILELIST_BYTES_MAX;
}

inline BOOL DcFileListCompressedOk(std::uint64_t nBytes)
{
	return nBytes > 0 && nBytes <= DC_FILELIST_BYTES_MAX;
}

inline BOOL DcFileListDepthOk(DWORD nDepth)
{
	return nDepth <= DC_FILELIST_DEPTH_MAX;
}

inline BOOL DcFileListEntryCountOk(DWORD nEntries)
{
	return nEntries < DC_FILELIST_ENTRIES_MAX;
}

inline BOOL DcFileListJoinedPathOk(size_t nParent, size_t nName, BOOL bNeedSep)
{
	size_t n = nParent;
	if (bNeedSep && nParent > 0)
	{
		if (n == static_cast<size_t>(-1))
			return FALSE;
		++n;
	}
	if (nName > static_cast<size_t>(-1) - n)
		return FALSE;
	n += nName;
	return n > 0 && n <= DC_FILELIST_PATH_MAX;
}

// Hostile listings can prefix many PI/comment blocks; skip them iteratively.
constexpr DWORD DC_FILELIST_PROLOG_MAX = 64u;

inline BOOL DcFileListTthOk(const wchar_t* pszTth, size_t nLen)
{
	if (pszTth == NULL || nLen != DC_FILELIST_TTH_LEN)
		return FALSE;
	for (size_t i = 0; i < nLen; ++i)
	{
		const wchar_t c = pszTth[i];
		const BOOL bAlpha = (c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z');
		const BOOL bDigit = (c >= L'2' && c <= L'7');
		if (!bAlpha && !bDigit)
			return FALSE;
	}
	return TRUE;
}

inline BOOL DcFileListTthOk(const wchar_t* pszTth)
{
	if (pszTth == NULL)
		return FALSE;
	return DcFileListTthOk(pszTth, wcslen(pszTth));
}

inline BOOL DcFileListTthUtf8Ok(const char* pszTth, size_t nLen)
{
	if (pszTth == NULL || nLen != DC_FILELIST_TTH_LEN)
		return FALSE;
	for (size_t i = 0; i < nLen; ++i)
	{
		const unsigned char c = static_cast<unsigned char>(pszTth[i]);
		const BOOL bAlpha = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
		const BOOL bDigit = (c >= '2' && c <= '7');
		if (!bAlpha && !bDigit)
			return FALSE;
	}
	return TRUE;
}

inline BOOL DcFileListParseSize(const wchar_t* psz, std::uint64_t& nOut)
{
	nOut = 0;
	if (psz == NULL || *psz == 0)
		return FALSE;
	for (; *psz; ++psz)
	{
		if (*psz < L'0' || *psz > L'9')
			return FALSE;
		const std::uint64_t nDigit = static_cast<std::uint64_t>(*psz - L'0');
		if (nOut > (UINT64_MAX - nDigit) / 10ull)
			return FALSE;
		nOut = nOut * 10ull + nDigit;
	}
	return TRUE;
}

inline BOOL DcFileListParseSizeUtf8(const char* psz, size_t nLen, std::uint64_t& nOut)
{
	nOut = 0;
	if (psz == NULL || nLen == 0)
		return FALSE;
	for (size_t i = 0; i < nLen; ++i)
	{
		if (psz[i] < '0' || psz[i] > '9')
			return FALSE;
		const std::uint64_t nDigit = static_cast<std::uint64_t>(psz[i] - '0');
		if (nOut > (UINT64_MAX - nDigit) / 10ull)
			return FALSE;
		nOut = nOut * 10ull + nDigit;
	}
	return TRUE;
}

inline BOOL DcFileListNameCharsOk(const wchar_t* psz, size_t nLen)
{
	if (psz == NULL || nLen == 0 || nLen > DC_FILELIST_NAME_MAX)
		return FALSE;
	if (nLen == 1 && psz[0] == L'.')
		return FALSE;
	if (nLen == 2 && psz[0] == L'.' && psz[1] == L'.')
		return FALSE;
	for (size_t i = 0; i < nLen; ++i)
	{
		const wchar_t c = psz[i];
		if (c < 32 || c == 127 || c == L'/' || c == L'\\' || c == L':' || c == L'*' || c == L'?' || c == L'"' || c == L'<' || c == L'>' || c == L'|')
			return FALSE;
	}
	return TRUE;
}

inline BOOL DcFileListNameUtf8Ok(const char* psz, size_t nLen)
{
	if (psz == NULL || nLen == 0 || nLen > DC_FILELIST_NAME_MAX)
		return FALSE;
	if (nLen == 1 && psz[0] == '.')
		return FALSE;
	if (nLen == 2 && psz[0] == '.' && psz[1] == '.')
		return FALSE;
	for (size_t i = 0; i < nLen; ++i)
	{
		const unsigned char c = static_cast<unsigned char>(psz[i]);
		if (c < 32 || c == 127 || c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|')
			return FALSE;
	}
	return TRUE;
}

struct DcFileListEntry
{
	std::string sPath;
	std::string sName;
	std::uint64_t nSize;
	std::string sTth;
};

namespace DcFileListDetail
{

inline void SkipWs(const char*& p, const char* pEnd)
{
	while (p < pEnd && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n'))
		++p;
}

inline BOOL Consume(const char*& p, const char* pEnd, const char* psz)
{
	const size_t n = strlen(psz);
	if (p + n > pEnd || strncmp(p, psz, n) != 0)
		return FALSE;
	p += n;
	return TRUE;
}

inline BOOL MatchName(const char* p, const char* pEnd, const char* pszName)
{
	const size_t n = strlen(pszName);
	if (p + n > pEnd || strncmp(p, pszName, n) != 0)
		return FALSE;
	return (p + n == pEnd) || p[n] == ' ' || p[n] == '\t' || p[n] == '/' || p[n] == '>';
}

inline BOOL ParseAttrValue(const char*& p, const char* pEnd, const char*& pVal, size_t& nVal)
{
	SkipWs(p, pEnd);
	pVal = NULL;
	nVal = 0;
	if (p >= pEnd || *p != '=')
		return FALSE;
	++p;
	SkipWs(p, pEnd);
	if (p >= pEnd || *p != '"')
		return FALSE;
	++p;
	pVal = p;
	while (p < pEnd && *p != '"')
		++p;
	if (p >= pEnd)
		return FALSE;
	nVal = static_cast<size_t>(p - pVal);
	++p;
	return TRUE;
}

struct Attrs
{
	const char* pName;
	size_t nName;
	const char* pSize;
	size_t nSize;
	const char* pTth;
	size_t nTth;
	BOOL bSelfClose;
};

inline DcFileListStatus ParseOpenTag(const char*& p, const char* pEnd,
                                     const char*& pTag, size_t& nTag, Attrs& o)
{
	DWORD nProlog = 0;
	for (;;)
	{
		o = {};
		SkipWs(p, pEnd);
		if (p >= pEnd || *p != '<')
			return dcFileListMalformed;
		++p;
		if (p < pEnd && *p == '/')
			return dcFileListMalformed;
		if (p < pEnd && *p == '?')
		{
			if (++nProlog > DC_FILELIST_PROLOG_MAX)
				return dcFileListTooMany;
			while (p + 1 < pEnd && !(p[0] == '?' && p[1] == '>'))
				++p;
			if (p + 1 >= pEnd)
				return dcFileListTruncated;
			p += 2;
			continue;
		}
		if (p < pEnd && *p == '!')
		{
			if (++nProlog > DC_FILELIST_PROLOG_MAX)
				return dcFileListTooMany;
			while (p < pEnd && *p != '>')
				++p;
			if (p >= pEnd)
				return dcFileListTruncated;
			++p;
			continue;
		}
		break;
	}
	pTag = p;
	while (p < pEnd && *p != ' ' && *p != '\t' && *p != '>' && *p != '/')
		++p;
	nTag = static_cast<size_t>(p - pTag);
	if (nTag == 0)
		return dcFileListMalformed;
	while (p < pEnd && *p != '>')
	{
		SkipWs(p, pEnd);
		if (p < pEnd && *p == '/')
		{
			++p;
			SkipWs(p, pEnd);
			if (p >= pEnd || *p != '>')
				return dcFileListMalformed;
			o.bSelfClose = TRUE;
			++p;
			return dcFileListOk;
		}
		if (p < pEnd && *p == '>')
			break;
		const char* pAttr = p;
		while (p < pEnd && ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z')))
			++p;
		const size_t nAttr = static_cast<size_t>(p - pAttr);
		const char* pVal = NULL;
		size_t nVal = 0;
		if (!ParseAttrValue(p, pEnd, pVal, nVal))
		{
			if (p >= pEnd)
				return dcFileListTruncated;
			return dcFileListMalformed;
		}
		if (nAttr == 4 && strncmp(pAttr, "Name", 4) == 0)
		{
			o.pName = pVal;
			o.nName = nVal;
		}
		else if (nAttr == 4 && strncmp(pAttr, "Size", 4) == 0)
		{
			o.pSize = pVal;
			o.nSize = nVal;
		}
		else if (nAttr == 3 && strncmp(pAttr, "TTH", 3) == 0)
		{
			o.pTth = pVal;
			o.nTth = nVal;
		}
	}
	if (p >= pEnd || *p != '>')
		return dcFileListTruncated;
	++p;
	return dcFileListOk;
}

inline BOOL IsCloseTag(const char*& p, const char* pEnd, const char* pszName)
{
	SkipWs(p, pEnd);
	if (p + 2 >= pEnd || p[0] != '<' || p[1] != '/')
		return FALSE;
	const char* pSave = p;
	p += 2;
	const size_t n = strlen(pszName);
	if (p + n > pEnd || strncmp(p, pszName, n) != 0)
	{
		p = pSave;
		return FALSE;
	}
	p += n;
	SkipWs(p, pEnd);
	if (p >= pEnd || *p != '>')
	{
		p = pSave;
		return FALSE;
	}
	++p;
	return TRUE;
}

inline DcFileListStatus WalkDir(const char*& p, const char* pEnd,
                                std::vector<DcFileListEntry>& oOut, std::string& sPath, DWORD nDepth, DWORD& nEntries)
{
	if (!DcFileListDepthOk(nDepth))
		return dcFileListTooDeep;

	for (;;)
	{
		SkipWs(p, pEnd);
		if (p >= pEnd)
			return dcFileListTruncated;
		if (p[0] == '<' && p + 1 < pEnd && p[1] == '/')
			return dcFileListOk;

		const char* pTag = NULL;
		size_t nTag = 0;
		Attrs o = {};
		const DcFileListStatus nTagSt = ParseOpenTag(p, pEnd, pTag, nTag, o);
		if (nTagSt != dcFileListOk)
			return nTagSt;

		if (MatchName(pTag, pTag + nTag, "Directory"))
		{
			if (!DcFileListEntryCountOk(nEntries))
				return dcFileListTooMany;
			if (!DcFileListNameUtf8Ok(o.pName, o.nName))
				return (o.pName && o.nName == 2 && o.pName[0] == '.' && o.pName[1] == '.')
				           ? dcFileListTraversal
				           : dcFileListBadName;
			if (sPath.size() + o.nName + 1 > DC_FILELIST_PATH_MAX)
				return dcFileListBadName;
			const size_t nOld = sPath.size();
			if (!sPath.empty())
				sPath.push_back('\\');
			sPath.append(o.pName, o.nName);
			++nEntries;
			if (!o.bSelfClose)
			{
				const DcFileListStatus nChild = WalkDir(p, pEnd, oOut, sPath, nDepth + 1, nEntries);
				if (nChild != dcFileListOk)
					return nChild;
				if (!IsCloseTag(p, pEnd, "Directory"))
					return dcFileListTruncated;
			}
			sPath.resize(nOld);
		}
		else if (MatchName(pTag, pTag + nTag, "File"))
		{
			if (!DcFileListEntryCountOk(nEntries))
				return dcFileListTooMany;
			if (!DcFileListNameUtf8Ok(o.pName, o.nName))
				return (o.pName && o.nName == 2 && o.pName[0] == '.' && o.pName[1] == '.')
				           ? dcFileListTraversal
				           : dcFileListBadName;
			std::uint64_t nSize = 0;
			if (!DcFileListParseSizeUtf8(o.pSize, o.nSize, nSize))
				return dcFileListBadSize;
			if (!DcFileListTthUtf8Ok(o.pTth, o.nTth))
				return dcFileListBadTth;
			DcFileListEntry e;
			e.sPath = sPath;
			e.sName.assign(o.pName, o.nName);
			e.nSize = nSize;
			e.sTth.assign(o.pTth, o.nTth);
			oOut.push_back(e);
			++nEntries;
			if (!o.bSelfClose)
			{
				if (!IsCloseTag(p, pEnd, "File"))
					return dcFileListMalformed;
			}
		}
		else
			return dcFileListMalformed;
	}
}

} // namespace DcFileListDetail

inline DcFileListStatus DcParseFileListingXml(const char* pXml, size_t nLen,
                                              std::vector<DcFileListEntry>& oOut)
{
	oOut.clear();
	if (pXml == NULL || nLen == 0)
		return dcFileListEmpty;
	if (!DcFileListUncompressedOk(nLen))
		return dcFileListTooLarge;

	const char* p = pXml;
	const char* pEnd = pXml + nLen;
	if (nLen >= 3 && (unsigned char)p[0] == 0xEF && (unsigned char)p[1] == 0xBB && (unsigned char)p[2] == 0xBF)
		p += 3;
	DcFileListDetail::SkipWs(p, pEnd);
	if (p >= pEnd)
		return dcFileListEmpty;

	const char* pTag = NULL;
	size_t nTag = 0;
	DcFileListDetail::Attrs o = {};
	const DcFileListStatus nOpen = DcFileListDetail::ParseOpenTag(p, pEnd, pTag, nTag, o);
	if (nOpen != dcFileListOk)
		return nOpen;
	if (!DcFileListDetail::MatchName(pTag, pTag + nTag, "FileListing"))
		return dcFileListMalformed;
	if (o.bSelfClose)
		return dcFileListEmpty;

	std::string sPath;
	DWORD nEntries = 0;
	const DcFileListStatus nWalk = DcFileListDetail::WalkDir(p, pEnd, oOut, sPath, 1, nEntries);
	if (nWalk != dcFileListOk)
	{
		oOut.clear();
		return nWalk;
	}
	if (!DcFileListDetail::IsCloseTag(p, pEnd, "FileListing"))
	{
		oOut.clear();
		return dcFileListTruncated;
	}
	DcFileListDetail::SkipWs(p, pEnd);
	if (p != pEnd)
	{
		oOut.clear();
		return dcFileListMalformed;
	}
	return dcFileListOk;
}

// Display name "Folder\\file.ext" as used by CHostBrowser::LoadDCDirectory.
// nParent == 0 means the file sits on the FileListing root.
inline BOOL DcFileListSplitParentUtf8(const char* pszFull, size_t nLen,
                                      const char*& pParent, size_t& nParent,
                                      const char*& pFile, size_t& nFile)
{
	pParent = pszFull;
	nParent = 0;
	pFile = pszFull;
	nFile = nLen;
	if (pszFull == NULL || nLen == 0)
		return FALSE;
	size_t nSlash = nLen;
	for (size_t i = 0; i < nLen; ++i)
	{
		if (pszFull[i] == '\\')
			nSlash = i;
	}
	if (nSlash == nLen)
		return TRUE;
	nParent = nSlash;
	pFile = pszFull + nSlash + 1;
	nFile = nLen - nSlash - 1;
	return nFile > 0;
}
