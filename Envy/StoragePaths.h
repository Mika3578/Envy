// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <cwctype>
#include <string>

struct StoragePathDefaults
{
	std::wstring userData;
	std::wstring incomplete;
	std::wstring complete;
	std::wstring collections;
	std::wstring torrents;
};

inline std::wstring JoinStoragePath(const std::wstring& strParent, const wchar_t* pszChild)
{
	if (strParent.empty())
		return std::wstring();

	size_t nLength = strParent.length();
	while (nLength > 1 && (strParent[nLength - 1] == L'\\' || strParent[nLength - 1] == L'/') &&
	       !(nLength == 3 && strParent[1] == L':'))
		--nLength;

	std::wstring strPath = strParent.substr(0, nLength);
	if (strPath.empty() || (strPath.back() != L'\\' && strPath.back() != L'/'))
		strPath += L'\\';
	strPath += pszChild;
	return strPath;
}

inline StoragePathDefaults BuildStoragePathDefaults(
    const std::wstring& strRoamingAppData,
    const std::wstring& strLocalAppData,
    const std::wstring& strCompleteDownloadRoot)
{
	StoragePathDefaults paths = {};
	paths.userData = JoinStoragePath(strRoamingAppData, L"Envy");
	paths.incomplete = JoinStoragePath(JoinStoragePath(strLocalAppData, L"Envy"), L"Incomplete");
	paths.complete = strCompleteDownloadRoot;
	paths.collections = JoinStoragePath(strCompleteDownloadRoot, L"Collections");
	paths.torrents = JoinStoragePath(strCompleteDownloadRoot, L"Torrents");
	return paths;
}

inline StoragePathDefaults BuildPortableStoragePathDefaults(
    const std::wstring& strApplicationRoot,
    const std::wstring& strCompleteDownloadRoot)
{
	StoragePathDefaults paths = {};
	paths.userData = strApplicationRoot;
	paths.incomplete = JoinStoragePath(strApplicationRoot, L"Incomplete");
	paths.complete = strCompleteDownloadRoot;
	paths.collections = JoinStoragePath(strApplicationRoot, L"Collections");
	paths.torrents = JoinStoragePath(strCompleteDownloadRoot, L"Torrents");
	return paths;
}

inline bool IsPortableStorageMode(bool bUserInstallMatches, bool bMachineInstallMatches)
{
	return !bUserInstallMatches && !bMachineInstallMatches;
}

inline std::wstring ResolveStoragePath(
    const std::wstring& strConfigured,
    const std::wstring& strDefault,
    const std::wstring& strNonemptyLegacy = std::wstring())
{
	if (!strConfigured.empty())
		return strConfigured;
	return strNonemptyLegacy.empty() ? strDefault : strNonemptyLegacy;
}

inline bool StoragePathsEqual(const std::wstring& strLeft, const std::wstring& strRight)
{
	auto trimmedLength = [](const std::wstring& strPath)
	{
		size_t nLength = strPath.length();
		while (nLength > 3 && (strPath[nLength - 1] == L'\\' || strPath[nLength - 1] == L'/'))
			--nLength;
		return nLength;
	};

	const size_t nLength = trimmedLength(strLeft);
	if (nLength != trimmedLength(strRight))
		return false;
	for (size_t i = 0; i < nLength; ++i)
	{
		if (std::towlower(strLeft[i]) != std::towlower(strRight[i]))
			return false;
	}
	return true;
}

// Recovery offered when an essential mutable path is unusable at startup.
// Resetting to the default is only meaningful for a customised location.
enum class StorageRecovery
{
	RetryOrExit,
	RetryUseDefaultOrExit
};

inline StorageRecovery ChooseStorageRecovery(const std::wstring& strConfigured, const std::wstring& strDefault)
{
	return strDefault.empty() || StoragePathsEqual(strConfigured, strDefault) ? StorageRecovery::RetryOrExit : StorageRecovery::RetryUseDefaultOrExit;
}

inline bool StoragePathIsReparsePoint(unsigned long nAttributes)
{
	constexpr unsigned long StorageReparsePointAttribute = 0x400;
	constexpr unsigned long InvalidFileAttributes = 0xFFFFFFFF;
	return nAttributes != InvalidFileAttributes && (nAttributes & StorageReparsePointAttribute) != 0;
}
