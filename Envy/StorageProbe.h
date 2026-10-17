// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <windows.h>
#include <shlobj.h>

#include <string>

enum class StorageProbeResult
{
	Ready,
	CreateFailed,
	NotDirectory,
	NotWritable
};

// Creates the directory if needed and proves that a file can be created in it.
// Attributes alone are not enough: an install-dir or redirected folder can exist
// and still deny FILE_ADD_FILE to the current user.
inline StorageProbeResult ProbeStorageDirectory(const std::wstring& strPath, DWORD* pnError = nullptr, DWORD* pnAttributes = nullptr)
{
	std::wstring strDirectory = strPath;
	while (strDirectory.length() > 3 && (strDirectory.back() == L'\\' || strDirectory.back() == L'/'))
		strDirectory.pop_back();

	DWORD nError = ERROR_SUCCESS;
	DWORD nAttributes = strDirectory.empty() ? INVALID_FILE_ATTRIBUTES : GetFileAttributesW(strDirectory.c_str());
	StorageProbeResult nResult = StorageProbeResult::Ready;

	if (strDirectory.empty())
	{
		nError = ERROR_PATH_NOT_FOUND;
		nResult = StorageProbeResult::CreateFailed;
	}
	else if (nAttributes == INVALID_FILE_ATTRIBUTES)
	{
		const int nCreateResult = SHCreateDirectoryExW(NULL, strDirectory.c_str(), NULL);
		if (nCreateResult != ERROR_SUCCESS && nCreateResult != ERROR_ALREADY_EXISTS)
		{
			nError = static_cast<DWORD>(nCreateResult);
			nResult = StorageProbeResult::CreateFailed;
		}
		else
		{
			nAttributes = GetFileAttributesW(strDirectory.c_str());
		}
	}

	if (nResult == StorageProbeResult::Ready &&
	    (nAttributes == INVALID_FILE_ATTRIBUTES || !(nAttributes & FILE_ATTRIBUTE_DIRECTORY)))
	{
		nError = nAttributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_DIRECTORY;
		nResult = StorageProbeResult::NotDirectory;
	}

	if (nResult == StorageProbeResult::Ready)
	{
		const std::wstring strProbePath = strDirectory + L"\\.envy-write-test-" +
		                                  std::to_wstring(GetCurrentProcessId()) + L"-" +
		                                  std::to_wstring(GetTickCount64()) + L".tmp";
		HANDLE hProbe = CreateFileW(strProbePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_NEW,
		                            FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
		if (hProbe == INVALID_HANDLE_VALUE)
		{
			nError = GetLastError();
			nResult = StorageProbeResult::NotWritable;
		}
		else
		{
			CloseHandle(hProbe);
		}
	}

	if (pnError)
		*pnError = nError;
	if (pnAttributes)
		*pnAttributes = nAttributes;
	return nResult;
}
