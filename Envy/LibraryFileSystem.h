// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <windows.h>
#include <string>

namespace EnvyFileSystem
{
inline std::wstring ApiPath(const std::wstring& path)
{
	if (path.size() < MAX_PATH - 4 || path.compare(0, 4, L"\\\\?\\") == 0)
		return path;

	if (path.compare(0, 2, L"\\\\") == 0)
		return L"\\\\?\\UNC" + path.substr(1);

	return L"\\\\?\\" + path;
}

inline bool EnumerationComplete(DWORD error)
{
	return error == ERROR_NO_MORE_FILES || error == ERROR_FILE_NOT_FOUND;
}
}
