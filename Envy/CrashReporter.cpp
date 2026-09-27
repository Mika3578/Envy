//
// CrashReporter.cpp
//
// Next-launch crash recovery UI (#90). Capture is Crashpad out-of-process.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//
#include "StdAfx.h"
#include "CrashReporter.h"
#include "CrashReportPolicy.h"
#ifdef _WIN64
#include "BugSplatHost.h"
#else
#include "CrashPadHost.h"
#endif

#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <knownfolders.h>
#include <exception>
#include <cstdlib>

namespace
{
BOOL ResolveCrashDirectory(wchar_t* dest, size_t cch)
{
	if (dest == nullptr || cch < 32)
		return FALSE;
	dest[0] = 0;

	wchar_t root[MAX_PATH];
	root[0] = 0;
	PWSTR known = nullptr;
	const HRESULT hr = SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_CREATE, nullptr, &known);
	if (SUCCEEDED(hr) && known != nullptr && known[0] != 0)
		CrashReportCopyTrunc(root, _countof(root), known);
	if (known != nullptr)
		CoTaskMemFree(known);
	if (root[0] == 0)
	{
		if (FAILED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA | CSIDL_FLAG_CREATE,
		                            nullptr, SHGFP_TYPE_CURRENT, root)))
		{
			root[0] = 0;
		}
	}
	if (root[0] == 0)
	{
		if (GetTempPathW(_countof(root), root) == 0)
			return FALSE;
	}

	wchar_t envyDir[MAX_PATH];
	if (!CrashReportJoinPath(root, CRASH_REPORTS_APP_DIR, envyDir, _countof(envyDir)))
		return FALSE;
	CreateDirectoryW(envyDir, nullptr);
	if (!CrashReportJoinPath(envyDir, CRASH_REPORTS_SUBDIR, dest, cch))
		return FALSE;
	CreateDirectoryW(dest, nullptr);
	return dest[0] != 0;
}

std::terminate_handler s_pPreviousTerminate = nullptr;
_invalid_parameter_handler s_pPreviousInvalid = nullptr;
_purecall_handler s_pPreviousPurecall = nullptr;
BOOL s_bInstalled = FALSE;
wchar_t s_directory[MAX_PATH];

void __cdecl OnTerminate()
{
#ifndef _WIN64
	CrashPadHost::DumpNow();
#endif
	abort();
}

void __cdecl OnInvalidParameter(
    const wchar_t* /*expression*/,
    const wchar_t* /*function*/,
    const wchar_t* /*file*/,
    unsigned int /*line*/,
    uintptr_t /*pReserved*/)
{
	// Do not copy CRT strings; they may contain user paths.
#ifndef _WIN64
	CrashPadHost::DumpNow();
#endif
	abort();
}

void __cdecl OnPureCall()
{
#ifndef _WIN64
	CrashPadHost::DumpNow();
#endif
	abort();
}

BOOL IsReparseFile(HANDLE hFile)
{
	BY_HANDLE_FILE_INFORMATION info;
	if (!GetFileInformationByHandle(hFile, &info))
		return TRUE;
	return (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

BOOL ReadMetadataFile(const wchar_t* pszPath, CrashReportMetadata* pMeta)
{
	CrashReportMetadataClear(pMeta);
	if (pszPath == nullptr)
		return FALSE;
	const HANDLE hFile = CreateFileW(pszPath, GENERIC_READ,
	                                 FILE_SHARE_READ, nullptr, OPEN_EXISTING,
	                                 FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;
	if (IsReparseFile(hFile))
	{
		CloseHandle(hFile);
		return FALSE;
	}
	LARGE_INTEGER size;
	if (!GetFileSizeEx(hFile, &size) || size.QuadPart <= 0 ||
	    size.QuadPart > static_cast<LONGLONG>(CRASH_REPORT_METADATA_MAX))
	{
		CloseHandle(hFile);
		return FALSE;
	}
	char utf8[CRASH_REPORT_METADATA_MAX + 1];
	DWORD nRead = 0;
	const BOOL bRead = ReadFile(hFile, utf8, static_cast<DWORD>(size.QuadPart), &nRead, nullptr);
	CloseHandle(hFile);
	if (!bRead || nRead == 0)
		return FALSE;
	utf8[nRead] = 0;

	wchar_t wide[CRASH_REPORT_METADATA_MAX + 1];
	int nWide = 0;
	if (nRead >= 2 && static_cast<unsigned char>(utf8[0]) == 0xFF &&
	    static_cast<unsigned char>(utf8[1]) == 0xFE)
	{
		nWide = static_cast<int>((nRead - 2) / sizeof(wchar_t));
		if (nWide > static_cast<int>(CRASH_REPORT_METADATA_MAX))
			nWide = static_cast<int>(CRASH_REPORT_METADATA_MAX);
		CopyMemory(wide, utf8 + 2, nWide * sizeof(wchar_t));
		wide[nWide] = 0;
	}
	else
	{
		nWide = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, nRead, wide,
		                            CRASH_REPORT_METADATA_MAX);
		if (nWide <= 0)
		{
			nWide = MultiByteToWideChar(CP_ACP, 0, utf8, nRead, wide,
			                            CRASH_REPORT_METADATA_MAX);
		}
		if (nWide <= 0)
			return FALSE;
		wide[nWide] = 0;
	}
	return CrashReportParseMetadataText(wide, static_cast<size_t>(nWide), pMeta);
}

BOOL CopyTextToClipboard(const wchar_t* pszText)
{
	if (pszText == nullptr)
		return FALSE;
	const size_t nChars = wcslen(pszText) + 1;
	if (nChars == 1 || nChars > CRASH_REPORT_METADATA_MAX)
		return FALSE;
	if (!OpenClipboard(nullptr))
		return FALSE;
	EmptyClipboard();
	HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, nChars * sizeof(wchar_t));
	if (hMem == nullptr)
	{
		CloseClipboard();
		return FALSE;
	}
	wchar_t* pszCopy = static_cast<wchar_t*>(GlobalLock(hMem));
	if (pszCopy == nullptr)
	{
		GlobalFree(hMem);
		CloseClipboard();
		return FALSE;
	}
	CrashReportCopyTrunc(pszCopy, nChars, pszText);
	GlobalUnlock(hMem);
	if (SetClipboardData(CF_UNICODETEXT, hMem) == nullptr)
	{
		GlobalFree(hMem);
		CloseClipboard();
		return FALSE;
	}
	CloseClipboard();
	return TRUE;
}

void OpenCrashFolder()
{
	const wchar_t* pszDir = s_directory;
	if (pszDir == nullptr || pszDir[0] == 0)
		return;
	ShellExecuteW(nullptr, L"open", pszDir, nullptr, nullptr, SW_SHOWNORMAL);
}

void OpenGitHubIssue(const CrashReportMetadata* pMeta)
{
	wchar_t szUrl[CRASH_REPORT_GITHUB_URL_MAX];
	if (!CrashReportBuildGitHubIssueUrl(
	        pMeta ? pMeta->version : L"unknown",
	        pMeta ? pMeta->arch : CrashReportArchitectureToken(),
	        pMeta ? pMeta->exceptionCode : L"unknown",
	        szUrl, _countof(szUrl)))
	{
		return;
	}
	if (!CrashReportIsTrustedGitHubNewIssueUrl(szUrl))
		return;
	ShellExecuteW(nullptr, L"open", szUrl, nullptr, nullptr, SW_SHOWNORMAL);
}

struct PendingReport
{
	wchar_t baseName[CRASH_REPORT_NAME_MAX + 1];
	wchar_t dumpName[CRASH_REPORT_NAME_MAX + 8];
	wchar_t txtName[CRASH_REPORT_NAME_MAX + 8];
	unsigned long long sizeBytes;
	unsigned long long mtimeUtc;
	BOOL hasDump;
	BOOL hasTxt;
	BOOL hasSeen;
	CrashReportMetadata meta;
};

// When the fixed scan buffer is full, keep the newest entries by mtime so
// retention/prune and the startup prompt still see recent reports.
PendingReport* AllocPendingSlot(PendingReport* pOut, size_t nMax, size_t* pnCount,
                                unsigned long long mtimeUtc)
{
	if (*pnCount < nMax)
	{
		PendingReport* pItem = &pOut[(*pnCount)++];
		ZeroMemory(pItem, sizeof(*pItem));
		return pItem;
	}
	size_t oldest = 0;
	for (size_t i = 1; i < nMax; ++i)
	{
		if (pOut[i].mtimeUtc < pOut[oldest].mtimeUtc)
			oldest = i;
	}
	if (mtimeUtc <= pOut[oldest].mtimeUtc)
		return nullptr;
	ZeroMemory(&pOut[oldest], sizeof(pOut[oldest]));
	return &pOut[oldest];
}

BOOL FindPendingReports(PendingReport* pOut, size_t nMax, size_t* pnCount)
{
	if (pnCount != nullptr)
		*pnCount = 0;
	if (pOut == nullptr || nMax == 0)
		return FALSE;

	const wchar_t* pszDir = s_directory;
	if (pszDir == nullptr || pszDir[0] == 0)
		return FALSE;

	wchar_t szPattern[MAX_PATH];
	if (wcslen(pszDir) + 3 >= MAX_PATH)
		return FALSE;
	wcscpy_s(szPattern, pszDir);
	wcscat_s(szPattern, L"\\*");

	WIN32_FIND_DATAW fd;
	const HANDLE hFind = FindFirstFileW(szPattern, &fd);
	if (hFind == INVALID_HANDLE_VALUE)
		return FALSE;

	size_t nCount = 0;
	do
	{
		if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
			continue;
		if (fd.cFileName[0] == L'.' &&
		    (fd.cFileName[1] == 0 || (fd.cFileName[1] == L'.' && fd.cFileName[2] == 0)))
			continue;

		if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			wchar_t szDump[MAX_PATH];
			if (!CrashReportJoinPath(pszDir, fd.cFileName, szDump, _countof(szDump)))
				continue;
			wchar_t szMini[MAX_PATH];
			if (!CrashReportJoinPath(szDump, L"minidump", szMini, _countof(szMini)))
				continue;
			WIN32_FILE_ATTRIBUTE_DATA attr;
			if (!GetFileAttributesExW(szMini, GetFileExInfoStandard, &attr))
				continue;
			if (attr.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				continue;
			ULARGE_INTEGER writeTime;
			writeTime.LowPart = attr.ftLastWriteTime.dwLowDateTime;
			writeTime.HighPart = attr.ftLastWriteTime.dwHighDateTime;
			PendingReport* pItem = AllocPendingSlot(pOut, nMax, &nCount, writeTime.QuadPart);
			if (pItem == nullptr)
				continue;
			CrashReportCopyTrunc(pItem->baseName, _countof(pItem->baseName), fd.cFileName);
			CrashReportCopyTrunc(pItem->dumpName, _countof(pItem->dumpName), fd.cFileName);
			pItem->hasDump = TRUE;
			pItem->mtimeUtc = writeTime.QuadPart;
			ULARGE_INTEGER fileSize;
			fileSize.LowPart = attr.nFileSizeLow;
			fileSize.HighPart = attr.nFileSizeHigh;
			pItem->sizeBytes = fileSize.QuadPart;
			wchar_t szSeenName[CRASH_REPORT_NAME_MAX + 8];
			if (swprintf_s(szSeenName, _countof(szSeenName), L"%s.seen", fd.cFileName) > 0 &&
			    CrashReportIsSafeFileName(szSeenName))
			{
				wchar_t szSeenPath[MAX_PATH];
				if (CrashReportJoinPath(pszDir, szSeenName, szSeenPath, _countof(szSeenPath)) &&
				    GetFileAttributesW(szSeenPath) != INVALID_FILE_ATTRIBUTES)
				{
					pItem->hasSeen = TRUE;
				}
			}
			continue;
		}

		if (!CrashReportIsSafeFileName(fd.cFileName))
			continue;
		if (_wcsicmp(fd.cFileName, L"identity.txt") == 0 ||
		    _wcsicmp(fd.cFileName, L"settings.dat") == 0)
			continue;

		const size_t nName = wcslen(fd.cFileName);
		const wchar_t* pszExt = nullptr;
		BOOL bDump = FALSE;
		BOOL bTxt = FALSE;
		BOOL bSeen = FALSE;
		if (nName > 4 && _wcsicmp(fd.cFileName + nName - 4, L".dmp") == 0)
		{
			bDump = TRUE;
			pszExt = fd.cFileName + nName - 4;
		}
		else if (nName > 4 && _wcsicmp(fd.cFileName + nName - 4, L".txt") == 0)
		{
			bTxt = TRUE;
			pszExt = fd.cFileName + nName - 4;
		}
		else if (nName > 5 && _wcsicmp(fd.cFileName + nName - 5, L".seen") == 0)
		{
			bSeen = TRUE;
			pszExt = fd.cFileName + nName - 5;
		}
		else
		{
			continue;
		}

		wchar_t szBase[CRASH_REPORT_NAME_MAX + 1];
		const size_t nBase = static_cast<size_t>(pszExt - fd.cFileName);
		if (nBase == 0 || nBase > CRASH_REPORT_NAME_MAX)
			continue;
		for (size_t i = 0; i < nBase; ++i)
			szBase[i] = fd.cFileName[i];
		szBase[nBase] = 0;
		if (!CrashReportIsSafeFileName(szBase))
			continue;

		PendingReport* pItem = nullptr;
		for (size_t i = 0; i < nCount; ++i)
		{
			if (_wcsicmp(pOut[i].baseName, szBase) == 0)
			{
				pItem = &pOut[i];
				break;
			}
		}
		ULARGE_INTEGER writeTime;
		writeTime.LowPart = fd.ftLastWriteTime.dwLowDateTime;
		writeTime.HighPart = fd.ftLastWriteTime.dwHighDateTime;
		if (pItem == nullptr)
		{
			pItem = AllocPendingSlot(pOut, nMax, &nCount, writeTime.QuadPart);
			if (pItem == nullptr)
				continue;
			CrashReportCopyTrunc(pItem->baseName, _countof(pItem->baseName), szBase);
		}

		if (writeTime.QuadPart > pItem->mtimeUtc)
			pItem->mtimeUtc = writeTime.QuadPart;

		ULARGE_INTEGER fileSize;
		fileSize.LowPart = fd.nFileSizeLow;
		fileSize.HighPart = fd.nFileSizeHigh;
		pItem->sizeBytes += fileSize.QuadPart;

		if (bDump)
		{
			pItem->hasDump = TRUE;
			CrashReportCopyTrunc(pItem->dumpName, _countof(pItem->dumpName), fd.cFileName);
		}
		if (bTxt)
		{
			pItem->hasTxt = TRUE;
			CrashReportCopyTrunc(pItem->txtName, _countof(pItem->txtName), fd.cFileName);
		}
		if (bSeen)
			pItem->hasSeen = TRUE;
	} while (FindNextFileW(hFind, &fd));
	FindClose(hFind);

	for (size_t i = 0; i < nCount; ++i)
	{
		if (pOut[i].hasTxt)
		{
			wchar_t szTxtPath[MAX_PATH];
			if (CrashReportJoinPath(pszDir, pOut[i].txtName, szTxtPath, _countof(szTxtPath)))
				ReadMetadataFile(szTxtPath, &pOut[i].meta);
		}
		else
		{
			wchar_t szIdentity[MAX_PATH];
			if (CrashReportJoinPath(pszDir, L"identity.txt", szIdentity, _countof(szIdentity)))
				ReadMetadataFile(szIdentity, &pOut[i].meta);
		}
		if (pOut[i].meta.dumpFile[0] == 0 && pOut[i].hasDump)
			CrashReportCopyTrunc(pOut[i].meta.dumpFile, _countof(pOut[i].meta.dumpFile), pOut[i].dumpName);
	}

	for (size_t i = 0; i + 1 < nCount; ++i)
	{
		size_t newest = i;
		for (size_t j = i + 1; j < nCount; ++j)
		{
			if (pOut[j].mtimeUtc > pOut[newest].mtimeUtc)
				newest = j;
		}
		if (newest != i)
		{
			PendingReport tmp = pOut[i];
			pOut[i] = pOut[newest];
			pOut[newest] = tmp;
		}
	}

	if (pnCount != nullptr)
		*pnCount = nCount;
	return nCount > 0;
}

void MarkSeen(const PendingReport* pItem)
{
	if (pItem == nullptr || pItem->baseName[0] == 0)
		return;
	wchar_t szSeenName[CRASH_REPORT_NAME_MAX + 8];
	swprintf_s(szSeenName, _countof(szSeenName), L"%s.seen", pItem->baseName);
	if (!CrashReportIsSafeFileName(szSeenName))
		return;
	wchar_t szPath[MAX_PATH];
	if (!CrashReportJoinPath(s_directory, szSeenName, szPath, _countof(szPath)))
		return;
	const HANDLE hFile = CreateFileW(szPath, GENERIC_WRITE, 0, nullptr,
	                                 CREATE_NEW,
	                                 FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
	                                 nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
		return;
	BY_HANDLE_FILE_INFORMATION info;
	if (!GetFileInformationByHandle(hFile, &info) ||
	    (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
	{
		CloseHandle(hFile);
		DeleteFileW(szPath);
		return;
	}
	CloseHandle(hFile);
}

void DeleteSafeTree(const wchar_t* pszDir, int depth)
{
	if (pszDir == nullptr || pszDir[0] == 0 || depth > 2)
		return;
	wchar_t szPattern[MAX_PATH];
	if (swprintf_s(szPattern, _countof(szPattern), L"%s\\*", pszDir) < 0)
		return;
	WIN32_FIND_DATAW fd;
	const HANDLE hFind = FindFirstFileW(szPattern, &fd);
	if (hFind == INVALID_HANDLE_VALUE)
		return;
	do
	{
		if (fd.cFileName[0] == L'.' &&
		    (fd.cFileName[1] == 0 || (fd.cFileName[1] == L'.' && fd.cFileName[2] == 0)))
			continue;
		if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
			continue;
		if (!CrashReportIsSafeFileName(fd.cFileName))
			continue;
		wchar_t szChild[MAX_PATH];
		if (!CrashReportJoinPath(pszDir, fd.cFileName, szChild, _countof(szChild)))
			continue;
		if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			DeleteSafeTree(szChild, depth + 1);
			RemoveDirectoryW(szChild);
		}
		else
		{
			DeleteFileW(szChild);
		}
	} while (FindNextFileW(hFind, &fd));
	FindClose(hFind);
}

void DeleteReportFiles(const wchar_t* pszBase)
{
	if (!CrashReportIsSafeFileName(pszBase))
		return;
	const wchar_t* pszDir = s_directory;
	const wchar_t* pszExts[] = { L".dmp", L".txt", L".seen" };
	for (size_t i = 0; i < 3; ++i)
	{
		wchar_t szName[CRASH_REPORT_NAME_MAX + 8];
		swprintf_s(szName, _countof(szName), L"%s%s", pszBase, pszExts[i]);
		if (!CrashReportIsSafeFileName(szName))
			continue;
		wchar_t szPath[MAX_PATH];
		if (!CrashReportJoinPath(pszDir, szName, szPath, _countof(szPath)))
			continue;
		DeleteFileW(szPath);
	}

	wchar_t szReportDir[MAX_PATH];
	if (!CrashReportJoinPath(pszDir, pszBase, szReportDir, _countof(szReportDir)))
		return;
	const DWORD attr = GetFileAttributesW(szReportDir);
	if (attr == INVALID_FILE_ATTRIBUTES)
		return;
	if (attr & FILE_ATTRIBUTE_REPARSE_POINT)
		return;
	if (attr & FILE_ATTRIBUTE_DIRECTORY)
	{
		DeleteSafeTree(szReportDir, 0);
		RemoveDirectoryW(szReportDir);
	}
}

void PruneOldReports(PendingReport* pItems, size_t nCount)
{
	if (pItems == nullptr || nCount == 0)
		return;
	CrashReportRetentionItem items[32];
	BOOL prune[32];
	const size_t nUse = nCount < 32 ? nCount : 32;
	for (size_t i = 0; i < nUse; ++i)
	{
		CrashReportCopyTrunc(items[i].baseName, _countof(items[i].baseName), pItems[i].baseName);
		items[i].sizeBytes = pItems[i].sizeBytes;
		items[i].mtimeUtc = pItems[i].mtimeUtc;
	}
	CrashReportSelectPrune(items, nUse, prune, CRASH_REPORT_KEEP_COUNT, CRASH_REPORT_KEEP_BYTES);
	for (size_t i = 0; i < nUse; ++i)
	{
		if (prune[i])
			DeleteReportFiles(pItems[i].baseName);
	}
}

enum
{
	CRASH_BTN_COPY = 1001,
	CRASH_BTN_FOLDER = 1002,
	CRASH_BTN_GITHUB = 1003
};

void ShowPendingDialog(PendingReport* pItem)
{
	wchar_t szBody[CRASH_REPORT_METADATA_MAX];
	CrashReportFormatMetadataText(&pItem->meta, szBody, _countof(szBody));

	wchar_t szInstruction[512];
	swprintf_s(szInstruction, _countof(szInstruction),
	           L"ENVY found a crash report from a previous run.\n\n"
	           L"Reports are stored locally in:\n%s\n\n"
	           L"Crashpad minidumps can contain fragments of process memory and are not anonymous. "
	           L"Nothing is uploaded. Attach the minidump only if you choose to share it.",
	           s_directory);

	TASKDIALOGCONFIG tdc;
	ZeroMemory(&tdc, sizeof(tdc));
	tdc.cbSize = sizeof(tdc);
	tdc.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_USE_COMMAND_LINKS | TDF_SIZE_TO_CONTENT;
	tdc.dwCommonButtons = TDCBF_CLOSE_BUTTON;
	tdc.pszWindowTitle = L"ENVY crash report";
	tdc.pszMainIcon = TD_WARNING_ICON;
	tdc.pszMainInstruction = L"ENVY recovered from a previous crash";
	tdc.pszContent = szInstruction;
	tdc.pszExpandedInformation = szBody;
	tdc.pszExpandedControlText = L"Hide report details";
	tdc.pszCollapsedControlText = L"Show report details";

	TASKDIALOG_BUTTON buttons[3];
	buttons[0].nButtonID = CRASH_BTN_COPY;
	buttons[0].pszButtonText = L"Copy sanitized report\nCopies text you can paste into a GitHub issue. The dump is not copied.";
	buttons[1].nButtonID = CRASH_BTN_FOLDER;
	buttons[1].pszButtonText = L"Open crash-report folder\nInspect or attach the Crashpad minidump yourself.";
	buttons[2].nButtonID = CRASH_BTN_GITHUB;
	buttons[2].pszButtonText = L"Open GitHub issue page\nOpens a blank issue with a short crash title. Paste the copied text. Do not put dumps in the URL.";
	tdc.cButtons = 3;
	tdc.pButtons = buttons;
	tdc.nDefaultButton = IDCLOSE;

	for (;;)
	{
		int nButton = 0;
		const HRESULT hr = TaskDialogIndirect(&tdc, &nButton, nullptr, nullptr);
		if (FAILED(hr))
		{
			CString str;
			str.Format(L"%s\n\n%s", szInstruction, szBody);
			MessageBoxW(nullptr, str, L"ENVY crash report", MB_OK | MB_ICONWARNING | MB_SETFOREGROUND);
			break;
		}
		if (nButton == CRASH_BTN_COPY)
		{
			CopyTextToClipboard(szBody);
			continue;
		}
		if (nButton == CRASH_BTN_FOLDER)
		{
			OpenCrashFolder();
			continue;
		}
		if (nButton == CRASH_BTN_GITHUB)
		{
			CopyTextToClipboard(szBody);
			OpenGitHubIssue(&pItem->meta);
			continue;
		}
		break;
	}
}
}

void CrashReporter::Initialize()
{
	s_directory[0] = 0;
	ResolveCrashDirectory(s_directory, _countof(s_directory));
#ifndef _WIN64
	CrashPadHost::Start(s_directory);
#endif

	if (s_bInstalled)
		return;

	// Win32: capture via Crashpad before abort. x64: same CRT hooks when BugSplat is
	// misconfigured so terminate/invalid-parameter/purecall still fail fast.
	s_pPreviousTerminate = set_terminate(&OnTerminate);
	s_pPreviousInvalid = _set_invalid_parameter_handler(&OnInvalidParameter);
	s_pPreviousPurecall = _set_purecall_handler(&OnPureCall);
	s_bInstalled = TRUE;
}

void CrashReporter::SetIdentity(const wchar_t* pszVersion, const wchar_t* pszRevision, const wchar_t* pszBuildType)
{
#ifdef _WIN64
	BugSplatHost::SetIdentity(pszVersion, pszRevision, pszBuildType);
#else
	CrashPadHost::SetIdentity(pszVersion, pszRevision, pszBuildType);
#endif
}

void CrashReporter::ShowStartupPromptIfNeeded()
{
	PendingReport reports[32];
	size_t nCount = 0;
	if (!FindPendingReports(reports, 32, &nCount) || nCount == 0)
		return;

#ifdef _WIN64
	// Legacy Crashpad dumps from pre-BugSplat x64 builds: prune only, no startup UI.
	FindPendingReports(reports, 32, &nCount);
	PruneOldReports(reports, nCount);
	return;
#else
	PendingReport* pNewestUnseen = nullptr;
	for (size_t i = 0; i < nCount; ++i)
	{
		if (!reports[i].hasSeen && (reports[i].hasDump || reports[i].hasTxt))
		{
			pNewestUnseen = &reports[i];
			break;
		}
	}
	if (pNewestUnseen != nullptr)
	{
		ShowPendingDialog(pNewestUnseen);
		MarkSeen(pNewestUnseen);
	}

	FindPendingReports(reports, 32, &nCount);
	PruneOldReports(reports, nCount);
#endif
}

void CrashReporter::Shutdown()
{
	if (!s_bInstalled)
		return;
#ifdef _WIN64
	BugSplatHost::Shutdown();
#endif
	if (s_pPreviousTerminate != nullptr)
		set_terminate(s_pPreviousTerminate);
	if (s_pPreviousInvalid != nullptr)
		_set_invalid_parameter_handler(s_pPreviousInvalid);
	if (s_pPreviousPurecall != nullptr)
		_set_purecall_handler(s_pPreviousPurecall);
	s_bInstalled = FALSE;
}

const wchar_t* CrashReporter::GetCrashDirectory()
{
	return s_directory;
}
