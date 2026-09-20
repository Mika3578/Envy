//
// CrashPadHost.cpp
//
// Crashpad client: local database, empty upload URL, uploads disabled.
// Crash-time snapshot work stays in crashpad_handler.exe.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "StdAfx.h"
#include "CrashPadHost.h"
#include "CrashReportPolicy.h"

#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

#include "client/crash_report_database.h"
#include "client/crashpad_client.h"
#include "client/settings.h"

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace
{
crashpad::CrashpadClient s_client;
BOOL s_bStarted = FALSE;
wchar_t s_handlerPath[MAX_PATH];
wchar_t s_database[MAX_PATH];

void ProbeDirectory(wchar_t* dest, size_t cch)
{
	CrashReportZero(dest, cch);
	wchar_t path[MAX_PATH];
	const DWORD n = GetModuleFileNameW(nullptr, path, MAX_PATH);
	if (n == 0 || n >= MAX_PATH)
		return;
	wchar_t* slash = wcsrchr(path, L'\\');
	if (slash != nullptr)
		*slash = 0;
	CrashReportCopyTrunc(dest, cch, path);
}

void CacheWindowsVersion(wchar_t* dest, size_t cch)
{
	CrashReportZero(dest, cch);
	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (hNtdll == nullptr)
		return;
	typedef LONG(WINAPI * RtlGetVersionFn)(OSVERSIONINFOW*);
	RtlGetVersionFn pRtlGetVersion =
	    reinterpret_cast<RtlGetVersionFn>(GetProcAddress(hNtdll, "RtlGetVersion"));
	if (pRtlGetVersion == nullptr)
		return;
	OSVERSIONINFOW vi;
	ZeroMemory(&vi, sizeof(vi));
	vi.dwOSVersionInfoSize = sizeof(vi);
	if (pRtlGetVersion(&vi) != 0)
		return;
	swprintf_s(dest, cch, L"%u.%u.%u", vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
}

BOOL IsReparseHandle(HANDLE hFile)
{
	BY_HANDLE_FILE_INFORMATION info;
	if (!GetFileInformationByHandle(hFile, &info))
		return TRUE;
	return (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

BOOL WriteUtf8FileReplace(const wchar_t* path, const wchar_t* text)
{
	if (path == nullptr || text == nullptr)
		return FALSE;
	const HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
	                             FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
	if (h == INVALID_HANDLE_VALUE)
		return FALSE;
	if (IsReparseHandle(h))
	{
		CloseHandle(h);
		return FALSE;
	}
	char utf8[CRASH_REPORT_METADATA_MAX];
	const int nUtf8 = WideCharToMultiByte(CP_UTF8, 0, text, -1, utf8, sizeof(utf8), nullptr, nullptr);
	BOOL ok = FALSE;
	if (nUtf8 > 1)
	{
		DWORD written = 0;
		ok = WriteFile(h, utf8, static_cast<DWORD>(nUtf8 - 1), &written, nullptr);
	}
	CloseHandle(h);
	return ok;
}
}

BOOL CrashPadHost::Start(const wchar_t* pszDatabaseDirectory)
{
	// CrashpadClient allows StartHandler once; a second call DCHECK-fatals in Debug.
	if (s_bStarted)
		return TRUE;

	s_handlerPath[0] = 0;
	s_database[0] = 0;
	if (pszDatabaseDirectory == nullptr || pszDatabaseDirectory[0] == 0)
		return FALSE;

	wchar_t exeDir[MAX_PATH];
	ProbeDirectory(exeDir, _countof(exeDir));
	if (!CrashReportJoinPath(exeDir, L"crashpad_handler.exe", s_handlerPath, _countof(s_handlerPath)))
		return FALSE;
	if (GetFileAttributesW(s_handlerPath) == INVALID_FILE_ATTRIBUTES)
		return FALSE;

	CrashReportCopyTrunc(s_database, _countof(s_database), pszDatabaseDirectory);
	CreateDirectoryW(s_database, nullptr);

	base::FilePath db(s_database);
	base::FilePath handler(s_handlerPath);
	std::unique_ptr<crashpad::CrashReportDatabase> reports =
	    crashpad::CrashReportDatabase::Initialize(db);
	if (!reports)
		return FALSE;
	if (!reports->GetSettings()->SetUploadsEnabled(false))
		return FALSE;

	std::map<std::string, std::string> annotations;
	annotations["product"] = "Envy";
	annotations["upload"] = "off";
	std::vector<std::string> arguments;
	const std::string emptyUrl;
	if (!s_client.StartHandler(handler, db, db, emptyUrl, annotations, arguments, true, false))
		return FALSE;

	s_bStarted = TRUE;
	return TRUE;
}

void CrashPadHost::SetIdentity(const wchar_t* pszVersion, const wchar_t* pszRevision, const wchar_t* pszBuildType)
{
	if (s_database[0] == 0)
		return;

	wchar_t version[64];
	wchar_t revision[32];
	wchar_t buildType[16];
	wchar_t windowsVersion[32];
	CrashReportSanitizeField(pszVersion, version, _countof(version));
	CrashReportSanitizeField(pszRevision, revision, _countof(revision));
	CrashReportSanitizeField(pszBuildType, buildType, _countof(buildType));
	CacheWindowsVersion(windowsVersion, _countof(windowsVersion));

	wchar_t identityPath[MAX_PATH];
	if (!CrashReportJoinPath(s_database, L"identity.txt", identityPath, _countof(identityPath)))
		return;

	CrashReportMetadata meta;
	CrashReportMetadataClear(&meta);
	CrashReportCopyTrunc(meta.version, _countof(meta.version), version);
	CrashReportCopyTrunc(meta.revision, _countof(meta.revision), revision);
	CrashReportCopyTrunc(meta.buildType, _countof(meta.buildType), buildType);
	CrashReportCopyTrunc(meta.arch, _countof(meta.arch), CrashReportArchitectureToken());
	CrashReportCopyTrunc(meta.windowsVersion, _countof(meta.windowsVersion), windowsVersion);
	CrashReportCopyTrunc(meta.symbolsNote, _countof(meta.symbolsNote),
	                     L"PDB not shipped in the installer");

	wchar_t text[CRASH_REPORT_METADATA_MAX];
	if (!CrashReportFormatMetadataText(&meta, text, _countof(text)))
		return;
	WriteUtf8FileReplace(identityPath, text);
}

void CrashPadHost::DumpNow()
{
	if (!s_bStarted)
		return;
	CONTEXT ctx;
	ZeroMemory(&ctx, sizeof(ctx));
	RtlCaptureContext(&ctx);
	s_client.DumpWithoutCrash(ctx);
}

BOOL CrashPadHost::HandlerStarted()
{
	return s_bStarted;
}

const wchar_t* CrashPadHost::HandlerPath()
{
	return s_handlerPath;
}
