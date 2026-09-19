//
// CrashDumpWin.h
//
// Crash-time minidump writer (#90). Uses system DbgHelp from System32.
// Initialize MiniDumpWriteDump at process start; the exception path only
// creates files and calls the cached function pointer.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include "CrashReportPolicy.h"

#include <dbghelp.h>

// Privacy-conscious dump type: stacks, unloaded modules, thread info, and
// memory indirectly referenced from stacks. Not a full-memory dump.
constexpr DWORD CRASH_REPORT_MINIDUMP_TYPE =
    MiniDumpNormal |
    MiniDumpWithUnloadedModules |
    MiniDumpWithIndirectlyReferencedMemory |
    MiniDumpWithThreadInfo;

typedef BOOL(WINAPI* CrashDumpMiniDumpWriteDumpFn)(
    HANDLE hProcess,
    DWORD ProcessId,
    HANDLE hFile,
    MINIDUMP_TYPE DumpType,
    CONST PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
    CONST PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
    CONST PMINIDUMP_CALLBACK_INFORMATION CallbackParam);

struct CrashDumpConfig
{
	wchar_t directory[MAX_PATH];
	wchar_t version[64];
	wchar_t revision[32];
	wchar_t buildType[16];
	wchar_t arch[8];
	wchar_t windowsVersion[32];
	BOOL continueSearch; // production: TRUE so WER still runs
};

namespace CrashDumpWin
{
inline CrashDumpConfig& Config()
{
	static CrashDumpConfig s_cfg = {};
	return s_cfg;
}

inline HMODULE& DbgHelp()
{
	static HMODULE s_mod = nullptr;
	return s_mod;
}

inline CrashDumpMiniDumpWriteDumpFn& WriteDumpFn()
{
	static CrashDumpMiniDumpWriteDumpFn s_fn = nullptr;
	return s_fn;
}

inline volatile LONG& DumpOnce()
{
	static volatile LONG s_once = 0;
	return s_once;
}

inline void CacheWindowsVersion()
{
	CrashDumpConfig& cfg = Config();
	cfg.windowsVersion[0] = 0;
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
	swprintf_s(cfg.windowsVersion, _countof(cfg.windowsVersion),
	           L"%u.%u.%u", vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
}

inline BOOL LoadSystemDbgHelp()
{
	if (WriteDumpFn() != nullptr)
		return TRUE;
	HMODULE h = LoadLibraryExW(L"dbghelp.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
	if (h == nullptr)
		return FALSE;
	DbgHelp() = h;
	FARPROC p = GetProcAddress(h, "MiniDumpWriteDump");
	if (p == nullptr)
		return FALSE;
	WriteDumpFn() = reinterpret_cast<CrashDumpMiniDumpWriteDumpFn>(p);
	return TRUE;
}

inline void ResetDumpOnce()
{
	DumpOnce() = 0;
}

inline BOOL Configure(const CrashDumpConfig* incoming)
{
	CrashDumpConfig& cfg = Config();
	if (incoming != nullptr)
		cfg = *incoming;
	if (cfg.directory[0] == 0)
		return FALSE;
	if (cfg.arch[0] == 0)
		CrashReportCopyTrunc(cfg.arch, _countof(cfg.arch), CrashReportArchitectureToken());
	if (cfg.windowsVersion[0] == 0)
		CacheWindowsVersion();
	LoadSystemDbgHelp();
	DumpOnce() = 0;
	return cfg.directory[0] != 0;
}

inline void SetIdentity(const wchar_t* version, const wchar_t* revision, const wchar_t* buildType)
{
	CrashDumpConfig& cfg = Config();
	CrashReportSanitizeField(version, cfg.version, _countof(cfg.version));
	CrashReportSanitizeField(revision, cfg.revision, _countof(cfg.revision));
	CrashReportSanitizeField(buildType, cfg.buildType, _countof(cfg.buildType));
}

inline void ModuleBaseNameFromAddress(void* address, wchar_t* dest, size_t cch)
{
	CrashReportZero(dest, cch);
	if (address == nullptr || dest == nullptr || cch == 0)
		return;
	HMODULE hMod = nullptr;
	if (!GetModuleHandleExW(
	        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
	        static_cast<LPCWSTR>(address), &hMod) ||
	    hMod == nullptr)
	{
		return;
	}
	wchar_t path[MAX_PATH];
	const DWORD n = GetModuleFileNameW(hMod, path, MAX_PATH);
	if (n == 0 || n >= MAX_PATH)
		return;
	const wchar_t* slash = path;
	for (DWORD i = 0; i < n; ++i)
	{
		if (path[i] == L'\\' || path[i] == L'/')
			slash = path + i + 1;
	}
	CrashReportSanitizeToken(slash, dest, cch);
}

inline void FillUtcNow(int& year, int& month, int& day, int& hour, int& minute, int& second)
{
	SYSTEMTIME st;
	GetSystemTime(&st);
	year = st.wYear;
	month = st.wMonth;
	day = st.wDay;
	hour = st.wHour;
	minute = st.wMinute;
	second = st.wSecond;
}

inline BOOL WriteMetadataFile(const wchar_t* path, const CrashReportMetadata* meta)
{
	if (path == nullptr || meta == nullptr)
		return FALSE;
	wchar_t text[CRASH_REPORT_METADATA_MAX];
	if (!CrashReportFormatMetadataText(meta, text, _countof(text)))
		return FALSE;
	const HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, nullptr,
	                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (h == INVALID_HANDLE_VALUE)
		return FALSE;
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

// Crash path: no MFC, no logging, no network. Best-effort dump + tiny metadata.
inline BOOL WriteFromException(EXCEPTION_POINTERS* pEx)
{
	if (InterlockedCompareExchange(&DumpOnce(), 1, 0) != 0)
		return FALSE;

	const CrashDumpConfig& cfg = Config();
	if (cfg.directory[0] == 0)
		return FALSE;

	CreateDirectoryW(cfg.directory, nullptr);

	int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
	FillUtcNow(year, month, day, hour, minute, second);
	wchar_t stamp[20];
	if (!CrashReportFormatUtcFileStamp(year, month, day, hour, minute, second, stamp, _countof(stamp)))
		CrashReportCopyTrunc(stamp, _countof(stamp), L"19700101T000000Z");

	const DWORD pid = GetCurrentProcessId();
	wchar_t base[CRASH_REPORT_NAME_MAX + 1];
	wchar_t dumpPath[MAX_PATH];
	wchar_t txtPath[MAX_PATH];
	HANDLE hDump = INVALID_HANDLE_VALUE;
	unsigned suffix = GetTickCount() & 0xFFFFu;
	for (size_t attempt = 0; attempt < CRASH_REPORT_SUFFIX_ATTEMPTS; ++attempt)
	{
		if (!CrashReportBuildBaseName(cfg.version[0] ? cfg.version : L"unknown",
		                              cfg.arch, stamp, pid, suffix + static_cast<unsigned>(attempt),
		                              base, _countof(base)))
		{
			continue;
		}
		wchar_t dumpName[CRASH_REPORT_NAME_MAX + 8];
		wchar_t txtName[CRASH_REPORT_NAME_MAX + 8];
		swprintf_s(dumpName, _countof(dumpName), L"%s.dmp", base);
		swprintf_s(txtName, _countof(txtName), L"%s.txt", base);
		if (!CrashReportJoinPath(cfg.directory, dumpName, dumpPath, _countof(dumpPath)))
			continue;
		if (!CrashReportJoinPath(cfg.directory, txtName, txtPath, _countof(txtPath)))
			continue;
		hDump = CreateFileW(dumpPath, GENERIC_WRITE, 0, nullptr,
		                    CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (hDump != INVALID_HANDLE_VALUE)
			break;
	}
	if (hDump == INVALID_HANDLE_VALUE)
		return FALSE;

	BOOL dumped = FALSE;
	if (WriteDumpFn() != nullptr)
	{
		MINIDUMP_EXCEPTION_INFORMATION info;
		ZeroMemory(&info, sizeof(info));
		info.ThreadId = GetCurrentThreadId();
		info.ExceptionPointers = pEx;
		info.ClientPointers = FALSE;
		dumped = WriteDumpFn()(
		    GetCurrentProcess(),
		    GetCurrentProcessId(),
		    hDump,
		    static_cast<MINIDUMP_TYPE>(CRASH_REPORT_MINIDUMP_TYPE),
		    pEx != nullptr ? &info : nullptr,
		    nullptr,
		    nullptr);
	}
	CloseHandle(hDump);
	if (!dumped)
		DeleteFileW(dumpPath);

	CrashReportMetadata meta;
	CrashReportMetadataClear(&meta);
	CrashReportCopyTrunc(meta.version, _countof(meta.version), cfg.version);
	CrashReportCopyTrunc(meta.revision, _countof(meta.revision), cfg.revision);
	CrashReportCopyTrunc(meta.buildType, _countof(meta.buildType), cfg.buildType);
	CrashReportCopyTrunc(meta.arch, _countof(meta.arch), cfg.arch);
	CrashReportCopyTrunc(meta.windowsVersion, _countof(meta.windowsVersion), cfg.windowsVersion);
	if (pEx != nullptr && pEx->ExceptionRecord != nullptr)
	{
		CrashReportFormatExceptionCode(pEx->ExceptionRecord->ExceptionCode,
		                               meta.exceptionCode, _countof(meta.exceptionCode));
		CrashReportFormatAddress(
		    reinterpret_cast<DWORD64>(pEx->ExceptionRecord->ExceptionAddress),
		    meta.exceptionAddress, _countof(meta.exceptionAddress));
		ModuleBaseNameFromAddress(pEx->ExceptionRecord->ExceptionAddress,
		                          meta.exceptionModule, _countof(meta.exceptionModule));
	}
	CrashReportFormatUtcIso(year, month, day, hour, minute, second,
	                        meta.crashUtc, _countof(meta.crashUtc));
	wchar_t dumpNameOnly[CRASH_REPORT_NAME_MAX + 8];
	swprintf_s(dumpNameOnly, _countof(dumpNameOnly), L"%s.dmp", base);
	CrashReportCopyTrunc(meta.dumpFile, _countof(meta.dumpFile), dumpNameOnly);
	CrashReportCopyTrunc(meta.symbolsNote, _countof(meta.symbolsNote),
	                     L"PDB not shipped in the installer");
	WriteMetadataFile(txtPath, &meta);
	return dumped;
}

inline LONG WINAPI UnhandledExceptionFilter(EXCEPTION_POINTERS* pEx)
{
	WriteFromException(pEx);
	return Config().continueSearch ? EXCEPTION_CONTINUE_SEARCH : EXCEPTION_EXECUTE_HANDLER;
}
}
