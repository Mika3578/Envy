//
// test_crash_report_policy_smoke.cpp
//
// Crash-report naming, privacy, metadata, retention, and dump-failure
// helpers for #90. The live child-process dump smoke is Windows-only and
// must not crash this process.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/CrashReportPolicy.h"
#include "../Envy/CrashDumpWin.h"

#include <string>
#include <windows.h>

static bool streq(const wchar_t* a, const wchar_t* b)
{
	return a != nullptr && b != nullptr && wcscmp(a, b) == 0;
}

static bool test_normal_report_name()
{
	wchar_t name[CRASH_REPORT_NAME_MAX + 1];
	if (!CrashReportBuildBaseName(L"4.2.0", L"x64", L"20260919T182600Z", 1234, 0xA1B2, name, _countof(name)))
		return false;
	return streq(name, L"Envy-4.2.0-x64-20260919T182600Z-p1234-a1b2");
}

static bool test_win32_arch_name()
{
	wchar_t name[CRASH_REPORT_NAME_MAX + 1];
	if (!CrashReportBuildBaseName(L"4.2.0", L"Win32", L"20260919T182600Z", 9, 1, name, _countof(name)))
		return false;
	return wcsstr(name, L"-Win32-") != nullptr && CrashReportIsSafeFileName(name);
}

static bool test_long_version_truncated()
{
	wchar_t name[CRASH_REPORT_NAME_MAX + 1];
	const wchar_t* longVer =
	    L"4.2.0-preview.1-this-is-an-unreasonably-long-version-string-that-must-not-break-the-filename";
	if (!CrashReportBuildBaseName(longVer, L"x64", L"20260919T182600Z", 1, 2, name, _countof(name)))
		return false;
	return CrashReportIsSafeFileName(name) && wcslen(name) <= CRASH_REPORT_NAME_MAX;
}

static bool test_timestamp_format()
{
	wchar_t stamp[20];
	if (!CrashReportFormatUtcFileStamp(2026, 9, 19, 18, 26, 0, stamp, _countof(stamp)))
		return false;
	if (!streq(stamp, L"20260919T182600Z"))
		return false;
	if (CrashReportFormatUtcFileStamp(1969, 1, 1, 0, 0, 0, stamp, _countof(stamp)))
		return false;
	if (CrashReportFormatUtcFileStamp(2026, 13, 1, 0, 0, 0, stamp, _countof(stamp)))
		return false;
	wchar_t iso[32];
	if (!CrashReportFormatUtcIso(2026, 9, 19, 18, 26, 0, iso, _countof(iso)))
		return false;
	return streq(iso, L"2026-09-19T18:26:00Z");
}

static bool test_invalid_destination()
{
	wchar_t path[MAX_PATH];
	if (CrashReportJoinPath(nullptr, L"Envy-x.dmp", path, _countof(path)))
		return false;
	if (CrashReportJoinPath(L"", L"Envy-x.dmp", path, _countof(path)))
		return false;
	if (CrashReportJoinPath(L"C:\\EnvyCrashUnit", L"..\\evil.dmp", path, _countof(path)))
		return false;
	if (CrashReportJoinPath(L"C:\\EnvyCrashUnit", L"sub\\file.dmp", path, _countof(path)))
		return false;
	if (CrashReportJoinPath(L"C:\\EnvyCrashUnit", L"file.dmp.", path, _countof(path)))
		return false;
	if (!CrashReportJoinPath(L"C:\\EnvyCrashUnit", L"Envy-ok.dmp", path, _countof(path)))
		return false;
	return wcsstr(path, L"Envy-ok.dmp") != nullptr;
}

static bool test_filename_collision_suffix()
{
	wchar_t a[CRASH_REPORT_NAME_MAX + 1];
	wchar_t b[CRASH_REPORT_NAME_MAX + 1];
	if (!CrashReportBuildBaseName(L"4.2.0", L"x64", L"20260919T182600Z", 7, 1, a, _countof(a)))
		return false;
	if (!CrashReportBuildBaseName(L"4.2.0", L"x64", L"20260919T182600Z", 7, 2, b, _countof(b)))
		return false;
	return wcscmp(a, b) != 0;
}

static bool test_metadata_normal_and_empty()
{
	CrashReportMetadata meta;
	CrashReportMetadataClear(&meta);
	CrashReportCopyTrunc(meta.version, _countof(meta.version), L"4.2.0");
	CrashReportCopyTrunc(meta.arch, _countof(meta.arch), L"x64");
	CrashReportCopyTrunc(meta.exceptionCode, _countof(meta.exceptionCode), L"0xC0000005");
	CrashReportCopyTrunc(meta.dumpFile, _countof(meta.dumpFile), L"Envy-4.2.0-x64-20260919T182600Z-p1-0001.dmp");
	wchar_t text[CRASH_REPORT_METADATA_MAX];
	if (!CrashReportFormatMetadataText(&meta, text, _countof(text)))
		return false;
	if (wcsstr(text, L"envy_version=4.2.0") == nullptr)
		return false;
	if (wcsstr(text, L"HKEY_CURRENT_USER") != nullptr)
		return false;
	if (wcsstr(text, L"log_tail=omitted") == nullptr)
		return false;

	CrashReportMetadata parsed;
	if (!CrashReportParseMetadataText(text, wcslen(text), &parsed))
		return false;
	if (!streq(parsed.version, L"4.2.0"))
		return false;
	if (!streq(parsed.dumpFile, meta.dumpFile))
		return false;

	CrashReportMetadata empty;
	CrashReportMetadataClear(&empty);
	if (!CrashReportFormatMetadataText(&empty, text, _countof(text)))
		return false;
	return wcsstr(text, L"envy_crash_report=1") != nullptr;
}

static bool test_metadata_rejects_paths_and_registry()
{
	CrashReportMetadata meta;
	CrashReportMetadataClear(&meta);
	CrashReportCopyTrunc(meta.exceptionModule, _countof(meta.exceptionModule), L"C:\\Users\\alice\\Envy.exe");
	CrashReportCopyTrunc(meta.dumpFile, _countof(meta.dumpFile), L"..\\..\\Secrets.dmp");
	wchar_t text[CRASH_REPORT_METADATA_MAX];
	if (!CrashReportFormatMetadataText(&meta, text, _countof(text)))
		return false;
	if (wcsstr(text, L"C:\\Users") != nullptr)
		return false;
	if (wcsstr(text, L"..\\") != nullptr)
		return false;

	const wchar_t* crafted =
	    L"envy_crash_report=1\r\n"
	    L"dump_file=..\\evil.dmp\r\n"
	    L"exception_module=C:\\Users\\bob\\file.dll\r\n";
	CrashReportMetadata parsed;
	CrashReportParseMetadataText(crafted, wcslen(crafted), &parsed);
	if (parsed.dumpFile[0] != 0)
		return false;
	if (parsed.exceptionModule[0] != 0)
		return false;

	CrashReportMetadata emptyParse;
	if (CrashReportParseMetadataText(L"", 0, &emptyParse))
		return false;
	const wchar_t* malformed =
	    L"garbage\r\n"
	    L"dump_file=not/a\\safe name.dmp\r\n"
	    L"exception_code=0xC0000005\r\n";
	CrashReportMetadata malformedParsed;
	CrashReportParseMetadataText(malformed, wcslen(malformed), &malformedParsed);
	if (malformedParsed.dumpFile[0] != 0)
		return false;
	if (!streq(malformedParsed.exceptionCode, L"0xC0000005"))
		return false;
	return true;
}

static bool test_privacy_credentials_and_ips()
{
	if (!CrashReportLooksLikeCredentialUrl(L"https://alice:s3cret@tracker.example/announce"))
		return false;
	if (!CrashReportLooksPrivate(L"udp://alice:s3cret@203.0.113.50:6969/announce"))
		return false;
	if (!CrashReportLooksPrivate(L"passkey=abcdef"))
		return false;
	if (!CrashReportLooksPrivate(L"peer 203.0.113.50:6881"))
		return false;
	if (!CrashReportLooksPrivate(L"C:\\Users\\eve\\Downloads\\secret.mkv"))
		return false;
	if (CrashReportLooksPrivate(L"0xC0000005 in Envy.exe"))
		return false;
	if (CrashReportLooksPrivate(L"4.2.0 Release x64"))
		return false;
	return true;
}

static bool test_github_url_is_trusted_and_small()
{
	wchar_t url[CRASH_REPORT_GITHUB_URL_MAX];
	if (!CrashReportBuildGitHubIssueUrl(L"4.2.0", L"x64", L"0xC0000005", url, _countof(url)))
		return false;
	if (!CrashReportIsTrustedGitHubNewIssueUrl(url))
		return false;
	if (wcsstr(url, L"https://github.com/Mika3578/Envy/issues/new?title=") != url)
		return false;
	if (wcsstr(url, L".dmp") != nullptr)
		return false;
	if (CrashReportIsTrustedGitHubNewIssueUrl(L"https://evil.example/issues/new"))
		return false;
	if (CrashReportIsTrustedGitHubNewIssueUrl(L"javascript:alert(1)"))
		return false;
	return wcslen(url) < CRASH_REPORT_GITHUB_URL_MAX;
}

static bool test_retention_keeps_newest()
{
	CrashReportRetentionItem items[4];
	ZeroMemory(items, sizeof(items));
	CrashReportCopyTrunc(items[0].baseName, _countof(items[0].baseName), L"newest");
	items[0].sizeBytes = 10;
	items[0].mtimeUtc = 400;
	CrashReportCopyTrunc(items[1].baseName, _countof(items[1].baseName), L"old-a");
	items[1].sizeBytes = 10;
	items[1].mtimeUtc = 300;
	CrashReportCopyTrunc(items[2].baseName, _countof(items[2].baseName), L"old-b");
	items[2].sizeBytes = 10;
	items[2].mtimeUtc = 200;
	CrashReportCopyTrunc(items[3].baseName, _countof(items[3].baseName), L"old-c");
	items[3].sizeBytes = 10;
	items[3].mtimeUtc = 100;
	BOOL prune[4] = {};
	CrashReportSelectPrune(items, 4, prune, 2, 1000);
	if (prune[0])
		return false;
	if (!prune[2] || !prune[3])
		return false;
	return true;
}

static bool test_retention_never_prunes_newest_over_size()
{
	CrashReportRetentionItem items[2];
	ZeroMemory(items, sizeof(items));
	CrashReportCopyTrunc(items[0].baseName, _countof(items[0].baseName), L"newest");
	items[0].sizeBytes = 60ull * 1024ull * 1024ull;
	items[0].mtimeUtc = 2;
	CrashReportCopyTrunc(items[1].baseName, _countof(items[1].baseName), L"older");
	items[1].sizeBytes = 10;
	items[1].mtimeUtc = 1;
	BOOL prune[2] = {};
	CrashReportSelectPrune(items, 2, prune, CRASH_REPORT_KEEP_COUNT, CRASH_REPORT_KEEP_BYTES);
	if (prune[0])
		return false;
	return prune[1] == TRUE;
}

static bool test_metadata_dump_or_txt_only()
{
	const wchar_t* dumpOnly =
	    L"envy_crash_report=1\r\n"
	    L"dump_file=Envy-4.2.0-x64-20260919T182600Z-p1-0001.dmp\r\n";
	CrashReportMetadata parsedDump;
	if (!CrashReportParseMetadataText(dumpOnly, wcslen(dumpOnly), &parsedDump))
		return false;
	if (!streq(parsedDump.dumpFile, L"Envy-4.2.0-x64-20260919T182600Z-p1-0001.dmp"))
		return false;

	const wchar_t* codeOnly =
	    L"envy_crash_report=1\r\n"
	    L"exception_code=0xC0000005\r\n";
	CrashReportMetadata parsedCode;
	if (!CrashReportParseMetadataText(codeOnly, wcslen(codeOnly), &parsedCode))
		return false;
	if (parsedCode.dumpFile[0] != 0)
		return false;
	return streq(parsedCode.exceptionCode, L"0xC0000005");
}

static bool test_configure_rejects_empty_directory()
{
	CrashDumpConfig cfg;
	ZeroMemory(&cfg, sizeof(cfg));
	cfg.continueSearch = FALSE;
	return CrashDumpWin::Configure(&cfg) == FALSE;
}

static bool test_dump_write_invalid_directory()
{
	CrashDumpWin::ResetDumpOnce();
	CrashDumpConfig cfg;
	ZeroMemory(&cfg, sizeof(cfg));
	CrashReportCopyTrunc(cfg.directory, _countof(cfg.directory), L"?:\\envy-crash-missing-dir");
	cfg.continueSearch = FALSE;
	CrashDumpWin::Configure(&cfg);
	CrashDumpWin::ResetDumpOnce();
	const BOOL wrote = CrashDumpWin::WriteFromException(nullptr);
	CrashDumpWin::ResetDumpOnce();
	return wrote == FALSE;
}

static bool MakeTempCrashDir(wchar_t* dest, size_t cch)
{
	wchar_t tmp[MAX_PATH];
	if (GetTempPathW(_countof(tmp), tmp) == 0)
		return false;
	swprintf_s(dest, cch, L"%sEnvyCrashTest-%lu-%lu", tmp, GetCurrentProcessId(), GetTickCount());
	return CreateDirectoryW(dest, nullptr) != 0 || GetLastError() == ERROR_ALREADY_EXISTS;
}

static void RemoveDirBestEffort(const wchar_t* dir)
{
	if (dir == nullptr || dir[0] == 0)
		return;
	wchar_t pattern[MAX_PATH];
	swprintf_s(pattern, _countof(pattern), L"%s\\*", dir);
	WIN32_FIND_DATAW fd;
	HANDLE h = FindFirstFileW(pattern, &fd);
	if (h != INVALID_HANDLE_VALUE)
	{
		do
		{
			if (fd.cFileName[0] == L'.')
				continue;
			wchar_t path[MAX_PATH];
			swprintf_s(path, _countof(path), L"%s\\%s", dir, fd.cFileName);
			DeleteFileW(path);
		} while (FindNextFileW(h, &fd));
		FindClose(h);
	}
	RemoveDirectoryW(dir);
}

int crash_dump_child_main()
{
	SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
	_set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);

	wchar_t dir[MAX_PATH];
	dir[0] = 0;
	GetEnvironmentVariableW(L"ENVY_CRASH_TEST_DIR", dir, MAX_PATH);
	if (dir[0] == 0)
		return 2;

	CrashDumpConfig cfg;
	ZeroMemory(&cfg, sizeof(cfg));
	CrashReportCopyTrunc(cfg.directory, _countof(cfg.directory), dir);
	CrashReportCopyTrunc(cfg.version, _countof(cfg.version), L"4.2.0");
	CrashReportCopyTrunc(cfg.buildType, _countof(cfg.buildType), L"Test");
	cfg.continueSearch = FALSE;
	CrashDumpWin::Configure(&cfg);
	SetUnhandledExceptionFilter(&CrashDumpWin::UnhandledExceptionFilter);

	RaiseException(EXCEPTION_ACCESS_VIOLATION, EXCEPTION_NONCONTINUABLE, 0, nullptr);
	return 3;
}

static bool test_child_process_writes_dump()
{
	wchar_t dir[MAX_PATH];
	if (!MakeTempCrashDir(dir, _countof(dir)))
		return false;

	SetEnvironmentVariableW(L"ENVY_CRASH_TEST_DIR", dir);

	wchar_t exe[MAX_PATH];
	if (GetModuleFileNameW(nullptr, exe, MAX_PATH) == 0)
	{
		RemoveDirBestEffort(dir);
		return false;
	}

	wchar_t cmd[MAX_PATH + 64];
	swprintf_s(cmd, _countof(cmd), L"\"%s\" --crash-dump-child", exe);

	STARTUPINFOW si;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));
	if (!CreateProcessW(exe, cmd, nullptr, nullptr, FALSE,
	                    CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
	{
		RemoveDirBestEffort(dir);
		return false;
	}
	const DWORD wait = WaitForSingleObject(pi.hProcess, 15000);
	DWORD code = STILL_ACTIVE;
	GetExitCodeProcess(pi.hProcess, &code);
	if (wait == WAIT_TIMEOUT)
		TerminateProcess(pi.hProcess, 9);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	BOOL foundDump = FALSE;
	BOOL foundTxt = FALSE;
	BOOL nonEmpty = FALSE;
	wchar_t pattern[MAX_PATH];
	swprintf_s(pattern, _countof(pattern), L"%s\\*", dir);
	WIN32_FIND_DATAW fd;
	HANDLE h = FindFirstFileW(pattern, &fd);
	if (h != INVALID_HANDLE_VALUE)
	{
		do
		{
			const size_t n = wcslen(fd.cFileName);
			if (n > 4 && _wcsicmp(fd.cFileName + n - 4, L".dmp") == 0)
			{
				foundDump = TRUE;
				if (fd.nFileSizeLow > 0 || fd.nFileSizeHigh > 0)
					nonEmpty = TRUE;
			}
			if (n > 4 && _wcsicmp(fd.cFileName + n - 4, L".txt") == 0)
				foundTxt = TRUE;
		} while (FindNextFileW(h, &fd));
		FindClose(h);
	}

	RemoveDirBestEffort(dir);
	SetEnvironmentVariableW(L"ENVY_CRASH_TEST_DIR", nullptr);

	if (wait == WAIT_TIMEOUT)
		return false;
	if (code == 0)
		return false;
	return foundDump && foundTxt && nonEmpty;
}

void register_crash_report_policy_smoke_tests(TestSuite& suite)
{
	suite.add_test("CrashReport.FileName.Normal", test_normal_report_name);
	suite.add_test("CrashReport.FileName.Win32", test_win32_arch_name);
	suite.add_test("CrashReport.FileName.LongVersion", test_long_version_truncated);
	suite.add_test("CrashReport.FileName.Timestamp", test_timestamp_format);
	suite.add_test("CrashReport.Path.InvalidDestination", test_invalid_destination);
	suite.add_test("CrashReport.FileName.CollisionSuffix", test_filename_collision_suffix);
	suite.add_test("CrashReport.Metadata.NormalEmpty", test_metadata_normal_and_empty);
	suite.add_test("CrashReport.Metadata.RejectsPaths", test_metadata_rejects_paths_and_registry);
	suite.add_test("CrashReport.Privacy.CredentialsAndIps", test_privacy_credentials_and_ips);
	suite.add_test("CrashReport.GitHub.TrustedUrl", test_github_url_is_trusted_and_small);
	suite.add_test("CrashReport.Retention.KeepsNewest", test_retention_keeps_newest);
	suite.add_test("CrashReport.Retention.NeverPruneNewest", test_retention_never_prunes_newest_over_size);
	suite.add_test("CrashReport.Metadata.DumpOrTxtOnly", test_metadata_dump_or_txt_only);
	suite.add_test("CrashReport.Dump.EmptyDirectory", test_configure_rejects_empty_directory);
	suite.add_test("CrashReport.Dump.InvalidDirectory", test_dump_write_invalid_directory);
	suite.add_test("CrashReport.Dump.ChildProcessSmoke", test_child_process_writes_dump);
}
