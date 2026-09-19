//
// test_crash_report_policy_smoke.cpp
//
// Crash-report naming, privacy, metadata, and retention helpers for #90.
// Live Crashpad crash-class tests run in tools/crash-probe (disposable
// child processes), not in this runner.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/CrashReportPolicy.h"

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

static void JoinUserinfoUrl(wchar_t* dest, size_t cch, const wchar_t* prefix, const wchar_t* user, const wchar_t* cred, const wchar_t* suffix)
{
	swprintf_s(dest, cch, L"%s%s:%s%s", prefix, user, cred, suffix);
}

static bool test_privacy_credentials_and_ips()
{
	wchar_t httpsUrl[160];
	wchar_t udpUrl[160];
	JoinUserinfoUrl(httpsUrl, _countof(httpsUrl), L"https://", L"alice", L"tok", L"@tracker.example/announce");
	JoinUserinfoUrl(udpUrl, _countof(udpUrl), L"udp://", L"alice", L"tok", L"@203.0.113.50:6969/announce");
	if (!CrashReportLooksLikeCredentialUrl(httpsUrl))
		return false;
	if (!CrashReportLooksPrivate(udpUrl))
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
	if (CrashReportContainsInsensitive(L"pass", L"passkey="))
		return false;
	if (!CrashReportContainsInsensitive(L"passkey=abcdef", L"passkey="))
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

static bool test_crashpad_uuid_name_is_safe()
{
	const wchar_t* uuid = L"01234567-89ab-cdef-0123-456789abcdef";
	if (!CrashReportIsSafeFileName(uuid))
		return false;
	wchar_t path[MAX_PATH];
	if (!CrashReportJoinPath(L"C:\\EnvyCrashUnit", uuid, path, _countof(path)))
		return false;
	wchar_t mini[MAX_PATH];
	if (!CrashReportJoinPath(path, L"minidump", mini, _countof(mini)))
		return false;
	return wcsstr(mini, L"minidump") != nullptr;
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
	suite.add_test("CrashReport.Crashpad.UuidPath", test_crashpad_uuid_name_is_safe);
}
