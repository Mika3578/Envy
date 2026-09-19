// Isolated Crashpad / Sentry Native probe for ENVY #90 (not linked into Envy.exe).
// Upload URL and DSN are always empty. Do not add an ingest host here.

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

#include <windows.h>

#ifndef FAST_FAIL_FATAL_APP_EXIT
#define FAST_FAIL_FATAL_APP_EXIT 7
#endif

#include <intrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>

#ifdef CRASH_PROBE_SENTRY
#include <sentry.h>
#else
#include "client/crash_report_database.h"
#include "client/crashpad_client.h"
#include "client/settings.h"
#include <map>
#include <memory>
#include <vector>
#endif

static const wchar_t* kUploadUrlPrint = L"";

static void PrintUsage()
{
	fwprintf(stderr,
	         L"CrashProbe --init-only | --crash av|heap|stack|fastfail\n"
	         L"  [--database DIR] [--handler crashpad_handler.exe]\n");
}

static std::wstring ProbeDir()
{
	wchar_t path[MAX_PATH];
	DWORD n = GetModuleFileNameW(nullptr, path, MAX_PATH);
	if (n == 0 || n >= MAX_PATH)
		return L".";
	wchar_t* slash = wcsrchr(path, L'\\');
	if (slash)
		*slash = 0;
	return path;
}

static std::wstring JoinPath(const std::wstring& dir, const wchar_t* name)
{
	if (dir.empty())
		return name;
	if (dir.back() == L'\\' || dir.back() == L'/')
		return dir + name;
	return dir + L"\\" + name;
}

static void EnsureDirectory(const std::wstring& path)
{
	std::wstring cur;
	for (size_t i = 0; i < path.size(); ++i)
	{
		cur.push_back(path[i]);
		if (path[i] == L'\\' || path[i] == L'/' || i + 1 == path.size())
		{
			if (cur.size() > 2)
				CreateDirectoryW(cur.c_str(), nullptr);
		}
	}
}

static std::wstring DefaultDatabase()
{
	wchar_t tmp[MAX_PATH];
	DWORD n = GetTempPathW(MAX_PATH, tmp);
	if (n == 0 || n >= MAX_PATH)
		wcscpy_s(tmp, L".\\");
#ifdef CRASH_PROBE_SENTRY
	return JoinPath(tmp, L"EnvyCrashProbe\\sentry");
#else
	return JoinPath(tmp, L"EnvyCrashProbe\\crashpad");
#endif
}

static std::wstring FindHandler(const std::wstring& exeDir, const std::wstring& overridePath)
{
	if (!overridePath.empty())
		return overridePath;
	wchar_t envBuf[MAX_PATH];
	DWORD envLen = GetEnvironmentVariableW(L"CRASH_PROBE_HANDLER", envBuf, MAX_PATH);
	if (envLen > 0 && envLen < MAX_PATH)
		return envBuf;
	return JoinPath(exeDir, L"crashpad_handler.exe");
}

static void PrintIdentity(const wchar_t* backend, const std::wstring& handler, const std::wstring& database, int uploadsEnabled)
{
	wprintf(L"backend=%s\n", backend);
	wprintf(L"handler=%s\n", handler.c_str());
	wprintf(L"database=%s\n", database.c_str());
	wprintf(L"upload_url=%s\n", kUploadUrlPrint);
	wprintf(L"uploads_enabled=%d\n", uploadsEnabled);
	wprintf(L"consent=local-only\n");
}

#ifdef CRASH_PROBE_SENTRY
static int InitBackend(const std::wstring& database, const std::wstring& handler)
{
	_putenv("SENTRY_DSN=");
	EnsureDirectory(database);
	sentry_options_t* options = sentry_options_new();
	if (!options)
		return 2;
	sentry_options_set_database_pathw(options, database.c_str());
	sentry_options_set_handler_pathw(options, handler.c_str());
	sentry_options_set_dsn(options, "");
	sentry_options_set_auto_session_tracking(options, 0);
	sentry_options_set_debug(options, 0);
	sentry_options_set_max_breadcrumbs(options, 0);
	if (sentry_init(options) != 0)
	{
		fwprintf(stderr, L"sentry_init failed\n");
		return 3;
	}
	PrintIdentity(L"sentry", handler, database, 0);
	return 0;
}

static void ShutdownBackend()
{
	sentry_close();
}
#else
static crashpad::CrashpadClient g_client;

static int InitBackend(const std::wstring& database, const std::wstring& handler)
{
	EnsureDirectory(database);
	base::FilePath db(database);
	base::FilePath handlerPath(handler);
	std::unique_ptr<crashpad::CrashReportDatabase> reports = crashpad::CrashReportDatabase::Initialize(db);
	if (!reports)
	{
		fwprintf(stderr, L"Crashpad database init failed\n");
		return 2;
	}
	if (!reports->GetSettings()->SetUploadsEnabled(false))
	{
		fwprintf(stderr, L"SetUploadsEnabled(false) failed\n");
		return 2;
	}
	bool uploads = true;
	reports->GetSettings()->GetUploadsEnabled(&uploads);

	std::map<std::string, std::string> annotations;
	annotations["product"] = "EnvyCrashProbe";
	annotations["version"] = "eval";
	std::vector<std::string> arguments;
	const std::string emptyUrl;
	if (!g_client.StartHandler(handlerPath, db, db, emptyUrl, annotations, arguments, true, false))
	{
		fwprintf(stderr, L"Crashpad StartHandler failed (handler missing?)\n");
		return 3;
	}
	PrintIdentity(L"crashpad", handler, database, uploads ? 1 : 0);
	if (uploads)
	{
		fwprintf(stderr, L"uploads_enabled must stay 0\n");
		return 4;
	}
	return 0;
}

static void ShutdownBackend()
{
}
#endif

static void CrashAccessViolation()
{
	RaiseException(EXCEPTION_ACCESS_VIOLATION, EXCEPTION_NONCONTINUABLE, 0, nullptr);
}

static void CrashHeapCorruption()
{
	HANDLE heap = HeapCreate(0, 0, 0);
	if (!heap)
		RaiseException(static_cast<DWORD>(0xC0000374), EXCEPTION_NONCONTINUABLE, 0, nullptr);
	HeapSetInformation(heap, HeapEnableTerminationOnCorruption, nullptr, 0);
	BYTE* p = static_cast<BYTE*>(HeapAlloc(heap, 0, 64));
	if (!p)
		RaiseException(static_cast<DWORD>(0xC0000374), EXCEPTION_NONCONTINUABLE, 0, nullptr);
	memset(p - 16, 0xCC, 48);
	HeapFree(heap, 0, p);
	HeapDestroy(heap);
}

#if defined(_MSC_VER)
__declspec(noinline)
#endif
static void
RecurseStack(volatile unsigned* sink)
{
	volatile unsigned char buf[4096];
	buf[0] = static_cast<unsigned char>(*sink + 1);
	*sink = buf[0];
	RecurseStack(sink);
	buf[1] = buf[0];
}

static void CrashStackOverflow()
{
	ULONG guarantee = 64 * 1024;
	SetThreadStackGuarantee(&guarantee);
	volatile unsigned sink = 1;
	RecurseStack(&sink);
}

static void CrashFastFail()
{
	__fastfail(FAST_FAIL_FATAL_APP_EXIT);
}

static int RunCrash(const wchar_t* kind)
{
	if (_wcsicmp(kind, L"av") == 0)
		CrashAccessViolation();
	else if (_wcsicmp(kind, L"heap") == 0)
		CrashHeapCorruption();
	else if (_wcsicmp(kind, L"stack") == 0)
		CrashStackOverflow();
	else if (_wcsicmp(kind, L"fastfail") == 0)
		CrashFastFail();
	else
	{
		fwprintf(stderr, L"unknown crash kind: %s\n", kind);
		return 1;
	}
	fwprintf(stderr, L"crash kind %s did not terminate\n", kind);
	return 5;
}

int wmain(int argc, wchar_t** argv)
{
	std::wstring database = DefaultDatabase();
	std::wstring handlerOverride;
	const wchar_t* crashKind = nullptr;
	bool initOnly = false;

	for (int i = 1; i < argc; ++i)
	{
		if (wcscmp(argv[i], L"--init-only") == 0)
			initOnly = true;
		else if (wcscmp(argv[i], L"--crash") == 0 && i + 1 < argc)
			crashKind = argv[++i];
		else if (wcscmp(argv[i], L"--database") == 0 && i + 1 < argc)
			database = argv[++i];
		else if (wcscmp(argv[i], L"--handler") == 0 && i + 1 < argc)
			handlerOverride = argv[++i];
		else if (wcscmp(argv[i], L"--help") == 0 || wcscmp(argv[i], L"-h") == 0)
		{
			PrintUsage();
			return 0;
		}
		else
		{
			PrintUsage();
			return 1;
		}
	}

	if (!initOnly && crashKind == nullptr)
	{
		PrintUsage();
		return 1;
	}

	const std::wstring handler = FindHandler(ProbeDir(), handlerOverride);
	if (GetFileAttributesW(handler.c_str()) == INVALID_FILE_ATTRIBUTES)
	{
		fwprintf(stderr, L"handler not found: %s\n", handler.c_str());
		return 3;
	}

	EnsureDirectory(database);

	const int initRc = InitBackend(database, handler);
	if (initRc != 0)
		return initRc;

	if (initOnly)
	{
		ShutdownBackend();
		return 0;
	}

	return RunCrash(crashKind);
}
