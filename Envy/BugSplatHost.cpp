//
// BugSplatHost.cpp
//
// BugSplat SDK v8.0.0 out-of-process crash reporting for ENVY x64.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "StdAfx.h"
#include "BugSplatHost.h"
#include "CrashReportPolicy.h"

#include "BugSplat.h"

#include <array>
#include <memory>
#include <new>

namespace
{
struct BugSplatState
{
	std::unique_ptr<BugSplat> client;
	bool active = false;
	std::array<wchar_t, 64> version{};
	std::array<wchar_t, 32> revision{};
	std::array<wchar_t, 16> buildType{};
};

BugSplatState& State()
{
	static BugSplatState state;
	return state;
}

using RtlGetVersionFn = LONG(WINAPI*)(OSVERSIONINFOW*);

RtlGetVersionFn ResolveRtlGetVersion(HMODULE hNtdll)
{
	const FARPROC proc = GetProcAddress(hNtdll, "RtlGetVersion");
	if (proc == nullptr)
		return nullptr;
	return reinterpret_cast<RtlGetVersionFn>(proc); // NOSONAR cpp:S3630 (FARPROC → stdcall fn)
}

void ApplyCrashReportingDefaults()
{
	if (!State().client)
		return;
	State().client->ClearAttachments();
	State().client->SetQuietMode(false);
}

void ApplyPrivacySafeMetadata()
{
	if (!State().client)
		return;

	std::array<wchar_t, 32> windowsVersion{};
	if (const HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll"); hNtdll != nullptr)
	{
		if (const RtlGetVersionFn pRtlGetVersion = ResolveRtlGetVersion(hNtdll); pRtlGetVersion != nullptr)
		{
			OSVERSIONINFOW vi;
			ZeroMemory(&vi, sizeof(vi));
			vi.dwOSVersionInfoSize = sizeof(vi);
			if (pRtlGetVersion(&vi) == 0)
				swprintf_s(windowsVersion.data(), windowsVersion.size(), L"%u.%u.%u",
				           vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
		}
	}

	if (State().version[0] != 0)
		State().client->SetAttribute(L"envy_version", State().version.data());
	if (State().revision[0] != 0)
		State().client->SetAttribute(L"envy_revision", State().revision.data());
	if (State().buildType[0] != 0)
		State().client->SetAttribute(L"envy_build_type", State().buildType.data());
	if (windowsVersion[0] != 0)
		State().client->SetAttribute(L"windows_version", windowsVersion.data());
	State().client->SetAttribute(L"envy_arch", CrashReportArchitectureToken());
}

#ifdef ENVY_BUGSPLAT_DATABASE
const wchar_t kBugSplatDatabase[] = ENVY_BUGSPLAT_DATABASE;
#else
const wchar_t kBugSplatDatabase[] = L"";
#endif

BOOL EnsureBugSplatStarted()
{
	if (State().active)
		return TRUE;

	const wchar_t* pszDatabase = kBugSplatDatabase;
	if (pszDatabase == nullptr || pszDatabase[0] == 0)
		return FALSE;
	if (State().version[0] == 0)
		return FALSE;

	try
	{
		State().client = std::make_unique<BugSplat>(pszDatabase, L"Envy", State().version.data());
	}
	catch (const std::bad_alloc&)
	{
		State().client.reset();
		return FALSE;
	}
	catch (...) // NOSONAR cpp:S2738 — vendor SDK boundary; must not abort Envy startup
	{
		State().client.reset();
		return FALSE;
	}

	SetGlobalCRTExceptionBehavior();
	SetPerThreadCRTExceptionBehavior();
	ApplyCrashReportingDefaults();
	State().active = true;
	return TRUE;
}
}

void BugSplatHost::SetIdentity(const wchar_t* pszVersion, const wchar_t* pszRevision, const wchar_t* pszBuildType)
{
	CrashReportSanitizeField(pszVersion, State().version.data(), State().version.size());
	CrashReportSanitizeField(pszRevision, State().revision.data(), State().revision.size());
	CrashReportSanitizeField(pszBuildType, State().buildType.data(), State().buildType.size());

	if (!EnsureBugSplatStarted())
		return;

	ApplyPrivacySafeMetadata();
}

void BugSplatHost::Shutdown()
{
	if (!State().active)
		return;
	if (State().client)
		State().client->CleanupExceptionSystem();
	State().client.reset();
	State().active = false;
}

BOOL BugSplatHost::IsActive()
{
	return State().active ? TRUE : FALSE;
}

void BugSplatHost::InstallWorkerThreadExceptionBehavior()
{
	if (!State().active)
		return;
	SetPerThreadCRTExceptionBehavior();
}
