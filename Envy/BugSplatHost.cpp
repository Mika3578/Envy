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
#include <exception>
#include <memory>

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

BugSplatState s_state;

using RtlGetVersionFn = LONG(WINAPI*)(OSVERSIONINFOW*);

RtlGetVersionFn ResolveRtlGetVersion(HMODULE hNtdll)
{
	const FARPROC proc = GetProcAddress(hNtdll, "RtlGetVersion");
	if (proc == nullptr)
		return nullptr;
	// FARPROC → stdcall function pointer is required on Win32; no portable alternative.
	return reinterpret_cast<RtlGetVersionFn>(proc);
}

void ApplyCrashReportingDefaults()
{
	if (!s_state.client)
		return;
	s_state.client->ClearAttachments();
	s_state.client->SetQuietMode(false);
}

void ApplyPrivacySafeMetadata()
{
	if (!s_state.client)
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

	if (s_state.version[0] != 0)
		s_state.client->SetAttribute(L"envy_version", s_state.version.data());
	if (s_state.revision[0] != 0)
		s_state.client->SetAttribute(L"envy_revision", s_state.revision.data());
	if (s_state.buildType[0] != 0)
		s_state.client->SetAttribute(L"envy_build_type", s_state.buildType.data());
	if (windowsVersion[0] != 0)
		s_state.client->SetAttribute(L"windows_version", windowsVersion.data());
	s_state.client->SetAttribute(L"envy_arch", CrashReportArchitectureToken());
}

#ifdef ENVY_BUGSPLAT_DATABASE
const wchar_t kBugSplatDatabase[] = ENVY_BUGSPLAT_DATABASE;
#else
const wchar_t kBugSplatDatabase[] = L"";
#endif

BOOL EnsureBugSplatStarted()
{
	if (s_state.active)
		return TRUE;

	const wchar_t* pszDatabase = kBugSplatDatabase;
	if (pszDatabase == nullptr || pszDatabase[0] == 0)
		return FALSE;
	if (s_state.version[0] == 0)
		return FALSE;

	try
	{
		s_state.client = std::make_unique<BugSplat>(pszDatabase, L"Envy", s_state.version.data());
	}
	catch (const std::exception&)
	{
		s_state.client.reset();
		return FALSE;
	}
	catch (...)
	{
		// BugSplat SDK may throw outside std::exception; crash reporter must fail closed.
		s_state.client.reset();
		return FALSE;
	}

	SetGlobalCRTExceptionBehavior();
	SetPerThreadCRTExceptionBehavior();
	ApplyCrashReportingDefaults();
	s_state.active = true;
	return TRUE;
}
}

void BugSplatHost::SetIdentity(const wchar_t* pszVersion, const wchar_t* pszRevision, const wchar_t* pszBuildType)
{
	CrashReportSanitizeField(pszVersion, s_state.version.data(), s_state.version.size());
	CrashReportSanitizeField(pszRevision, s_state.revision.data(), s_state.revision.size());
	CrashReportSanitizeField(pszBuildType, s_state.buildType.data(), s_state.buildType.size());

	if (!EnsureBugSplatStarted())
		return;

	ApplyPrivacySafeMetadata();
}

void BugSplatHost::Shutdown()
{
	if (!s_state.active)
		return;
	if (s_state.client)
		s_state.client->CleanupExceptionSystem();
	s_state.client.reset();
	s_state.active = false;
}

BOOL BugSplatHost::IsActive()
{
	return s_state.active ? TRUE : FALSE;
}

void BugSplatHost::InstallWorkerThreadExceptionBehavior()
{
	if (!s_state.active)
		return;
	SetPerThreadCRTExceptionBehavior();
}
