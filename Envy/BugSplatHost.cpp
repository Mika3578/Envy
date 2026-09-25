//
// BugSplatHost.cpp
//
// BugSplat 7 out-of-process crash reporting for ENVY x64.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "StdAfx.h"
#include "BugSplatHost.h"
#include "CrashReportPolicy.h"

#include "BugSplat.h"

#include <memory>

namespace
{
std::unique_ptr<BugSplat> s_pBugSplat;
BOOL s_bActive = FALSE;
wchar_t s_version[64];
wchar_t s_revision[32];
wchar_t s_buildType[16];

void ApplyPrivacySafeMetadata()
{
	if (!s_pBugSplat)
		return;

	s_pBugSplat->ClearAttachments();
	s_pBugSplat->SetQuietMode(false);

	wchar_t windowsVersion[32];
	windowsVersion[0] = 0;
	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (hNtdll != nullptr)
	{
		typedef LONG(WINAPI * RtlGetVersionFn)(OSVERSIONINFOW*);
		RtlGetVersionFn pRtlGetVersion =
		    reinterpret_cast<RtlGetVersionFn>(GetProcAddress(hNtdll, "RtlGetVersion"));
		if (pRtlGetVersion != nullptr)
		{
			OSVERSIONINFOW vi;
			ZeroMemory(&vi, sizeof(vi));
			vi.dwOSVersionInfoSize = sizeof(vi);
			if (pRtlGetVersion(&vi) == 0)
				swprintf_s(windowsVersion, _countof(windowsVersion), L"%u.%u.%u",
				           vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
		}
	}

	if (s_version[0] != 0)
		s_pBugSplat->SetAttribute(L"envy_version", s_version);
	if (s_revision[0] != 0)
		s_pBugSplat->SetAttribute(L"envy_revision", s_revision);
	if (s_buildType[0] != 0)
		s_pBugSplat->SetAttribute(L"envy_build_type", s_buildType);
	if (windowsVersion[0] != 0)
		s_pBugSplat->SetAttribute(L"windows_version", windowsVersion);
	s_pBugSplat->SetAttribute(L"envy_arch", CrashReportArchitectureToken());
}

#ifdef ENVY_BUGSPLAT_DATABASE
#define ENVY_BUGSPLAT_DB_NAME ENVY_BUGSPLAT_DATABASE
#else
#define ENVY_BUGSPLAT_DB_NAME L""
#endif
}

BOOL BugSplatHost::Start()
{
	if (s_bActive)
		return TRUE;

	const wchar_t* pszDatabase = ENVY_BUGSPLAT_DB_NAME;
	if (pszDatabase == nullptr || pszDatabase[0] == 0)
		return FALSE;

	s_version[0] = 0;
	s_revision[0] = 0;
	s_buildType[0] = 0;

	try
	{
		s_pBugSplat = std::make_unique<BugSplat>(pszDatabase, L"Envy", L"0.0.0");
	}
	catch (...)
	{
		s_pBugSplat.reset();
		return FALSE;
	}

	SetGlobalCRTExceptionBehavior();
	SetPerThreadCRTExceptionBehavior();
	ApplyPrivacySafeMetadata();

	s_bActive = TRUE;
	return TRUE;
}

void BugSplatHost::SetIdentity(const wchar_t* pszVersion, const wchar_t* pszRevision, const wchar_t* pszBuildType)
{
	CrashReportSanitizeField(pszVersion, s_version, _countof(s_version));
	CrashReportSanitizeField(pszRevision, s_revision, _countof(s_revision));
	CrashReportSanitizeField(pszBuildType, s_buildType, _countof(s_buildType));
	ApplyPrivacySafeMetadata();
}

void BugSplatHost::Shutdown()
{
	if (!s_bActive)
		return;
	if (s_pBugSplat)
		s_pBugSplat->CleanupExceptionSystem();
	s_pBugSplat.reset();
	s_bActive = FALSE;
}

BOOL BugSplatHost::IsActive()
{
	return s_bActive;
}
