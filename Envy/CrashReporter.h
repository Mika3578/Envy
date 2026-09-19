//
// CrashReporter.h
//
// Windows crash reporting UI (#90). Capture is Crashpad. Not an EnvyCore API.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

namespace CrashReporter
{
void Initialize();
void SetIdentity(const wchar_t* pszVersion, const wchar_t* pszRevision, const wchar_t* pszBuildType);
void ShowStartupPromptIfNeeded();
void Shutdown();
const wchar_t* GetCrashDirectory();
}
