//
// CrashPadHost.h
//
// Out-of-process Crashpad client for ENVY (#90 / D-017).
// Upload URL is always empty. Not an EnvyCore API.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

namespace CrashPadHost
{
BOOL Start(const wchar_t* pszDatabaseDirectory);
void SetIdentity(const wchar_t* pszVersion, const wchar_t* pszRevision, const wchar_t* pszBuildType);
void DumpNow();
BOOL HandlerStarted();
const wchar_t* HandlerPath();
}
