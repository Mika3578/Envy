//
// BugSplatHost.h
//
// BugSplat 7 client wrapper for ENVY x64 (#353).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

namespace BugSplatHost
{
BOOL Start();
void SetIdentity(const wchar_t* pszVersion, const wchar_t* pszRevision, const wchar_t* pszBuildType);
void Shutdown();
BOOL IsActive();
}
