//
// WebHookRegistrationPolicy.h
//
// Pure helpers for legacy Internet Explorer WebHook plugin registration.
// Shared by CPlugins::Register and EnvyTests smoke tests.
//
// WebHook32.dll / WebHook64.dll are an IE Browser Helper Object that intercepts
// downloads and hands URLs to Envy via envy://url:. This is not an HTTP webhook
// and is not loaded by Edge Chromium, Chrome, or Firefox.
//
// Shipped filenames are WebHook32.dll (Win32 project) and WebHook64.dll (x64).
// WebHook.dll is retained for historical OriginalFilename / older trees only.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <cwchar>
#include <windows.h>

// Exact plugin filenames (no wildcard).
inline bool IsWebHookPluginFileName(LPCTSTR pszFileName)
{
	if ( ! pszFileName || ! *pszFileName )
		return false;

	return ( _wcsicmp( pszFileName, L"WebHook.dll" ) == 0 ) ||
		( _wcsicmp( pszFileName, L"WebHook32.dll" ) == 0 ) ||
		( _wcsicmp( pszFileName, L"WebHook64.dll" ) == 0 );
}

// When Downloads.WebHookEnable is false, never LoadLibrary / DllRegister*
// either architecture at Envy startup.
inline bool ShouldSkipWebHookPluginRegistration(LPCTSTR pszFileName, bool bWebHookEnable)
{
	return ! bWebHookEnable && IsWebHookPluginFileName( pszFileName );
}

// BHO "Browser Helper Objects" hive: HKCU for AtlSetPerUserRegistration / DllInstall
// "user", HKLM only for explicit machine-wide DllRegisterServer.
inline HKEY WebHookBhoRegistryRoot(bool bPerUserRegistration)
{
	return bPerUserRegistration ? HKEY_CURRENT_USER : HKEY_LOCAL_MACHINE;
}

inline LPCTSTR WebHookBhoClsidString()
{
	return L"{C0283C00-AA11-43E4-8C1D-8D28A0C86042}";
}

inline LPCTSTR WebHookBhoRegistrySubKey()
{
	return L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\"
		L"Browser Helper Objects\\{C0283C00-AA11-43E4-8C1D-8D28A0C86042}";
}