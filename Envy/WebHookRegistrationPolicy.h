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

// RegDeleteKey result for BHO cleanup: missing key is idempotent success.
inline HRESULT WebHookMapBhoDeleteResult(LONG lResult)
{
	if ( lResult == ERROR_SUCCESS ||
		lResult == ERROR_FILE_NOT_FOUND ||
		lResult == ERROR_PATH_NOT_FOUND )
		return S_OK;
	return HRESULT_FROM_WIN32( lResult );
}

// Prefer a real BHO failure over ATL unregister result (never cross-mask).
inline HRESULT WebHookCombineUnregisterHresults(HRESULT hrBho, HRESULT hrAtl)
{
	if ( FAILED( hrBho ) )
		return hrBho;
	return hrAtl;
}

// After ATL COM registration succeeded, BHO key failure must roll back ATL and
// still return the original BHO HRESULT (ignore rollback HRESULT).
inline HRESULT WebHookPreferBhoFailureOverRollback(HRESULT hrBho)
{
	return hrBho;
}