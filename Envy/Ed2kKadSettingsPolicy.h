//
// Ed2kKadSettingsPolicy.h
//
// Pure ED2K/Kad settings policy helpers (no network / MFC Settings object).
// Shared by CSettings registration and EnvyTests smoke tests.
//
// EnableKad must be registered with Settings.Add; without that registration the
// member stays at static zero-init (false) and InitKademlia never runs even
// when EnableKadHello / KadFindValue default to true.
//
// Missing-key load semantics match CSettings::Item::Load → CRegistry::GetBool(
// section, name, bDefault ): absent value returns bDefault.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <cstddef>
#include <cwchar>
#include <windows.h>

// Registry / settings section and value names (must match Settings.Add).
inline LPCTSTR Ed2kEnableKadSection()
{
	return L"eDonkey";
}

inline LPCTSTR Ed2kEnableKadName()
{
	return L"EnableKad";
}

// Intended default when the registry value is absent: true.
// Matches docs/50_user/reference/COMPLETE_SETTINGS_REFERENCE.md and the
// sibling Kad defaults (EnableKadHello / KadFindValue). Pre-#124 runtime was
// falsely stuck at false only because EnableKad was never registered.
inline bool Ed2kEnableKadDefault()
{
	return true;
}

// Sibling eDonkey Kad-related setting *names* (same section). Must not collide
// with EnableKad. Keep in sync with Settings.cpp registration list.
inline const LPCTSTR* Ed2kKadRelatedSettingNames(size_t* pnCount)
{
	static const LPCTSTR kNames[] = {
		L"EnableKadHello",
		L"KadFindValue",
		L"KadHelloTimeout",
		L"KadFindValueTimeout"
	};
	if ( pnCount )
		*pnCount = sizeof( kNames ) / sizeof( kNames[0] );
	return kNames;
}

inline bool Ed2kEnableKadNameCollidesWithSiblings()
{
	size_t nCount = 0;
	const LPCTSTR* pNames = Ed2kKadRelatedSettingNames( &nCount );
	for ( size_t i = 0; i < nCount; ++i )
	{
		if ( wcscmp( Ed2kEnableKadName(), pNames[i] ) == 0 )
			return true;
	}
	return false;
}
