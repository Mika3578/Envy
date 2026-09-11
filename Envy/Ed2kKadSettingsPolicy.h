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
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

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

// Documented default: true (COMPLETE_SETTINGS_REFERENCE.md).
// Distinct from EnableKadHello (KADEMLIA2_HELLO_REQ/RES only).
inline bool Ed2kEnableKadDefault()
{
	return true;
}
