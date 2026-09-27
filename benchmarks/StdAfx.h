//
// StdAfx.h
//
// Minimal precompiled header for EnvyBenchmarks (production CBuffer.cpp).
// Resolves #include "StdAfx.h" from Envy/Buffer.cpp via include path order.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#pragma once

#define NOXPSUPPORT

#define NTDDI_VERSION NTDDI_WIN10_RS5
#define _WIN32_WINNT 0x0A00
#define WINVER 0x0A00

#include <sdkddkver.h>

#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN
#endif

#ifndef _SECURE_ATL
#define _SECURE_ATL 1
#endif

#define _ATL_NO_COM_SUPPORT
#define _ATL_CSTRING_NO_CRT
#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS
#define _AFX_NO_MFC_CONTROLS_IN_DIALOGS

#pragma warning(push, 0)

#include <wtsapi32.h>
#include <afxwin.h>
#include <afxext.h>

#pragma warning(pop)

#include <cstdint>
#include <cstring>
