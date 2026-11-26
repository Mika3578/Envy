// SPDX-License-Identifier: AGPL-3.0-or-later
// Minimal Win32 type subset for portable regression harnesses that include
// production validation headers outside Windows. Never used by Envy itself.

#pragma once

#include <cstddef>
#include <cstdint>

typedef std::uint32_t DWORD;
typedef std::uint16_t WORD;
typedef unsigned char BYTE;
typedef int BOOL;
typedef unsigned long long ULONGLONG;
typedef const wchar_t* LPCTSTR;

#define TRUE 1
#define FALSE 0
#define MAXDWORD 0xFFFFFFFFu
#define CP_UTF8 65001u
