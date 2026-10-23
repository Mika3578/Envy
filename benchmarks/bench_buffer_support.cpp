//
// bench_buffer_support.cpp
//
// Link-only UTF8Decode shim for production BufferImpl.inc (ReadLine path).
// Must stay behavior-identical to Envy/Strings.cpp UTF8Decode overloads.
// Buffer foundation workloads do not call ReadLine; compiling all of
// Strings.cpp would pull unrelated Envy string surface into this target.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include "StdAfx.h"

#include "../Envy/Strings.h"

CStringW UTF8Decode(__in const CStringA& strInput)
{
	return UTF8Decode(strInput, strInput.GetLength());
}

CStringW UTF8Decode(__in_bcount(nInput) LPCSTR psInput, __in int nInput)
{
	CStringW strWide;
	int nWide = 0;

	nWide = ::MultiByteToWideChar(CP_UTF8, 0, psInput, nInput, strWide.GetBuffer(nInput + 1), nInput + 1);
	if (nWide == 0 && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		nWide = ::MultiByteToWideChar(CP_UTF8, 0, psInput, nInput, NULL, 0);
		nWide = ::MultiByteToWideChar(CP_UTF8, 0, psInput, nInput, strWide.GetBuffer(nWide), nWide);
	}
	strWide.ReleaseBuffer(nWide);
	return strWide;
}
