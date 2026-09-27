//
// bench_buffer_support.cpp
//
// Links production Buffer.cpp helpers not pulled in by the minimal benchmark PCH.
// UTF8Decode matches Envy/Strings.cpp (ReadLine path only).
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
