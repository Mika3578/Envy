//
// DcMaxedOutValidate.h
//
// Pure NMDC $MaxedOut queue-position token validation (#329).
// Shared by CDCClient / CDownloadTransferDC and EnvyTests.
//
// NMDC: $MaxedOut| means no upload slot (busy). $MaxedOut <rank>| carries
// queue position only — not total queue length.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <stddef.h>

// Upper bound for parsed rank (fits CDownloadTransferDC::OnQueue int parameter).
constexpr unsigned DC_NMDC_QUEUE_RANK_MAX = 2147483647u;

// Strict positive unsigned decimal [1-9][0-9]* over exactly nLen bytes.
// Rejects empty, zero, signs, junk, embedded whitespace, and overflow.
inline bool DcParseNmdcMaxedOutQueueRank(const char* psz, size_t nLen, unsigned* pnRankOut)
{
	if (!psz || !pnRankOut || nLen == 0)
		return false;

	// No leading zeros (positive rank is [1-9][0-9]*).
	if (psz[0] < '1' || psz[0] > '9')
		return false;

	unsigned nValue = 0;

	for (size_t i = 0; i < nLen; ++i)
	{
		const char c = psz[i];
		if (c < '0' || c > '9')
			return false;

		const unsigned nDigit = static_cast<unsigned>(c - '0');
		if (nValue > (DC_NMDC_QUEUE_RANK_MAX - nDigit) / 10u)
			return false;
		nValue = nValue * 10u + nDigit;
	}

	if (nValue == 0)
		return false;

	*pnRankOut = nValue;
	return true;
}
