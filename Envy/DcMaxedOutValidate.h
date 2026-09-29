//
// DcMaxedOutValidate.h
//
// Pure NMDC $MaxedOut queue-position token validation (#329).
// Shared by CDCClient / CDownloadTransferDC and EnvyTests.
//
// NMDC: $MaxedOut| means no upload slot (busy). $MaxedOut <rank>| carries
// queue position only — not total queue length.
//
// This file is part of Envy (getenvy.com) © 2016-2026
//

#pragma once

#include <stddef.h>

// Upper bound for parsed rank (fits CDownloadTransferDC::OnQueue int parameter).
constexpr unsigned DC_NMDC_QUEUE_RANK_MAX = 2147483647u;

// Empty $MaxedOut params (before trailing '|') mean busy, not queued.
inline bool DcNmdcMaxedOutIsBusyToken(const char* psz, size_t nLen)
{
	return psz != nullptr && nLen == 0;
}

enum class DcNmdcMaxedOutAction
{
	Busy,
	Queued,
	Invalid
};

// Strict positive unsigned decimal over exactly nLen bytes. Leading zero
// padding is accepted because some NMDC peers serialize queue positions
// with a fixed width. Rejects empty, zero, signs, junk, embedded whitespace,
// and overflow.
inline bool DcParseNmdcMaxedOutQueueRank(const char* psz, size_t nLen, unsigned* pnRankOut)
{
	if (!psz || !pnRankOut || nLen == 0)
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

// Mirrors CDCClient::OnMaxedOut routing (busy / OnQueue / ignore invalid).
inline DcNmdcMaxedOutAction DcNmdcMaxedOutResolveAction(const char* psz, size_t nLen, unsigned* pnRankOut)
{
	if (DcNmdcMaxedOutIsBusyToken(psz, nLen))
		return DcNmdcMaxedOutAction::Busy;
	if (pnRankOut != nullptr && DcParseNmdcMaxedOutQueueRank(psz, nLen, pnRankOut))
		return DcNmdcMaxedOutAction::Queued;
	return DcNmdcMaxedOutAction::Invalid;
}

// NMDC rank-only: total queue length stays unknown (m_nQueueLen = 0).
inline unsigned DcNmdcQueueTotalLengthForRank(unsigned /*nRank*/)
{
	return 0u;
}

// Mirrors CDownloadTransferDC::OnQueue queue-limit drop.
inline bool DcNmdcShouldDropQueuePosition(unsigned nRank, unsigned nQueueLimit)
{
	return nQueueLimit != 0 && nRank > nQueueLimit;
}
