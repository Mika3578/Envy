//
// DownloadTransferHttpValidate.h
//
// Shared policy helpers for bounded HTTP download framing.
// Suitable for EnvyTests without linking the full MFC transfer stack.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <windows.h>

// Explicit Content-Length: 0 must not be rejected while parsing headers for
// control responses (busy/queue, range fault, redirect) or MetaFetch/THEX,
// which may legitimately advertise an empty body. Ordinary file content
// rejection is applied only after those paths have been classified.
inline bool RejectExplicitZeroContentLength(
    bool bMetaFetch,
    bool bTigerFetch,
    bool bBusyFault,
    bool bRangeFault,
    bool bRedirect) noexcept
{
	return !bMetaFetch && !bTigerFetch && !bBusyFault && !bRangeFault && !bRedirect;
}

// After a known-length THEX body is fully consumed, the remainder tracked on
// m_nLength must be zero so OnDropped does not treat a completed fetch as
// truncated. A positive remainder means bytes are still outstanding.
inline bool TigerKnownLengthBodyFullyConsumed(ULONGLONG nRemainingLength) noexcept
{
	return nRemainingLength == 0;
}

// One socket event can span headers and body. Each read applies the current
// phase's cap; repeat only while the socket queue shrinks, so bandwidth limits
// or a full partial-frame buffer cannot create a busy loop.
template<typename ReadInput, typename PendingInput>
inline bool ReadHttpInputUntilBlocked(ReadInput readInput, PendingInput pendingInput)
{
	DWORD nPending = pendingInput();
	for (;;)
	{
		if (!readInput())
			return false;
		const DWORD nRemaining = pendingInput();
		if (nRemaining == 0 || nRemaining >= nPending)
			return true;
		nPending = nRemaining;
	}
}
