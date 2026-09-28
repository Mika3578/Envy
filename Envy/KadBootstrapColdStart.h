//
// KadBootstrapColdStart.h
//
// Cold-start Kad bootstrap via validated remote nodes.dat acquisition.
// Pure policy + validation helpers (no live network in header).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include "KadNodesDat.h"

#include <cstdint>

#ifndef KAD_BOOTSTRAP_HTTP_MAX_BYTES
#define KAD_BOOTSTRAP_HTTP_MAX_BYTES KadNodesDatMaxFileBytes
#endif

#ifndef KAD_BOOTSTRAP_HTTP_TIMEOUT_MS
#define KAD_BOOTSTRAP_HTTP_TIMEOUT_MS 15000u
#endif

#ifndef KAD_BOOTSTRAP_MAX_URLS
#define KAD_BOOTSTRAP_MAX_URLS 4u
#endif

#ifndef KAD_BOOTSTRAP_MAX_ATTEMPTS
#define KAD_BOOTSTRAP_MAX_ATTEMPTS 6u
#endif

enum KadBootstrapColdStartPhase : int
{
	KadBootstrapPhaseIdle = 0,
	KadBootstrapPhaseNoCandidate,
	KadBootstrapPhaseRequestSent,
	KadBootstrapPhaseTimeout,
	KadBootstrapPhaseRejectedSize,
	KadBootstrapPhaseResponseMalformed,
	KadBootstrapPhaseContactsRejected,
	KadBootstrapPhaseValidated,
	KadBootstrapPhaseContactsAccepted,
	KadBootstrapPhasePreservedLastKnownGood,
	KadBootstrapPhasePersistenceFailed,
	KadBootstrapPhaseScheduledRetry,
};

enum KadBootstrapAcquireResult : int
{
	KadBootstrapAcquireOk = 0,
	KadBootstrapAcquireEmptyBody,
	KadBootstrapAcquireOversized,
	KadBootstrapAcquireParseFailed,
	KadBootstrapAcquireNoAcceptedContacts,
	KadBootstrapAcquirePersistenceFailed,
};

inline constexpr uint32_t KadBootstrapHttpMaxBytes()
{
	return KAD_BOOTSTRAP_HTTP_MAX_BYTES;
}

inline constexpr uint32_t KadBootstrapHttpTimeoutMs()
{
	return KAD_BOOTSTRAP_HTTP_TIMEOUT_MS;
}

// Wrap-safe elapsed check for GetTickCount() deadlines (DWORD ~49.7 day wrap).
inline bool KadBootstrapTickElapsed(uint32_t dwNowTick, uint32_t dwDeadlineTick)
{
	return static_cast<int32_t>(dwNowTick - dwDeadlineTick) >= 0;
}

inline uint32_t KadBootstrapBackoffMs(uint32_t nAttempt, uint32_t nBaseMs, uint32_t nCapMs)
{
	if (nAttempt == 0)
		return 0;
	uint32_t nDelay = nBaseMs;
	for (uint32_t i = 1; i < nAttempt && nDelay < nCapMs; ++i)
	{
		if (nDelay > nCapMs / 2)
			nDelay = nCapMs;
		else
			nDelay *= 2;
	}
	return nDelay > nCapMs ? nCapMs : nDelay;
}

inline KadBootstrapAcquireResult KadBootstrapValidateDownloadedBody(
    const uint8_t* pData, uint32_t nLength, KadNodesDatResult* pResultOut)
{
	if (pResultOut == NULL)
		return KadBootstrapAcquireParseFailed;

	if (nLength == 0)
		return KadBootstrapAcquireEmptyBody;

	if (pData == NULL)
		return KadBootstrapAcquireParseFailed;

	if (nLength > KadBootstrapHttpMaxBytes())
		return KadBootstrapAcquireOversized;

	KadNodesDatContact scratch[KadNodesDatBootstrapSelect];
	uint8_t zeroOwn[16] = {};
	const KadNodesDatResult oParsed =
	    KadNodesDatParse(pData, nLength, scratch, KadNodesDatBootstrapSelect, zeroOwn);
	*pResultOut = oParsed;

	if (oParsed.status != KadNodesDatStatus::Ok)
		return KadBootstrapAcquireParseFailed;

	if (oParsed.acceptedCount == 0)
		return KadBootstrapAcquireNoAcceptedContacts;

	return KadBootstrapAcquireOk;
}

inline KadBootstrapColdStartPhase KadBootstrapPhaseFromAcquireResult(KadBootstrapAcquireResult nResult)
{
	switch (nResult)
	{
	case KadBootstrapAcquireOversized:
		return KadBootstrapPhaseRejectedSize;
	case KadBootstrapAcquireNoAcceptedContacts:
		return KadBootstrapPhaseContactsRejected;
	case KadBootstrapAcquirePersistenceFailed:
		return KadBootstrapPhasePersistenceFailed;
	default:
		return KadBootstrapPhaseResponseMalformed;
	}
}

#ifdef _WIN32
// Undo an on-disk nodes.dat replacement when runtime HostCache import accepted no contacts.
inline bool KadBootstrapRestoreNodesDatAfterRejectedImport(
    bool bHadPriorNodesDat, LPCWSTR pszNodesDat, LPCWSTR pszLkg)
{
	if (pszNodesDat == NULL || pszNodesDat[0] == L'\0')
		return false;
	if (bHadPriorNodesDat)
	{
		if (pszLkg == NULL || pszLkg[0] == L'\0')
			return false;
		// bFailIfExists FALSE: overwrite the rejected candidate with the .lkg backup.
		return CopyFile(pszLkg, pszNodesDat, FALSE) != FALSE;
	}
	return DeleteFile(pszNodesDat) != FALSE;
}
#endif

#if !defined(KAD_BOOTSTRAP_TEST_HEADER_ONLY)
// Runtime cold-start gate (implemented in KadBootstrapColdStart.cpp).
bool KadBootstrapColdStartMayRequest(uint32_t dwNowTick);
void KadBootstrapColdStartOnDownloadSuccess();
void KadBootstrapColdStartOnDownloadFailure(KadBootstrapColdStartPhase nPhase);
LPCTSTR KadBootstrapColdStartPhaseName(KadBootstrapColdStartPhase nPhase);
#endif
