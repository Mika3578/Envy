//
// KadBootstrapColdStart.cpp
//
// Cold-start Kad bootstrap scheduling (backoff, rate-limited logging).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "StdAfx.h"
#include "Envy.h"
#include "KadBootstrapColdStart.h"

namespace
{
CCriticalSection s_oStateSection;
uint32_t s_nAttempt = 0;
DWORD s_dwNextTryTick = 0;
DWORD s_dwLastLogTick = 0;
KadBootstrapColdStartPhase s_nLastLoggedPhase = KadBootstrapPhaseIdle;

constexpr DWORD KAD_BOOTSTRAP_BACKOFF_BASE_MS = 60u * 1000u;
constexpr DWORD KAD_BOOTSTRAP_BACKOFF_CAP_MS = 10u * 60u * 1000u;
constexpr DWORD KAD_BOOTSTRAP_LOG_INTERVAL_MS = 5u * 60u * 1000u;
} // namespace

bool KadBootstrapColdStartMayRequest(uint32_t dwNowTick)
{
	CSingleLock oLock(&s_oStateSection, TRUE);
	if (s_nAttempt >= KAD_BOOTSTRAP_MAX_ATTEMPTS)
	{
		if (s_dwNextTryTick != 0 &&
		    !KadBootstrapTickElapsed(dwNowTick, static_cast<uint32_t>(s_dwNextTryTick)))
			return false;
		s_nAttempt = 0;
		s_dwNextTryTick = 0;
	}
	return s_dwNextTryTick == 0 ||
	       KadBootstrapTickElapsed(dwNowTick, static_cast<uint32_t>(s_dwNextTryTick));
}

void KadBootstrapColdStartOnDownloadSuccess()
{
	CSingleLock oLock(&s_oStateSection, TRUE);
	s_nAttempt = 0;
	s_dwNextTryTick = 0;
	s_nLastLoggedPhase = KadBootstrapPhaseContactsAccepted;
}

void KadBootstrapColdStartOnDownloadFailure(KadBootstrapColdStartPhase nPhase)
{
	CSingleLock oLock(&s_oStateSection, TRUE);
	if (s_nAttempt < KAD_BOOTSTRAP_MAX_ATTEMPTS)
		++s_nAttempt;

	const DWORD dwNow = GetTickCount();
	s_dwNextTryTick = dwNow + KadBootstrapBackoffMs(s_nAttempt, KAD_BOOTSTRAP_BACKOFF_BASE_MS, KAD_BOOTSTRAP_BACKOFF_CAP_MS);

	if (nPhase == s_nLastLoggedPhase && static_cast<DWORD>(KAD_BOOTSTRAP_LOG_INTERVAL_MS) > static_cast<DWORD>(dwNow - s_dwLastLogTick))
		return;

	s_nLastLoggedPhase = nPhase;
	s_dwLastLogTick = dwNow;
	theApp.Message(MSG_NOTICE, L"Kad cold-start bootstrap %s (attempt %u/%u, retry in %u s)",
	               KadBootstrapColdStartPhaseName(nPhase), s_nAttempt, KAD_BOOTSTRAP_MAX_ATTEMPTS,
	               KadBootstrapBackoffMs(s_nAttempt, KAD_BOOTSTRAP_BACKOFF_BASE_MS, KAD_BOOTSTRAP_BACKOFF_CAP_MS) / 1000u);
}

LPCTSTR KadBootstrapColdStartPhaseName(KadBootstrapColdStartPhase nPhase)
{
	switch (nPhase)
	{
	case KadBootstrapPhaseNoCandidate:
		return L"no HTTPS nodes.dat source available";
	case KadBootstrapPhaseRequestSent:
		return L"request in progress";
	case KadBootstrapPhaseTimeout:
		return L"HTTP timeout";
	case KadBootstrapPhaseRejectedSize:
		return L"response too large";
	case KadBootstrapPhaseResponseMalformed:
		return L"response failed nodes.dat validation";
	case KadBootstrapPhaseContactsRejected:
		return L"no acceptable contacts in nodes.dat";
	case KadBootstrapPhasePreservedLastKnownGood:
		return L"kept previous nodes.dat after failed refresh";
	case KadBootstrapPhasePersistenceFailed:
		return L"could not update nodes.dat on disk";
	case KadBootstrapPhaseScheduledRetry:
		return L"scheduled retry";
	default:
		return L"failed";
	}
}
