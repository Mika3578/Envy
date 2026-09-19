//
// NetworkJobValidate.h
//
// Pure Network async job-queue bounds (#81 DoS). Shared by Network and EnvyTests.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <windows.h>

// Cap for CNetwork::m_oJobs (inbound query search / hit ownership).
// RunJobs drains ~250 ms/tick; without a cap, floods grow unbounded heap trees.
constexpr DWORD NETWORK_JOB_QUEUE_MAX = 2048u;

inline BOOL NetworkJobQueueCountOk(DWORD nCount)
{
	return nCount < NETWORK_JOB_QUEUE_MAX;
}
