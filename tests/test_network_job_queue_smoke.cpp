//
// test_network_job_queue_smoke.cpp
//
// Smoke tests for CNetwork async job-queue bounds (#81).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/NetworkJobValidate.h"

static bool test_network_job_queue_bounds()
{
	return NetworkJobQueueCountOk(0) == TRUE
		&& NetworkJobQueueCountOk(NETWORK_JOB_QUEUE_MAX - 1) == TRUE
		&& NetworkJobQueueCountOk(NETWORK_JOB_QUEUE_MAX) == FALSE
		&& NetworkJobQueueCountOk(NETWORK_JOB_QUEUE_MAX + 1) == FALSE;
}

void register_network_job_queue_smoke_tests(TestSuite& suite)
{
	suite.add_test("network_job_queue_bounds", test_network_job_queue_bounds);
}
