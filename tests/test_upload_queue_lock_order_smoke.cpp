//
// test_upload_queue_lock_order_smoke.cpp
//
// Smoke test documenting Network-before-UploadQueues lock order (#332).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/UploadQueueLockOrder.h"

static bool test_upload_queue_lock_order_network_before_queues()
{
	return UPLOAD_LOCK_ORDER_NETWORK < UPLOAD_LOCK_ORDER_QUEUES
		&& UPLOAD_LOCK_ORDER_QUEUES < UPLOAD_LOCK_ORDER_TRANSFERS
		&& UPLOAD_LOCK_ORDER_NETWORK == 1
		&& UPLOAD_LOCK_ORDER_QUEUES == 2
		&& UPLOAD_LOCK_ORDER_TRANSFERS == 3;
}

void register_upload_queue_lock_order_smoke_tests( TestSuite& suite )
{
	suite.add_test( "upload_queue_lock_order_network_before_queues",
		test_upload_queue_lock_order_network_before_queues );
}
