//
// test_ed2k_lock_order_smoke.cpp
//
// Smoke test documenting EDClients-before-Transfers lock order (#92).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/Ed2kLockOrder.h"

static bool test_ed2k_lock_order_edclients_before_transfers()
{
	return Ed2kLockOrderEdClientsBeforeTransfers()
		&& ED2K_LOCK_ORDER_EDCLIENTS == 1
		&& ED2K_LOCK_ORDER_TRANSFERS == 2;
}

void register_ed2k_lock_order_smoke_tests( TestSuite& suite )
{
	suite.add_test( "ed2k_lock_order_edclients_before_transfers",
		test_ed2k_lock_order_edclients_before_transfers );
}
