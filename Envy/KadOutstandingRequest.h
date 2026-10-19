// Kad2 request metadata shared by the application and native state tests.
// This file is part of Envy (getenvy.com) (C) 2016-2026
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

#include <winsock2.h>
#include "KadRoutingTable.h"

// Kad2 request tracking
enum KadRequestType
{
	KAD_REQUEST_BOOTSTRAP = 0,
	KAD_REQUEST_FIND_NODE = 1,
	KAD_REQUEST_SEARCH_KEY = 2,
	KAD_REQUEST_SEARCH_SOURCE = 3,
	KAD_REQUEST_PUBLISH_KEY = 4,
	KAD_REQUEST_PUBLISH_SOURCE = 5,
	KAD_REQUEST_FIREWALL_CHECK = 6,
	KAD_REQUEST_HELLO = 7
};

struct KadOutstandingRequest
{
	KadRequestType type;
	uint64_t sentTime;
	SOCKADDR_IN targetAddr;
	KadId targetId;
	bool hasTargetId;

	KadOutstandingRequest()
	    : type(KAD_REQUEST_BOOTSTRAP)
	    , sentTime(0)
	    , hasTargetId(false)
	{
		memset(&targetAddr, 0, sizeof(targetAddr));
		memset(targetId, 0, KAD_ID_SIZE);
	}

	KadOutstandingRequest(KadRequestType t, const SOCKADDR_IN& addr, uint64_t now)
	    : type(t)
	    , sentTime(now)
	    , hasTargetId(false)
	{
		targetAddr = addr;
		memset(targetId, 0, KAD_ID_SIZE);
	}
};
