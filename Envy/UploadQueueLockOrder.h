//
// UploadQueueLockOrder.h
//
// Canonical lock order for upload queue position lookups (#332).
// Always acquire Network.m_pSection before CUploadQueues::m_pSection.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

// Documented order (outer -> inner):
//   1. CNetwork::m_pSection
//   2. CUploadQueues::m_pSection
//   3. CTransfers::m_pSection (reached through CUploadQueue::Start)
//
// Violating this order deadlocks against CUploadQueues::GetPosition, which
// locks Network then UploadQueues while a queue start can take Transfers.

inline constexpr int UPLOAD_LOCK_ORDER_NETWORK = 1;
inline constexpr int UPLOAD_LOCK_ORDER_QUEUES = 2;
inline constexpr int UPLOAD_LOCK_ORDER_TRANSFERS = 3;

inline bool UploadLockOrderNetworkBeforeQueues()
{
	return UPLOAD_LOCK_ORDER_NETWORK < UPLOAD_LOCK_ORDER_QUEUES
		&& UPLOAD_LOCK_ORDER_QUEUES < UPLOAD_LOCK_ORDER_TRANSFERS;
}
