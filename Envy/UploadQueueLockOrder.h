// SPDX-License-Identifier: AGPL-3.0-or-later
//
// UploadQueueLockOrder.h
//
// Lock order for upload queue position lookups.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

// How the sections actually nest:
//   - The transfers thread runs transfers while holding
//     CTransfers::m_pSection (recursive on that thread), and ranking inside
//     it acquires CNetwork::m_pSection before CUploadQueues::m_pSection.
//   - CUploadQueue::Start, reached while UploadQueues is held, touches the
//     transfers list; safe because those calls run on the transfers thread,
//     which already holds CTransfers::m_pSection, and no other thread takes
//     CTransfers::m_pSection while holding CUploadQueues::m_pSection.
//   - Never acquire CNetwork::m_pSection after CUploadQueues::m_pSection:
//     CUploadQueues::GetPosition takes Network first and would deadlock
//     against itself in reverse.

inline constexpr int UPLOAD_LOCK_ORDER_NETWORK = 1;
inline constexpr int UPLOAD_LOCK_ORDER_QUEUES = 2;
inline constexpr int UPLOAD_LOCK_ORDER_TRANSFERS = 3;

static_assert(UPLOAD_LOCK_ORDER_NETWORK < UPLOAD_LOCK_ORDER_QUEUES,
              "CNetwork::m_pSection must be acquired before CUploadQueues::m_pSection");
static_assert(UPLOAD_LOCK_ORDER_QUEUES < UPLOAD_LOCK_ORDER_TRANSFERS,
              "CUploadQueues::m_pSection precedes CTransfers::m_pSection on the transfers thread");
