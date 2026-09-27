//
// Ed2kLockOrder.h
//
// Canonical lock order when both EDClients and Transfers sections are held (#92).
// Always acquire EDClients.m_pSection before Transfers.m_pSection.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

// Documented order (outer → inner):
//   1. CEDClients::m_pSection
//   2. CTransfers::m_pSection
//
// Violating this order deadlocks against CEDClients::OnRun, which locks
// EDClients then Transfers.

inline constexpr int ED2K_LOCK_ORDER_EDCLIENTS = 1;
inline constexpr int ED2K_LOCK_ORDER_TRANSFERS = 2;

inline bool Ed2kLockOrderEdClientsBeforeTransfers()
{
	return ED2K_LOCK_ORDER_EDCLIENTS < ED2K_LOCK_ORDER_TRANSFERS;
}
