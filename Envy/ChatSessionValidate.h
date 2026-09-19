//
// ChatSessionValidate.h
//
// Pure chat undelivered-queue bounds (#81 DoS). Shared by ChatSession and EnvyTests.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <windows.h>

// Cap for CChatSession::m_pMessages before a private chat window drains it.
// Mirrors the application log queue depth (~1000); stops wire chat floods when
// no window is open or the UI lags.
constexpr DWORD CHAT_SESSION_QUEUE_MAX = 1024u;

inline BOOL ChatSessionQueueCountOk(DWORD nCount)
{
	return nCount < CHAT_SESSION_QUEUE_MAX;
}
