//
// test_chat_session_queue_smoke.cpp
//
// Smoke tests for CChatSession undelivered message queue bounds (#81).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/ChatSessionValidate.h"

static bool test_chat_session_queue_bounds()
{
	// Pin expected production cap so bumps to CHAT_SESSION_QUEUE_MAX fail the suite.
	if (CHAT_SESSION_QUEUE_MAX != 1024u)
		return false;
	return ChatSessionQueueCountOk(0) == TRUE
		&& ChatSessionQueueCountOk(1023u) == TRUE
		&& ChatSessionQueueCountOk(1024u) == FALSE
		&& ChatSessionQueueCountOk(1025u) == FALSE;
}

void register_chat_session_queue_smoke_tests(TestSuite& suite)
{
	suite.add_test("chat_session_queue_bounds", test_chat_session_queue_bounds);
}
