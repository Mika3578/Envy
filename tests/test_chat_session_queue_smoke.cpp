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
	return ChatSessionQueueCountOk( 0 ) == TRUE
		&& ChatSessionQueueCountOk( CHAT_SESSION_QUEUE_MAX - 1 ) == TRUE
		&& ChatSessionQueueCountOk( CHAT_SESSION_QUEUE_MAX ) == FALSE
		&& ChatSessionQueueCountOk( CHAT_SESSION_QUEUE_MAX + 1 ) == FALSE;
}

void register_chat_session_queue_smoke_tests( TestSuite& suite )
{
	suite.add_test( "chat_session_queue_bounds", test_chat_session_queue_bounds );
}
