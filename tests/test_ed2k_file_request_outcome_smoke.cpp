//
// test_ed2k_file_request_outcome_smoke.cpp
//
// Regression tests for the ED2K FILEREQUEST reply decision.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/Ed2kFileRequestOutcome.h"

// Shared file with a free Library lock answers normally.
static bool test_outcome_shared_available_answers()
{
	return Ed2kResolveFileRequestOutcome( true, true, false ) == Ed2kFileRequestOutcome::AnswerShared
		&& Ed2kResolveFileRequestOutcome( true, true, true ) == Ed2kFileRequestOutcome::AnswerShared;
}

// An active download answers even when the library lookup found nothing.
static bool test_outcome_download_answers()
{
	return Ed2kResolveFileRequestOutcome( true, false, true ) == Ed2kFileRequestOutcome::AnswerDownload
		&& Ed2kResolveFileRequestOutcome( false, false, true ) == Ed2kFileRequestOutcome::AnswerDownload;
}

// Transient lock contention must defer, never produce a negative reply:
// this is the false-FILENOTFOUND regression the decision prevents.
static bool test_outcome_busy_defers_not_found()
{
	return Ed2kResolveFileRequestOutcome( false, false, false ) == Ed2kFileRequestOutcome::DeferredBusy;
}

// A held lock with neither a shared match nor a download is a real miss.
static bool test_outcome_genuine_not_found()
{
	return Ed2kResolveFileRequestOutcome( true, false, false ) == Ed2kFileRequestOutcome::NotFound;
}

void register_ed2k_file_request_outcome_smoke_tests( TestSuite& suite )
{
	suite.add_test( "ed2k_file_request_shared_available_answers",
		test_outcome_shared_available_answers );
	suite.add_test( "ed2k_file_request_download_answers",
		test_outcome_download_answers );
	suite.add_test( "ed2k_file_request_busy_defers_not_found",
		test_outcome_busy_defers_not_found );
	suite.add_test( "ed2k_file_request_genuine_not_found",
		test_outcome_genuine_not_found );
}
