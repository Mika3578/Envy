//
// test_dc_maxedout_queue_smoke.cpp
//
// Regression tests for NMDC $MaxedOut queue rank parsing and rank-only queue UX (#329).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "test_envy_rc_fixture.h"
#include "../Envy/DcMaxedOutValidate.h"
#include "../Envy/Resource.h"

#include <cstring>
#include <string>

static bool parse_rank(const char* psz, size_t nLen, unsigned expected)
{
	unsigned nRank = 0;
	if (!DcParseNmdcMaxedOutQueueRank(psz, nLen, &nRank))
		return false;
	return nRank == expected;
}

static bool test_dc_maxedout_resolve_busy_without_rank_out()
{
	return DcNmdcMaxedOutResolveAction("", 0, nullptr) == DcNmdcMaxedOutAction::Busy &&
	       DcNmdcMaxedOutResolveAction(nullptr, 0, nullptr) == DcNmdcMaxedOutAction::Invalid &&
	       DcNmdcMaxedOutResolveAction(nullptr, 1, nullptr) == DcNmdcMaxedOutAction::Invalid;
}

static bool test_dc_maxedout_resolve_queued_rank()
{
	unsigned nRank = 0;
	return DcNmdcMaxedOutResolveAction("25", 2, &nRank) == DcNmdcMaxedOutAction::Queued &&
	       nRank == 25u;
}

static bool test_dc_maxedout_resolve_invalid_rank()
{
	unsigned nRank = 0;
	return DcNmdcMaxedOutResolveAction("0", 1, &nRank) == DcNmdcMaxedOutAction::Invalid &&
	       DcNmdcMaxedOutResolveAction("abc", 3, &nRank) == DcNmdcMaxedOutAction::Invalid;
}

static bool test_dc_maxedout_rank_one_and_twenty_five()
{
	return parse_rank("1", 1, 1u) && parse_rank("01", 2, 1u) && parse_rank("25", 2, 25u);
}

static bool test_dc_maxedout_rejects_zero_negative_and_non_numeric()
{
	unsigned n = 1;
	return !DcParseNmdcMaxedOutQueueRank("0", 1, &n) && !DcParseNmdcMaxedOutQueueRank("-1", 2, &n) &&
	       !DcParseNmdcMaxedOutQueueRank("abc", 3, &n) && !DcParseNmdcMaxedOutQueueRank("12abc", 5, &n) &&
	       !DcParseNmdcMaxedOutQueueRank("1x", 2, &n);
}

static bool test_dc_maxedout_rejects_overflow_and_whitespace_junk()
{
	unsigned n = 0;
	const char kOverflow[] = "2147483648";
	return !DcParseNmdcMaxedOutQueueRank(kOverflow, sizeof(kOverflow) - 1, &n) &&
	       !DcParseNmdcMaxedOutQueueRank(" 1", 2, &n) && !DcParseNmdcMaxedOutQueueRank("1 ", 2, &n) &&
	       !DcParseNmdcMaxedOutQueueRank("00", 2, &n);
}

static bool test_dc_maxedout_nlen_truncation_ignores_trailer()
{
	unsigned n = 0;
	return DcParseNmdcMaxedOutQueueRank("25|", 2, &n) && n == 25u;
}

static bool test_dc_maxedout_queue_total_unknown_for_rank()
{
	const unsigned rank = 4u;
	return DcNmdcQueueTotalLengthForRank(rank) == 0u;
}

static bool test_dc_maxedout_queue_limit_drop_matches_onqueue()
{
	return DcNmdcShouldDropQueuePosition(5000u, 1000u) &&
	       !DcNmdcShouldDropQueuePosition(500u, 1000u) && !DcNmdcShouldDropQueuePosition(5000u, 0u);
}

static bool test_dc_maxedout_queued_rank_resource_templates()
{
#if IDS_DOWNLOAD_QUEUED_RANK != 20277
	return false;
#endif
	std::string rc;
	if (!TestReadEnvyRc(rc, "dc_maxedout_queue: Envy/Envy.rc not found from cwd\n"))
		return false;

	std::string rankFmt;
	std::string knownFmt;
	if (!TestExtractRcQuotedString(rc, "IDS_DOWNLOAD_QUEUED_RANK", rankFmt) ||
	    !TestExtractRcQuotedString(rc, "IDS_DOWNLOAD_QUEUED", knownFmt))
		return false;

	if (rankFmt.find(" of %i") != std::string::npos)
		return false;
	if (knownFmt.find(" of %i") == std::string::npos)
		return false;
	if (rankFmt.find("position #%i") == std::string::npos)
		return false;
	if (rankFmt.find("(\"%s\")") == std::string::npos)
		return false;
	if (knownFmt.find("(\"%s\")") == std::string::npos)
		return false;

	return true;
}

void register_dc_maxedout_queue_smoke_tests(TestSuite& suite)
{
	suite.add_test("dc_maxedout_resolve_busy_without_rank_out", test_dc_maxedout_resolve_busy_without_rank_out);
	suite.add_test("dc_maxedout_resolve_queued_rank", test_dc_maxedout_resolve_queued_rank);
	suite.add_test("dc_maxedout_resolve_invalid_rank", test_dc_maxedout_resolve_invalid_rank);
	suite.add_test("dc_maxedout_rank_one_and_twenty_five", test_dc_maxedout_rank_one_and_twenty_five);
	suite.add_test("dc_maxedout_rejects_zero_negative_and_non_numeric",
	               test_dc_maxedout_rejects_zero_negative_and_non_numeric);
	suite.add_test("dc_maxedout_rejects_overflow_and_whitespace_junk",
	               test_dc_maxedout_rejects_overflow_and_whitespace_junk);
	suite.add_test("dc_maxedout_nlen_truncation_ignores_trailer", test_dc_maxedout_nlen_truncation_ignores_trailer);
	suite.add_test("dc_maxedout_queue_total_unknown_for_rank", test_dc_maxedout_queue_total_unknown_for_rank);
	suite.add_test("dc_maxedout_queue_limit_drop_matches_onqueue", test_dc_maxedout_queue_limit_drop_matches_onqueue);
	suite.add_test("dc_maxedout_queued_rank_resource_templates", test_dc_maxedout_queued_rank_resource_templates);
}
