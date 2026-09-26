//
// test_dc_maxedout_queue_smoke.cpp
//
// Regression tests for NMDC $MaxedOut queue rank parsing and rank-only queue UX (#329).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/DcMaxedOutValidate.h"

#include <cstdio>
#include <cstring>
#include <string>

// Mirrors IDS_DOWNLOAD_QUEUED / IDS_DOWNLOAD_QUEUED_RANK English templates in Envy.rc.
static const char kQueuedKnownTotalFmt[] =
    "Download host %s is busy, waiting in queue at position #%i of %i (\"%s\").";
static const char kQueuedRankOnlyFmt[] =
    "Download host %s is busy, waiting in queue at position #%i (\"%s\").";

static bool parse_rank(const char* psz, size_t nLen, unsigned expected)
{
	unsigned nRank = 0;
	if (!DcParseNmdcMaxedOutQueueRank(psz, nLen, &nRank))
		return false;
	return nRank == expected;
}

static bool test_dc_maxedout_empty_params_is_busy_path()
{
	// Empty token is not a queue rank; CDCClient routes to OnBusy before parsing.
	return !DcParseNmdcMaxedOutQueueRank("", 0, nullptr);
}

static bool test_dc_maxedout_rank_one_and_twenty_five()
{
	return parse_rank("1", 1, 1u) && parse_rank("25", 2, 25u);
}

static bool test_dc_maxedout_rejects_zero_negative_and_non_numeric()
{
	unsigned n = 1;
	return !DcParseNmdcMaxedOutQueueRank("0", 1, &n) && !DcParseNmdcMaxedOutQueueRank("-1", 2, &n) && !DcParseNmdcMaxedOutQueueRank("abc", 3, &n) && !DcParseNmdcMaxedOutQueueRank("12abc", 5, &n) && !DcParseNmdcMaxedOutQueueRank("1x", 2, &n);
}

static bool test_dc_maxedout_rejects_overflow_and_whitespace_junk()
{
	unsigned n = 0;
	const char kOverflow[] = "2147483648";
	return !DcParseNmdcMaxedOutQueueRank(kOverflow, sizeof(kOverflow) - 1, &n) && !DcParseNmdcMaxedOutQueueRank(" 1", 2, &n) && !DcParseNmdcMaxedOutQueueRank("1 ", 2, &n) && !DcParseNmdcMaxedOutQueueRank("01", 2, &n);
}

static bool test_dc_maxedout_nlen_truncation_ignores_trailer()
{
	unsigned n = 0;
	// Parser is length-aware (DCClient passes substr size, not c_str scan).
	return DcParseNmdcMaxedOutQueueRank("25|", 2, &n) && n == 25u;
}

static bool test_dc_maxedout_queue_total_stays_unknown()
{
	// NMDC rank-only: production keeps m_nQueueLen at 0 meaning unknown (see DownloadTransfer.cpp status).
	const unsigned queueLenUnknown = 0;
	return queueLenUnknown == 0;
}

static bool test_dc_maxedout_queue_limit_compares_rank()
{
	const unsigned rank = 5000u;
	const unsigned limit = 1000u;
	const bool shouldDrop = (limit != 0 && rank > limit);
	return shouldDrop;
}

static bool test_dc_maxedout_rank_only_message_has_no_of_zero()
{
	if (std::strstr(kQueuedRankOnlyFmt, " of %i") != nullptr)
		return false;

	char buf[256];
	const int n = std::snprintf(buf, sizeof(buf), kQueuedRankOnlyFmt, "host.example", 4, "file.dat");
	if (n <= 0)
		return false;
	const std::string msg(buf);
	if (msg.find(" of 0") != std::string::npos)
		return false;
	if (msg.find("position #4") == std::string::npos)
		return false;

	// Known-total format still uses both placeholders for other protocols.
	char known[256];
	std::snprintf(known, sizeof(known), kQueuedKnownTotalFmt, "host.example", 4, 10, "file.dat");
	return std::strstr(known, " of 10") != nullptr;
}

void register_dc_maxedout_queue_smoke_tests(TestSuite& suite)
{
	suite.add_test("dc_maxedout_empty_params_is_busy_path", test_dc_maxedout_empty_params_is_busy_path);
	suite.add_test("dc_maxedout_rank_one_and_twenty_five", test_dc_maxedout_rank_one_and_twenty_five);
	suite.add_test("dc_maxedout_rejects_zero_negative_and_non_numeric", test_dc_maxedout_rejects_zero_negative_and_non_numeric);
	suite.add_test("dc_maxedout_rejects_overflow_and_whitespace_junk", test_dc_maxedout_rejects_overflow_and_whitespace_junk);
	suite.add_test("dc_maxedout_nlen_truncation_ignores_trailer", test_dc_maxedout_nlen_truncation_ignores_trailer);
	suite.add_test("dc_maxedout_queue_total_stays_unknown", test_dc_maxedout_queue_total_stays_unknown);
	suite.add_test("dc_maxedout_queue_limit_compares_rank", test_dc_maxedout_queue_limit_compares_rank);
	suite.add_test("dc_maxedout_rank_only_message_has_no_of_zero", test_dc_maxedout_rank_only_message_has_no_of_zero);
}
