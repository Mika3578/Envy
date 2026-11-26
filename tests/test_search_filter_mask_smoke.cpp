//
// test_search_filter_mask_smoke.cpp
//
// Regression tests for the Settings.Search.FilterMask codec contract.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "test_framework.h"
#include "../Envy/SearchFilterMask.h"

// CMatchList::Filter() writes this mask, so these positions are what
// existing users have persisted; a change here swaps saved Local/Reject
// semantics on upgrade.
static bool test_search_filter_mask_persisted_positions()
{
	return SEARCH_FILTER_LOCAL == ( 1u << 4 )
		&& SEARCH_FILTER_REJECT == ( 1u << 5 )
		&& SEARCH_FILTER_REGEXP == ( 1u << 0 )
		&& SEARCH_FILTER_PUSH == ( 1u << 1 )
		&& SEARCH_FILTER_UNSTABLE == ( 1u << 2 )
		&& SEARCH_FILTER_BUSY == ( 1u << 3 )
		&& SEARCH_FILTER_BOGUS == ( 1u << 6 )
		&& SEARCH_FILTER_DRM == ( 1u << 7 )
		&& SEARCH_FILTER_RESTRICTED == ( 1u << 8 )
		&& SEARCH_FILTER_SUSPICIOUS == ( 1u << 9 )
		&& SEARCH_FILTER_ADULT == ( 1u << 10 );
}

// The production decoder must map the persisted Local/Reject bits the way
// CMatchList::Filter() writes them: bit 4 = Local, bit 5 = Reject. A swap
// here is the reported regression.
static bool test_search_filter_mask_local_reject_decode()
{
	const SearchFilterState oLocal = DecodeSearchFilterMask( SEARCH_FILTER_LOCAL );
	const SearchFilterState oReject = DecodeSearchFilterMask( SEARCH_FILTER_REJECT );
	const SearchFilterState oBoth = DecodeSearchFilterMask( SEARCH_FILTER_LOCAL | SEARCH_FILTER_REJECT );
	const SearchFilterState oNone = DecodeSearchFilterMask( 0u );

	if ( ! oLocal.bFilterLocal || oLocal.bFilterReject ) return false;
	if ( ! oReject.bFilterReject || oReject.bFilterLocal ) return false;
	if ( ! oBoth.bFilterLocal || ! oBoth.bFilterReject ) return false;
	if ( oNone.bFilterLocal || oNone.bFilterReject ) return false;

	return true;
}

// Every distinct combination of the 11 filter bits must decode through the
// production decoder into a disjoint set of flags and re-encode through the
// production encoder to the identical mask: 0, single bits, Local+Reject,
// and all bits set included.
static bool test_search_filter_mask_round_trip()
{
	for ( unsigned int nMask = 0; nMask < 2048u; nMask++ )
	{
		if ( EncodeSearchFilterMask( DecodeSearchFilterMask( nMask ) ) != nMask )
			return false;
	}

	return true;
}

// The named constants must be pairwise distinct and cover exactly the low
// 11 bits, so a reader cannot silently alias one filter onto another.
static bool test_search_filter_mask_constants_distinct()
{
	const unsigned int nBits[] =
	{
		SEARCH_FILTER_REGEXP, SEARCH_FILTER_PUSH, SEARCH_FILTER_UNSTABLE,
		SEARCH_FILTER_BUSY, SEARCH_FILTER_LOCAL, SEARCH_FILTER_REJECT,
		SEARCH_FILTER_BOGUS, SEARCH_FILTER_DRM, SEARCH_FILTER_RESTRICTED,
		SEARCH_FILTER_SUSPICIOUS, SEARCH_FILTER_ADULT
	};

	unsigned int nUnion = 0;

	for ( unsigned int nOuter = 0; nOuter < 11u; nOuter++ )
	{
		for ( unsigned int nInner = nOuter + 1; nInner < 11u; nInner++ )
		{
			if ( nBits[ nOuter ] == nBits[ nInner ] ) return false;
		}

		nUnion |= nBits[ nOuter ];
	}

	return nUnion == 0x7FFu;
}

void register_search_filter_mask_smoke_tests( TestSuite& suite )
{
	suite.add_test( "search_filter_mask_persisted_positions",
		test_search_filter_mask_persisted_positions );
	suite.add_test( "search_filter_mask_local_reject_decode",
		test_search_filter_mask_local_reject_decode );
	suite.add_test( "search_filter_mask_round_trip",
		test_search_filter_mask_round_trip );
	suite.add_test( "search_filter_mask_constants_distinct",
		test_search_filter_mask_constants_distinct );
}
