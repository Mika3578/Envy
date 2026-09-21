//
// test_partial_import_workflow_smoke.cpp
//
// Portable tests for partial-import job semantics and progress math.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
// License: GNU Affero General Public License v3.0 (AGPLv3)
//

#include "test_framework.h"
#include "../Envy/PartialImportTypes.h"

static bool test_percent_bounds()
{
	if ( PartialImportPercent( 0, 0 ) != 0 )
		return false;
	if ( PartialImportPercent( 0, 100 ) != 0 )
		return false;
	if ( PartialImportPercent( 50, 100 ) != 50 )
		return false;
	if ( PartialImportPercent( 100, 100 ) != 100 )
		return false;
	if ( PartialImportPercent( 200, 100 ) != 100 )
		return false;
	// Large QWORD files must not overflow.
	const std::uint64_t nBig = 0x100000000ull;	// 4 GiB
	if ( PartialImportPercent( nBig / 2, nBig ) != 50 )
		return false;
	return true;
}

static bool test_overall_prefers_bytes()
{
	// File-count 1/2 would be 50%; bytes 10/100 is 10%.
	return PartialImportOverallPercent( 10, 100, 1, 2 ) == 10
		&& PartialImportOverallPercent( 0, 0, 1, 4 ) == 25;
}

static bool test_progress_monotone()
{
	return PartialImportProgressIsMonotone( 0, 1 )
		&& PartialImportProgressIsMonotone( 99, 100 )
		&& ! PartialImportProgressIsMonotone( 50, 49 )
		&& ! PartialImportProgressIsMonotone( -1, 0 );
}

static bool test_gap_validation()
{
	return PartialImportGapIsValid( 0, 100, 100 )
		&& ! PartialImportGapIsValid( 100, 100, 100 )
		&& ! PartialImportGapIsValid( 80, 40, 100 )
		&& ! PartialImportGapIsValid( 0, 101, 100 )
		&& ! PartialImportGapIsValid( 0, 10, 0 );
}

static bool test_part_name_safety()
{
	return PartialImportPartNameIsSafe( L"" )
		&& PartialImportPartNameIsSafe( L"file.part" )
		&& ! PartialImportPartNameIsSafe( L"..\\secret.part" )
		&& ! PartialImportPartNameIsSafe( L"C:\\abs.part" )
		&& ! PartialImportPartNameIsSafe( L"sub\\file.part" )
		&& ! PartialImportPartNameIsSafe( L"\\\\unc\\share" );
}

static bool test_completed_requires_merge_finish()
{
	return PartialImportMayMarkCompleted( false, false )
		&& ! PartialImportMayMarkCompleted( true, false )
		&& PartialImportMayMarkCompleted( true, true )
		&& PartialImportJobIsTerminal( PartialImportStage::Completed )
		&& ! PartialImportJobIsTerminal( PartialImportStage::Merging )
		&& PartialImportJobIsSuccess( PartialImportStage::NoUsefulData );
}

void register_partial_import_workflow_smoke_tests(TestSuite& suite)
{
	suite.add_test( "partial_import_percent_bounds", test_percent_bounds );
	suite.add_test( "partial_import_overall_prefers_bytes", test_overall_prefers_bytes );
	suite.add_test( "partial_import_progress_monotone", test_progress_monotone );
	suite.add_test( "partial_import_gap_validation", test_gap_validation );
	suite.add_test( "partial_import_part_name_safety", test_part_name_safety );
	suite.add_test( "partial_import_completed_after_merge", test_completed_requires_merge_finish );
}
