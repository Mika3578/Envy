//
// PartialImportTypes.h
//
// Portable helpers for ED2K/Shareaza partial-import jobs.
// No MFC types: keep this header usable from EnvyTests.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
// License: GNU Affero General Public License v3.0 (AGPLv3)
//

#pragma once

#include <cstdint>
#include <cstddef>
#include <cwchar>

enum class PartialImportStage : int
{
	Queued = 0,
	Scanning,
	ReadingMetadata,
	ValidatingMetadata,
	ResolvingIdentity,
	PreparingTarget,
	PlanningRanges,
	Merging,
	Verifying,
	Saving,
	Completed,
	NoUsefulData,
	Failed,
	Cancelled
};

enum class PartialImportError : int
{
	None = 0,
	AlreadyExists,
	MetadataUnreadable,
	InvalidFormat,
	Truncated,
	InvalidHashset,
	InvalidGaps,
	PartMissing,
	PathRejected,
	DiskSpace,
	SourceNewerThanMet,
	IoError,
	Cancelled,
	IdentityConflict,
	NoUsefulData
};

struct PartialImportProgress
{
	std::uint64_t bytesProcessed;
	std::uint64_t bytesTotal;
};

inline int PartialImportPercent(std::uint64_t nProcessed, std::uint64_t nTotal) noexcept
{
	if ( nTotal == 0 )
		return 0;
	if ( nProcessed >= nTotal )
		return 100;
	const double f = ( 100.0 * static_cast< double >( nProcessed ) ) / static_cast< double >( nTotal );
	if ( f < 0.0 )
		return 0;
	if ( f > 100.0 )
		return 100;
	return static_cast< int >( f );
}

inline int PartialImportOverallPercent(std::uint64_t nBytesDone, std::uint64_t nBytesTotal,
	int nFilesDone, int nFilesTotal) noexcept
{
	if ( nBytesTotal > 0 )
		return PartialImportPercent( nBytesDone, nBytesTotal );
	return PartialImportPercent( static_cast< std::uint64_t >( nFilesDone < 0 ? 0 : nFilesDone ),
		static_cast< std::uint64_t >( nFilesTotal < 0 ? 0 : nFilesTotal ) );
}

inline bool PartialImportProgressIsMonotone(int nPrevious, int nNext) noexcept
{
	if ( nPrevious < 0 || nNext < 0 || nPrevious > 100 || nNext > 100 )
		return false;
	return nNext >= nPrevious;
}

inline bool PartialImportGapIsValid(std::uint64_t nStart, std::uint64_t nStop, std::uint64_t nSize) noexcept
{
	if ( nSize == 0 )
		return false;
	if ( nStart >= nSize )
		return false;
	if ( nStop > nSize )
		return false;
	if ( nStop <= nStart )
		return false;
	return true;
}

// Reject path injection in ED2K_FT_PARTFILENAME. Only a relative file name
// (no separators, no "..", no drive/UNC) is accepted.
inline bool PartialImportPartNameIsSafe(const wchar_t* pszName) noexcept
{
	if ( pszName == nullptr || pszName[ 0 ] == L'\0' )
		return true;	// empty → importer uses "<stem>.part"

	if ( pszName[ 0 ] == L'\\' || pszName[ 0 ] == L'/' )
		return false;

	for ( const wchar_t* p = pszName; *p; ++p )
	{
		if ( *p == L'\\' || *p == L'/' || *p == L':' || *p == L'\0' )
			return false;
		if ( *p == L'.' && p[ 1 ] == L'.' )
			return false;
	}

	if ( wcsstr( pszName, L":" ) != nullptr )
		return false;

	return true;
}

inline bool PartialImportJobIsTerminal(PartialImportStage nStage) noexcept
{
	return nStage == PartialImportStage::Completed
		|| nStage == PartialImportStage::NoUsefulData
		|| nStage == PartialImportStage::Failed
		|| nStage == PartialImportStage::Cancelled;
}

inline bool PartialImportJobIsSuccess(PartialImportStage nStage) noexcept
{
	return nStage == PartialImportStage::Completed
		|| nStage == PartialImportStage::NoUsefulData;
}

// Historical Shareaza/Envy bug: "copy finished" was logged before MergeFile().
// Completed must not be claimed until the merge task itself has finished.
inline bool PartialImportMayMarkCompleted(bool bMergeStarted, bool bMergeFinished) noexcept
{
	if ( ! bMergeStarted )
		return true;	// no payload copy required
	return bMergeFinished;
}
