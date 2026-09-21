//
// EDPartImporter.cpp
//
// This file is part of Envy (getenvy.com) © 2016-2018
// Portions copyright Shareaza 2002-2007 and PeerProject 2008-2014
//
// Envy is free software. You may redistribute and/or modify it
// under the terms of the GNU Affero General Public License
// as published by the Free Software Foundation (fsf.org);
// version 3 or later at your option. (AGPLv3)
//
// Envy is distributed in the hope that it will be useful,
// but AS-IS WITHOUT ANY WARRANTY; without even implied warranty
// of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU Affero General Public License 3.0 for details:
// (http://www.gnu.org/licenses/agpl.html)
//

#include "StdAfx.h"
#include "Settings.h"
#include "Envy.h"
#include "EDPartImporter.h"
#include "EDPacket.h"
#include "Transfers.h"
#include "Download.h"
#include "Downloads.h"
#include "DownloadGroups.h"
#include "DownloadTask.h"
#include "FragmentedFile.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#define new DEBUG_NEW
#endif	// Debug


/////////////////////////////////////////////////////////////////////////////
// CEDPartImporter construction

CEDPartImporter::CEDPartImporter()
	: m_hNotify		( NULL )
	, m_nCount		( 0 )
	, m_nFailed		( 0 )
	, m_nCancelled	( 0 )
	, m_nActiveSerID( 0 )
{
}

CEDPartImporter::~CEDPartImporter()
{
	Stop();
}

/////////////////////////////////////////////////////////////////////////////
// CEDPartImporter operations

void CEDPartImporter::AddFolder(LPCTSTR pszFolder)
{
	CQuickLock oLock( m_pSection );
	m_pFolders.AddTail( pszFolder );
}

void CEDPartImporter::Start(HWND hNotify)
{
	if ( IsThreadAlive() )
		return;

	m_hNotify = hNotify;
	BeginThread( "ED Part Importer" );
}

void CEDPartImporter::DetachNotify()
{
	m_hNotify = NULL;
}

void CEDPartImporter::Stop()
{
	m_hNotify = NULL;
	CloseThread();
}

void CEDPartImporter::CopyJobs(CArray< CEDPartImportJob >& oOut) const
{
	CQuickLock oLock( m_pSection );
	oOut.Copy( m_pJobs );
}

void CEDPartImporter::GetTotals(int& nJobs, int& nCompleted, int& nFailed, int& nCancelled,
	int& nOverallPercent, CString& sCurrent, int& nCurrentPercent,
	ULONGLONG& tLastProgress) const
{
	CQuickLock oLock( m_pSection );

	nJobs = static_cast< int >( m_pJobs.GetCount() );
	nCompleted = m_nCount;
	nFailed = m_nFailed;
	nCancelled = m_nCancelled;
	nCurrentPercent = 0;
	tLastProgress = 0;
	sCurrent.Empty();

	std::uint64_t nBytesDone = 0;
	std::uint64_t nBytesTotal = 0;

	for ( int i = 0; i < nJobs; ++i )
	{
		const CEDPartImportJob& oJob = m_pJobs.GetAt( i );
		nBytesDone += oJob.nBytesProcessed;
		nBytesTotal += oJob.nBytesTotal;
		if ( ! PartialImportJobIsTerminal( oJob.nStage ) )
		{
			sCurrent = oJob.sDisplayName;
			nCurrentPercent = oJob.nPercent;
			tLastProgress = oJob.tLastProgress;
		}
	}

	nOverallPercent = PartialImportOverallPercent( nBytesDone, nBytesTotal, nCompleted, nJobs );
}

/////////////////////////////////////////////////////////////////////////////
// CEDPartImporter run

void CEDPartImporter::OnRun()
{
	Message( IDS_ED2K_EPI_START );
	m_nCount = 0;
	m_nFailed = 0;
	m_nCancelled = 0;

	CreateDirectory( Settings.Downloads.IncompletePath );

	for ( ;; )
	{
		CString strFolder;
		{
			CQuickLock oLock( m_pSection );
			if ( m_pFolders.IsEmpty() )
				break;
			strFolder = m_pFolders.RemoveHead();
		}

		if ( ! IsThreadEnabled() )
			break;

		ImportFolder( strFolder );
	}

	Message( IDS_ED2K_EPI_FINISHED, m_nCount );

	if ( m_nCount )
		Downloads.Save();

	NotifyRefresh();
}

/////////////////////////////////////////////////////////////////////////////
// CEDPartImporter import a folder

void CEDPartImporter::ImportFolder(LPCTSTR pszPath)
{
	WIN32_FIND_DATA pFind;
	CString strPath;
	HANDLE hSearch;

	Message( IDS_ED2K_EPI_FOLDER, pszPath );

	strPath.Format( L"%s\\*.part.met", pszPath );
	hSearch = FindFirstFile( strPath, &pFind );
	if ( hSearch == INVALID_HANDLE_VALUE ) return;

	CArray< CString > oNames;
	do
	{
		if ( ! IsThreadEnabled() )
			break;

		if ( pFind.cFileName[0] == '.' ||
		   ( pFind.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ) )
			continue;

		strPath = pFind.cFileName;
		int nPos = strPath.Find( L".part.met" );
		if ( nPos < 1 ) continue;
		oNames.Add( strPath.Left( nPos ) );
	}
	while ( FindNextFile( hSearch, &pFind ) );

	FindClose( hSearch );

	CArray< int > oJobIds;
	{
		CQuickLock oLock( m_pSection );
		for ( int i = 0; i < oNames.GetCount(); ++i )
		{
			CEDPartImportJob oJob;
			oJob.nId = static_cast< int >( m_pJobs.GetCount() ) + 1;
			oJob.sDisplayName = oNames.GetAt( i );
			oJob.sMetPath.Format( L"%s\\%s.part.met", pszPath, (LPCTSTR)oNames.GetAt( i ) );
			oJob.sDataPath.Empty();
			oJob.nStage = PartialImportStage::Queued;
			oJob.nError = PartialImportError::None;
			oJob.nBytesProcessed = 0;
			oJob.nBytesTotal = 0;
			oJob.nPercent = 0;
			oJob.nSerID = 0;
			oJob.tLastProgress = GetTickCount64();
			m_pJobs.Add( oJob );
			oJobIds.Add( static_cast< int >( m_pJobs.GetCount() ) - 1 );
		}
	}

	NotifyRefresh();

	for ( int i = 0; i < oJobIds.GetCount(); ++i )
	{
		if ( ! IsThreadEnabled() )
			break;

		if ( ImportFile( oJobIds.GetAt( i ) ) )
			++m_nCount;
		else if ( IsThreadEnabled() )
		{
			++m_nFailed;
			Message( IDS_ED2K_EPI_FILE_FAILED );
		}
		else
		{
			++m_nCancelled;
			SetJobStage( oJobIds.GetAt( i ), PartialImportStage::Cancelled, PartialImportError::Cancelled );
		}

		NotifyRefresh();
	}
}

/////////////////////////////////////////////////////////////////////////////
// CEDPartImporter import file

BOOL CEDPartImporter::ImportFile(int nJob)
{
	CString strStem;
	CString strMet;
	{
		CQuickLock oLock( m_pSection );
		if ( nJob < 0 || nJob >= m_pJobs.GetCount() )
			return FALSE;
		strStem = m_pJobs[ nJob ].sDisplayName;
		strMet = m_pJobs[ nJob ].sMetPath;
	}

	Message( IDS_ED2K_EPI_FILE_START, (LPCTSTR)strStem );
	SetJobStage( nJob, PartialImportStage::ReadingMetadata );

	CString strFolder = strMet;
	int nSlash = strFolder.ReverseFind( L'\\' );
	if ( nSlash > 0 )
		strFolder = strFolder.Left( nSlash );

	CFile pFile;
	if ( ! pFile.Open( strMet, CFile::modeRead ) )
	{
		Message( IDS_ED2K_EPI_CANT_OPEN_PART, (LPCTSTR)strMet );
		SetJobStage( nJob, PartialImportStage::Failed, PartialImportError::MetadataUnreadable );
		return FALSE;
	}

	BYTE nMagic;
	if ( pFile.Read( &nMagic, 1 ) != 1 )
	{
		SetJobStage( nJob, PartialImportStage::Failed, PartialImportError::Truncated );
		return FALSE;
	}

	if ( nMagic != 0xE0 )
	{
		SetJobStage( nJob, PartialImportStage::Failed, PartialImportError::InvalidFormat );
		return FALSE;
	}

	LONG nDate;
	if ( pFile.Read( &nDate, 4 ) != 4 )
	{
		SetJobStage( nJob, PartialImportStage::Failed, PartialImportError::Truncated );
		return FALSE;
	}

	Hashes::Ed2kHash oED2K;
	if ( pFile.Read( &*oED2K.begin(), oED2K.byteCount ) != oED2K.byteCount )
	{
		SetJobStage( nJob, PartialImportStage::Failed, PartialImportError::Truncated );
		return FALSE;
	}
	oED2K.validate();

	WORD nParts;
	if ( pFile.Read( &nParts, 2 ) != 2 )
	{
		SetJobStage( nJob, PartialImportStage::Failed, PartialImportError::Truncated );
		return FALSE;
	}

	SetJobStage( nJob, PartialImportStage::ResolvingIdentity );

	{
		CQuickLock oTransfersLock( Transfers.m_pSection );

		if ( Downloads.FindByED2K( oED2K ) )
		{
			Message( IDS_ED2K_EPI_ALREADY );
			SetJobStage( nJob, PartialImportStage::Failed, PartialImportError::AlreadyExists );
			return FALSE;
		}
	}

	SetJobStage( nJob, PartialImportStage::ValidatingMetadata );

	CED2K pED2K;
	if ( nParts == 0 )
	{
		pED2K.FromRoot( &oED2K[ 0 ] );
	}
	else if ( nParts > 0 )
	{
		if ( nParts > 8192 )
		{
			SetJobStage( nJob, PartialImportStage::Failed, PartialImportError::InvalidHashset );
			return FALSE;
		}

		const UINT nDigest = sizeof( CMD4::Digest );
		if ( nParts > ( UINT_MAX / nDigest ) )
		{
			SetJobStage( nJob, PartialImportStage::Failed, PartialImportError::InvalidHashset );
			return FALSE;
		}

		UINT len = nDigest * nParts;
		auto_array< CMD4::Digest > pHashset( new CMD4::Digest[ nParts ] );
		if ( pFile.Read( pHashset.get(), len ) != len )
		{
			SetJobStage( nJob, PartialImportStage::Failed, PartialImportError::Truncated );
			return FALSE;
		}

		BOOL bSuccess = pED2K.FromBytes( (BYTE*)pHashset.get(), len );
		if ( ! bSuccess )
		{
			SetJobStage( nJob, PartialImportStage::Failed, PartialImportError::InvalidHashset );
			return FALSE;
		}

		Hashes::Ed2kHash pCheck;
		pED2K.GetRoot( &pCheck[ 0 ] );
		pCheck.validate();
		if ( validAndUnequal( pCheck, oED2K ) )
		{
			SetJobStage( nJob, PartialImportStage::Failed, PartialImportError::InvalidHashset );
			return FALSE;
		}
	}

	if ( ! pED2K.IsAvailable() )
	{
		SetJobStage( nJob, PartialImportStage::Failed, PartialImportError::InvalidHashset );
		return FALSE;
	}

	DWORD nCount;
	if ( pFile.Read( &nCount, 4 ) != 4 )
	{
		SetJobStage( nJob, PartialImportStage::Failed, PartialImportError::Truncated );
		return FALSE;
	}
	if ( nCount > 2048 )
	{
		SetJobStage( nJob, PartialImportStage::Failed, PartialImportError::InvalidFormat );
		return FALSE;
	}

	CMap< int, int, QWORD, QWORD > pGapStart, pGapStop;
	CArray< int > pGapIndex;
	BOOL bPaused = FALSE;
	CString strName, strPartName;
	QWORD nSize = 0;

	while ( nCount-- )
	{
		if ( ! IsThreadEnabled() )
			return FALSE;

		CEDTag pTag;
		if ( ! pTag.Read( &pFile ) )
		{
			SetJobStage( nJob, PartialImportStage::Failed, PartialImportError::Truncated );
			return FALSE;
		}

		if ( pTag.Check( ED2K_FT_FILENAME, ED2K_TAG_STRING ) )
		{
			strName = pTag.m_sValue;
		}
		else if ( pTag.Check( ED2K_FT_PARTFILENAME, ED2K_TAG_STRING ) )
		{
			strPartName = pTag.m_sValue;
		}
		else if ( pTag.Check( ED2K_FT_FILESIZE, ED2K_TAG_INT ) )
		{
			nSize = pTag.m_nValue;
		}
		else if ( pTag.Check( ED2K_FT_STATUS, ED2K_TAG_INT ) )
		{
			bPaused = pTag.m_nValue != 0;
		}
		else if ( pTag.m_nType == ED2K_TAG_INT && pTag.m_sKey.GetLength() > 1 )
		{
			if ( pTag.m_sKey.GetAt( 0 ) == 0x09 )		// Start of gap
			{
				int nPart = 0;
				_stscanf( (LPCTSTR)pTag.m_sKey + 1, L"%i", &nPart );
				pGapStart.SetAt( nPart, pTag.m_nValue );
				pGapIndex.Add( nPart );
			}
			else if ( pTag.m_sKey.GetAt( 0 ) == 0x0A )	// End of gap
			{
				int nPart = 0;
				_stscanf( (LPCTSTR)pTag.m_sKey + 1, L"%i", &nPart );
				pGapStop.SetAt( nPart, pTag.m_nValue );
			}
		}
	}

	if ( strName.IsEmpty() || nSize == SIZE_UNKNOWN || nSize == 0 || pGapStart.IsEmpty() )
	{
		SetJobStage( nJob, PartialImportStage::Failed, PartialImportError::InvalidFormat );
		return FALSE;
	}

	SetJobStage( nJob, PartialImportStage::PlanningRanges );

	Fragments::List oGaps( nSize );
	for ( int nGap = 0; nGap < pGapIndex.GetSize(); nGap++ )
	{
		if ( ! IsThreadEnabled() )
			return FALSE;

		int nPart = pGapIndex.GetAt( nGap );
		QWORD nStart, nStop;
		if ( ! pGapStart.Lookup( nPart, nStart ) )
		{
			SetJobStage( nJob, PartialImportStage::Failed, PartialImportError::InvalidGaps );
			return FALSE;
		}
		if ( ! pGapStop.Lookup( nPart, nStop ) )
		{
			SetJobStage( nJob, PartialImportStage::Failed, PartialImportError::InvalidGaps );
			return FALSE;
		}
		if ( ! PartialImportGapIsValid( nStart, nStop, nSize ) )
		{
			SetJobStage( nJob, PartialImportStage::Failed, PartialImportError::InvalidGaps );
			return FALSE;
		}

		oGaps.insert( Fragments::Fragment( nStart, nStop ) );
	}

	Message( IDS_ED2K_EPI_DETECTED, strName, Settings.SmartVolume( nSize ) );
	SetJobDetail( nJob, strName );
	SetJobProgress( nJob, 0, nSize );

	if ( ! Downloads.IsSpaceAvailable( nSize, Downloads.dlPathIncomplete ) )
	{
		Message( IDS_ED2K_EPI_DISK_SPACE );
		SetJobStage( nJob, PartialImportStage::Failed, PartialImportError::DiskSpace );
		return FALSE;
	}

	if ( ! PartialImportPartNameIsSafe( strPartName ) )
	{
		Message( IDS_ED2K_EPI_PATH_REJECTED, (LPCTSTR)strPartName );
		SetJobStage( nJob, PartialImportStage::Failed, PartialImportError::PathRejected );
		return FALSE;
	}

	CString strData;
	if ( strPartName.IsEmpty() )
		strData.Format( L"%s\\%s.part", (LPCTSTR)strFolder, (LPCTSTR)strStem );
	else
		strData.Format( L"%s\\%s", (LPCTSTR)strFolder, (LPCTSTR)strPartName );

	{
		CQuickLock oLock( m_pSection );
		m_pJobs[ nJob ].sDataPath = strData;
		m_pJobs[ nJob ].sDisplayName = strName;
	}

	CFile pData;
	if ( ! pData.Open( strData, CFile::modeRead ) )
	{
		Message( IDS_ED2K_EPI_PART_MISSING, (LPCTSTR)strData );
		SetJobStage( nJob, PartialImportStage::Failed, PartialImportError::PartMissing );
		return FALSE;
	}

	CFileStatus pStatus;
	if ( ! pData.GetStatus( pStatus ) )
	{
		SetJobStage( nJob, PartialImportStage::Failed, PartialImportError::IoError );
		return FALSE;
	}

	pData.Close();

	struct tm ptmTemp = {};
	if ( nDate > mktime( pStatus.m_mtime.GetLocalTm( &ptmTemp ) ) )
	{
		Message( IDS_ED2K_EPI_FILE_OLD );
		SetJobStage( nJob, PartialImportStage::Failed, PartialImportError::SourceNewerThanMet );
		return FALSE;
	}

	SetJobStage( nJob, PartialImportStage::PreparingTarget );

	DWORD nSerID = 0;
	{
		CQuickLock oTransfersLock( Transfers.m_pSection );

		CDownload* pDownload = Downloads.Add();
		if ( ! pDownload )
		{
			SetJobStage( nJob, PartialImportStage::Failed, PartialImportError::IoError );
			return FALSE;
		}

		pDownload->m_sName			= strName;
		pDownload->m_nSize			= nSize;
		pDownload->m_oED2K			= oED2K;
		pDownload->m_bED2KTrusted	= true;
		pDownload->Pause();

		BYTE* pHashset = NULL;
		DWORD nHashset = 0;
		if ( pED2K.ToBytes( &pHashset, &nHashset ) )
		{
			pDownload->SetHashset( pHashset, nHashset );
			GlobalFree( pHashset );
		}

		pDownload->Save();
		DownloadGroups.Link( pDownload );
		nSerID = pDownload->m_nSerID;

		{
			CQuickLock oLock( m_pSection );
			m_pJobs[ nJob ].nSerID = nSerID;
			m_nActiveSerID = nSerID;
		}

		Message( IDS_ED2K_EPI_COPY_START, (LPCTSTR)strData, (LPCTSTR)pDownload->m_sPath );

		pDownload->MergeFile( strData, FALSE, &oGaps );
	}

	SetJobStage( nJob, PartialImportStage::Merging );

	const BOOL bMergeOk = WaitForMerge( nSerID, nJob );
	if ( ! IsThreadEnabled() )
	{
		SetJobStage( nJob, PartialImportStage::Cancelled, PartialImportError::Cancelled );
		return FALSE;
	}
	if ( ! bMergeOk )
	{
		SetJobStage( nJob, PartialImportStage::Failed, PartialImportError::IoError );
		return FALSE;
	}

	SetJobStage( nJob, PartialImportStage::Saving );

	{
		CQuickLock oTransfersLock( Transfers.m_pSection );
		CDownload* pDownload = Downloads.FindBySID( nSerID );
		if ( pDownload )
		{
			if ( ! bPaused )
				pDownload->Resume();
			pDownload->Save();

			Message( IDS_ED2K_EPI_COPY_FINISHED );
			Message( IDS_ED2K_EPI_FILE_CREATED,
				Settings.SmartVolume( pDownload->GetVolumeRemaining() ) );
		}
	}

	SetJobProgress( nJob, nSize, nSize );
	SetJobStage( nJob, PartialImportStage::Completed );
	m_nActiveSerID = 0;
	return TRUE;
}

BOOL CEDPartImporter::WaitForMerge(DWORD nSerID, int nJob)
{
	while ( IsThreadEnabled() )
	{
		bool bBusy = false;
		float fProgress = 0.0f;

		{
			CSingleLock oLock( &Transfers.m_pSection, FALSE );
			if ( ! oLock.Lock( 50 ) )
			{
				Doze( 50 );
				continue;
			}

			CDownload* pDownload = Downloads.FindBySID( nSerID );
			if ( ! pDownload )
				return false;

			if ( pDownload->GetTaskType() == dtaskMergeFile )
			{
				bBusy = true;
				fProgress = pDownload->GetProgress();
			}
		}

		if ( ! bBusy )
			return true;

		std::uint64_t nTotal = 0;
		{
			CQuickLock oLock( m_pSection );
			if ( nJob >= 0 && nJob < m_pJobs.GetCount() )
				nTotal = m_pJobs[ nJob ].nBytesTotal;
		}

		const int nPercent = ( fProgress < 0.0f ) ? 0 : ( fProgress > 100.0f ? 100 : static_cast< int >( fProgress ) );
		const std::uint64_t nDone = ( nTotal * static_cast< std::uint64_t >( nPercent ) ) / 100ull;
		SetJobProgress( nJob, nDone, nTotal );
		NotifyRefresh();
		Doze( 200 );
	}

	AbortActiveMerge();
	return false;
}

BOOL CEDPartImporter::AbortActiveMerge()
{
	DWORD nSerID = 0;
	{
		CQuickLock oLock( m_pSection );
		nSerID = m_nActiveSerID;
	}
	if ( ! nSerID )
		return TRUE;

	CSingleLock oLock( &Transfers.m_pSection, FALSE );
	if ( ! oLock.Lock( 500 ) )
		return FALSE;

	if ( CDownload* pDownload = Downloads.FindBySID( nSerID ) )
		pDownload->CancelTask();

	return TRUE;
}

void CEDPartImporter::SetJobStage(int nJob, PartialImportStage nStage, PartialImportError nError)
{
	CQuickLock oLock( m_pSection );
	if ( nJob < 0 || nJob >= m_pJobs.GetCount() )
		return;
	m_pJobs[ nJob ].nStage = nStage;
	m_pJobs[ nJob ].nError = nError;
	m_pJobs[ nJob ].tLastProgress = GetTickCount64();
}

void CEDPartImporter::SetJobProgress(int nJob, std::uint64_t nDone, std::uint64_t nTotal)
{
	CQuickLock oLock( m_pSection );
	if ( nJob < 0 || nJob >= m_pJobs.GetCount() )
		return;
	m_pJobs[ nJob ].nBytesProcessed = nDone;
	m_pJobs[ nJob ].nBytesTotal = nTotal;
	m_pJobs[ nJob ].nPercent = PartialImportPercent( nDone, nTotal );
	m_pJobs[ nJob ].tLastProgress = GetTickCount64();
}

void CEDPartImporter::SetJobDetail(int nJob, LPCTSTR pszDetail)
{
	CQuickLock oLock( m_pSection );
	if ( nJob < 0 || nJob >= m_pJobs.GetCount() )
		return;
	m_pJobs[ nJob ].sDetail = pszDetail;
}

void CEDPartImporter::NotifyRefresh()
{
	HWND h = m_hNotify;
	if ( h && IsWindow( h ) )
		PostMessage( h, WM_ED2K_IMPORT_REFRESH, 0, 0 );
}

void CEDPartImporter::Message(UINT nMessageID, ...)
{
	HWND h = m_hNotify;
	if ( ! h || ! IsWindow( h ) )
		return;

	const DWORD nBufferLength = 2048;
	auto_array< TCHAR > szBuffer( new TCHAR[ nBufferLength ] );
	ZeroMemory( szBuffer.get(), nBufferLength * sizeof( TCHAR ) );
	CString strFormat;
	va_list pArgs;

	LoadString( strFormat, nMessageID );
	va_start( pArgs, nMessageID );
	_vsntprintf_s( szBuffer.get(), nBufferLength, nBufferLength - 8, strFormat, pArgs );
	_tcscat( szBuffer.get(), L"\r\n" );
	va_end( pArgs );

	CString* pText = new CString( szBuffer.get() );
	if ( ! PostMessage( h, WM_ED2K_IMPORT_LOG, 0, reinterpret_cast< LPARAM >( pText ) ) )
		delete pText;
}
