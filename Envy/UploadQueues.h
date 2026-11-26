//
// UploadQueues.h
//
// This file is part of Envy (getenvy.com) � 2016-2018
// Portions copyright Shareaza 2002-2007 and PeerProject 2008-2010
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

#pragma once

class CUploadQueue;
class CUploadTransfer;
class CLibraryFile;
class CDownload;

// Explicit states for CUploadQueues::GetPosition(). Transient lock contention
// is reported separately from a dead queue so ranking callers can retry on
// their next periodic pass instead of dropping a legitimate upload client.
// Callers that do not need the distinction keep the historical int result:
// a non-negative queue position, or -1 for any failure state.
enum QueuePositionState
{
	qpsReady,         // Queue position is valid
	qpsTransientBusy, // A bounded lock wait timed out; retry later
	qpsNoQueue,       // No valid queue tracks this upload
	qpsShutdown       // Envy is closing; teardown owns the transfer
};

class CUploadQueues
{
public:
	CUploadQueues();
	virtual ~CUploadQueues();

public:
	mutable CMutexEx	m_pSection;
	CUploadQueue*		m_pTorrentQueue;
	CUploadQueue*		m_pHistoryQueue;

	BOOL	Enqueue(CUploadTransfer* pUpload, BOOL bForce = FALSE);
	BOOL	Dequeue(CUploadTransfer* pUpload);
	BOOL	StealPosition(CUploadTransfer* pTarget, CUploadTransfer* pSource);
	int GetPosition(CUploadTransfer* pUpload, BOOL bStart, QueuePositionState* pState = NULL);

	void			Delete(CUploadQueue* pQueue);
	BOOL			Reorder(CUploadQueue* pQueue, CUploadQueue* pBefore);
	CUploadQueue*	Create(LPCTSTR pszName = NULL, BOOL bTop = FALSE);
	CUploadQueue*	SelectQueue(PROTOCOLID nProtocol, CLibraryFile const * const pFile);
	CUploadQueue*	SelectQueue(PROTOCOLID nProtocol, CDownload const * const pFile);
	CUploadQueue*	SelectQueue(PROTOCOLID nProtocol, LPCTSTR pszName, QWORD nSize, DWORD nFileState, LPCTSTR pszShareTags = NULL);

	DWORD	GetTotalBandwidthPoints(BOOL ActiveOnly = FALSE);
//	DWORD	GetQueueCapacity();
//	DWORD	GetQueuedCount();
//	DWORD	GetQueueRemaining();
//	DWORD	GetTransferCount();
	BOOL	IsTransferAvailable();
	DWORD	GetMinimumDonkeyBandwidth();
	DWORD	GetCurrentDonkeyBandwidth();
	BOOL	CanUpload(PROTOCOLID nProtocol, CLibraryFile const * const pFile, BOOL bCanQueue = FALSE );	// Can this file be uploaded with the current queue setup?
//	DWORD	QueueRank(PROTOCOLID nProtocol, CLibraryFile const * const pFile );	// What queue position would this file be in? Unused.

	void	Clear();
	BOOL	Load();
	BOOL	Save();
	void	CreateDefault();
	void	Validate();

// Inline Access
	inline POSITION GetIterator() const
	{
		ASSUME_LOCK( m_pSection );
		return m_pList.GetHeadPosition();
	}

	inline CUploadQueue* GetNext(POSITION& pos) const
	{
		ASSUME_LOCK( m_pSection );
		return m_pList.GetNext( pos );
	}

	inline INT_PTR GetCount() const
	{
		CQuickLock oLock( m_pSection );
		return m_pList.GetCount();
	}

	inline bool Check(CUploadQueue* pQueue) const
	{
		CQuickLock oLock( m_pSection );
		if ( pQueue == NULL ) return FALSE;
		return m_pList.Find( pQueue ) != NULL;
	}

	inline BOOL	IsDonkeyRatioActive() const
	{
		return ( m_bDonkeyLimited );
	}

protected:
	volatile LONG m_nContentionEvents;  // Deferred position lookups (Interlocked)
	volatile LONG m_tLastContentionLog; // GetTickCount of last contention log (Interlocked)

	CList< CUploadQueue* >	m_pList;
	BOOL					m_bDonkeyLimited;

	void LogContention(CUploadTransfer* pUpload);
	void	Serialize(CArchive& ar);
};

extern CUploadQueues UploadQueues;
