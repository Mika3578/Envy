//
// EDPartImporter.h
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

#pragma once

#include "ThreadImpl.h"
#include "PartialImportTypes.h"

#define WM_ED2K_IMPORT_LOG		( WM_APP + 41 )
#define WM_ED2K_IMPORT_REFRESH	( WM_APP + 42 )

class CDownload;


struct CEDPartImportJob
{
	int					nId;
	CString				sDisplayName;
	CString				sMetPath;
	CString				sDataPath;
	PartialImportStage	nStage;
	PartialImportError	nError;
	std::uint64_t		nBytesProcessed;
	std::uint64_t		nBytesTotal;
	int					nPercent;
	DWORD				nSerID;
	ULONGLONG			tLastProgress;
	CString				sDetail;
};


class CEDPartImporter : public CThreadImpl
{
public:
	CEDPartImporter();
	virtual ~CEDPartImporter();

public:
	void	AddFolder(LPCTSTR pszFolder);
	void	Start(HWND hNotify);
	void	Stop();
	void	DetachNotify();

	void	CopyJobs(CArray< CEDPartImportJob >& oOut) const;
	void	GetTotals(int& nJobs, int& nCompleted, int& nFailed, int& nCancelled,
				int& nOverallPercent, CString& sCurrent, int& nCurrentPercent,
				ULONGLONG& tLastProgress) const;

protected:
	mutable CCriticalSection	m_pSection;
	CList< CString >			m_pFolders;
	CArray< CEDPartImportJob >	m_pJobs;
	HWND						m_hNotify;
	int							m_nCount;
	int							m_nFailed;
	int							m_nCancelled;
	DWORD						m_nActiveSerID;

	void	OnRun();
	void	ImportFolder(LPCTSTR pszPath);
	BOOL	ImportFile(int nJob);
	void	SetJobStage(int nJob, PartialImportStage nStage, PartialImportError nError = PartialImportError::None);
	void	SetJobProgress(int nJob, std::uint64_t nDone, std::uint64_t nTotal);
	void	SetJobDetail(int nJob, LPCTSTR pszDetail);
	void	Message(UINT nMessageID, ...);
	void	NotifyRefresh();
	BOOL	WaitForMerge(DWORD nSerID, int nJob);
	BOOL	AbortActiveMerge();
};
