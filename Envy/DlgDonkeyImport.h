//
// DlgDonkeyImport.h
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

#include "DlgSkinDialog.h"
#include "EDPartImporter.h"


class CDonkeyImportDlg : public CSkinDialog
{
	DECLARE_DYNAMIC(CDonkeyImportDlg)

public:
	CDonkeyImportDlg(CWnd* pParent = NULL);
	virtual ~CDonkeyImportDlg();

	enum { IDD = IDD_DONKEY_IMPORT };

	static CDonkeyImportDlg* OpenModeless(CWnd* pParent);
	static void CloseInstance();
	static BOOL IsOpen();

	void	AddFolder(LPCTSTR pszFolder);
	void	StartImport();

	CEDPartImporter	m_pImporter;

public:
	CButton			m_wndClose;
	CButton			m_wndCancel;
	CButton			m_wndImport;
	CButton			m_wndAddFolder;
	CEdit			m_wndLog;
	CProgressCtrl	m_wndOverall;
	CProgressCtrl	m_wndFile;
	CStatic			m_wndOverallText;
	CStatic			m_wndCurrentText;
	CListCtrl		m_wndJobs;

	CString	m_sCancel;

protected:
	static CDonkeyImportDlg* s_pDlg;
	void	RefreshJobs();
	CString	StageText(PartialImportStage nStage, PartialImportError nError) const;

protected:
	virtual void DoDataExchange(CDataExchange* pDX);
	virtual void OnCancel();
	virtual void PostNcDestroy();

	virtual BOOL OnInitDialog();
	afx_msg void OnClose();
	afx_msg void OnHide();
	afx_msg void OnImport();
	afx_msg void OnAddFolder();
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	afx_msg LRESULT OnImportLog(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnImportRefresh(WPARAM wParam, LPARAM lParam);

	DECLARE_MESSAGE_MAP()
};
