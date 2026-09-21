//
// DlgDonkeyImport.cpp
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
#include "DlgDonkeyImport.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#define new DEBUG_NEW
#endif	// Debug

IMPLEMENT_DYNAMIC(CDonkeyImportDlg, CSkinDialog)

CDonkeyImportDlg* CDonkeyImportDlg::s_pDlg = NULL;

BEGIN_MESSAGE_MAP(CDonkeyImportDlg, CSkinDialog)
	ON_WM_TIMER()
	ON_WM_CLOSE()
	ON_BN_CLICKED(IDC_IMPORT, OnImport)
	ON_BN_CLICKED(IDC_IMPORT_ADD_FOLDER, OnAddFolder)
	ON_BN_CLICKED(IDC_CLOSE, OnHide)
	ON_MESSAGE(WM_ED2K_IMPORT_LOG, OnImportLog)
	ON_MESSAGE(WM_ED2K_IMPORT_REFRESH, OnImportRefresh)
END_MESSAGE_MAP()


/////////////////////////////////////////////////////////////////////////////
// CDonkeyImportDlg dialog

CDonkeyImportDlg::CDonkeyImportDlg(CWnd* pParent /*=NULL*/)
	: CSkinDialog( CDonkeyImportDlg::IDD, pParent )
{
}

CDonkeyImportDlg::~CDonkeyImportDlg()
{
	if ( s_pDlg == this )
		s_pDlg = NULL;
}

BOOL CDonkeyImportDlg::IsOpen()
{
	return s_pDlg != NULL && IsWindow( s_pDlg->GetSafeHwnd() );
}

CDonkeyImportDlg* CDonkeyImportDlg::OpenModeless(CWnd* pParent)
{
	if ( s_pDlg && IsWindow( s_pDlg->GetSafeHwnd() ) )
	{
		s_pDlg->ShowWindow( SW_SHOW );
		s_pDlg->SetForegroundWindow();
		return s_pDlg;
	}

	s_pDlg = new CDonkeyImportDlg( pParent );
	if ( ! s_pDlg->Create( CDonkeyImportDlg::IDD, pParent ) )
	{
		delete s_pDlg;
		s_pDlg = NULL;
		return NULL;
	}

	s_pDlg->ShowWindow( SW_SHOW );
	return s_pDlg;
}

void CDonkeyImportDlg::CloseInstance()
{
	if ( ! s_pDlg )
		return;

	s_pDlg->m_pImporter.Stop();
	s_pDlg->m_pImporter.DetachNotify();
	if ( IsWindow( s_pDlg->GetSafeHwnd() ) )
		s_pDlg->DestroyWindow();
	else
	{
		delete s_pDlg;
		s_pDlg = NULL;
	}
}

void CDonkeyImportDlg::AddFolder(LPCTSTR pszFolder)
{
	m_pImporter.AddFolder( pszFolder );
}

void CDonkeyImportDlg::StartImport()
{
	OnImport();
}

void CDonkeyImportDlg::DoDataExchange(CDataExchange* pDX)
{
	CSkinDialog::DoDataExchange(pDX);

	DDX_Control(pDX, IDC_CLOSE, m_wndClose);
	DDX_Control(pDX, IDCANCEL, m_wndCancel);
	DDX_Control(pDX, IDC_IMPORT, m_wndImport);
	DDX_Control(pDX, IDC_IMPORT_ADD_FOLDER, m_wndAddFolder);
	DDX_Control(pDX, IDC_LOG, m_wndLog);
	DDX_Control(pDX, IDC_IMPORT_OVERALL_PROGRESS, m_wndOverall);
	DDX_Control(pDX, IDC_IMPORT_FILE_PROGRESS, m_wndFile);
	DDX_Control(pDX, IDC_IMPORT_OVERALL_TEXT, m_wndOverallText);
	DDX_Control(pDX, IDC_IMPORT_CURRENT_TEXT, m_wndCurrentText);
	DDX_Control(pDX, IDC_IMPORT_JOB_LIST, m_wndJobs);
}

/////////////////////////////////////////////////////////////////////////////
// CDonkeyImportDlg message handlers

BOOL CDonkeyImportDlg::OnInitDialog()
{
	CSkinDialog::OnInitDialog();

	SkinMe( L"CDonkeyImportDlg", IDR_MAINFRAME );

	CString str;
	m_wndCancel.GetWindowText( str );
	int nPos = str.Find( L'|' );
	if ( nPos > 0 )
	{
		m_sCancel = str.Mid( nPos + 1 );
		m_wndCancel.SetWindowText( str.Left( nPos ) );
	}

	m_wndOverall.SetRange( 0, 100 );
	m_wndFile.SetRange( 0, 100 );

	CString sFile, sState, sProg;
	LoadString( sFile, IDS_ED2K_EPI_COL_FILE );
	LoadString( sState, IDS_ED2K_EPI_COL_STATE );
	LoadString( sProg, IDS_ED2K_EPI_COL_PROGRESS );
	m_wndJobs.InsertColumn( 0, sFile, LVCFMT_LEFT, SCALE( 180 ) );
	m_wndJobs.InsertColumn( 1, sState, LVCFMT_LEFT, SCALE( 110 ) );
	m_wndJobs.InsertColumn( 2, sProg, LVCFMT_RIGHT, SCALE( 60 ) );
	m_wndJobs.SetExtendedStyle( m_wndJobs.GetExtendedStyle() | LVS_EX_FULLROWSELECT | LVS_EX_LABELTIP );

	m_wndClose.ShowWindow( SW_SHOW );

	return TRUE;
}

void CDonkeyImportDlg::OnImport()
{
	if ( m_pImporter.IsThreadAlive() )
		return;

	m_wndImport.EnableWindow( FALSE );
	if ( ! m_sCancel.IsEmpty() )
		m_wndCancel.SetWindowText( m_sCancel );
	m_pImporter.Start( GetSafeHwnd() );
	SetTimer( 1, 500, NULL );
}

void CDonkeyImportDlg::OnAddFolder()
{
	CString strPath( BrowseForFolder( IDS_SELECT_ED2K_TEMP_FOLDER ) );
	if ( strPath.IsEmpty() )
		return;

	m_pImporter.AddFolder( strPath );
	if ( ! m_pImporter.IsThreadAlive() )
		OnImport();
}

void CDonkeyImportDlg::OnCancel()
{
	m_pImporter.Stop();
	ShowWindow( SW_HIDE );
}

void CDonkeyImportDlg::OnHide()
{
	ShowWindow( SW_HIDE );
}

void CDonkeyImportDlg::OnClose()
{
	ShowWindow( SW_HIDE );
}

void CDonkeyImportDlg::PostNcDestroy()
{
	m_pImporter.Stop();
	if ( s_pDlg == this )
		s_pDlg = NULL;
	delete this;
}

void CDonkeyImportDlg::OnTimer(UINT_PTR /*nIDEvent*/)
{
	RefreshJobs();

	if ( ! m_pImporter.IsThreadAlive() )
	{
		KillTimer( 1 );
		m_wndImport.EnableWindow( TRUE );
		m_wndClose.ModifyStyle( 0, BS_DEFPUSHBUTTON );
		m_wndClose.ShowWindow( SW_SHOW );
		m_wndClose.SetFocus();
	}
}

LRESULT CDonkeyImportDlg::OnImportLog(WPARAM /*wParam*/, LPARAM lParam)
{
	CString* pText = reinterpret_cast< CString* >( lParam );
	if ( ! pText )
		return 0;

	int nLen = m_wndLog.GetWindowTextLength();
	m_wndLog.SetSel( nLen, nLen );
	m_wndLog.ReplaceSel( *pText );
	nLen += pText->GetLength();
	m_wndLog.SetSel( nLen, nLen );
	delete pText;
	return 0;
}

LRESULT CDonkeyImportDlg::OnImportRefresh(WPARAM /*wParam*/, LPARAM /*lParam*/)
{
	RefreshJobs();
	return 0;
}

CString CDonkeyImportDlg::StageText(PartialImportStage nStage, PartialImportError nError) const
{
	UINT nID = IDS_ED2K_EPI_STAGE_QUEUED;
	switch ( nStage )
	{
	case PartialImportStage::Scanning: nID = IDS_ED2K_EPI_STAGE_SCAN; break;
	case PartialImportStage::ReadingMetadata: nID = IDS_ED2K_EPI_STAGE_READ; break;
	case PartialImportStage::ValidatingMetadata: nID = IDS_ED2K_EPI_STAGE_VALIDATE; break;
	case PartialImportStage::ResolvingIdentity: nID = IDS_ED2K_EPI_STAGE_IDENTITY; break;
	case PartialImportStage::PreparingTarget: nID = IDS_ED2K_EPI_STAGE_PREPARE; break;
	case PartialImportStage::PlanningRanges: nID = IDS_ED2K_EPI_STAGE_PLAN; break;
	case PartialImportStage::Merging: nID = IDS_ED2K_EPI_STAGE_MERGE; break;
	case PartialImportStage::Verifying: nID = IDS_ED2K_EPI_STAGE_VERIFY; break;
	case PartialImportStage::Saving: nID = IDS_ED2K_EPI_STAGE_SAVE; break;
	case PartialImportStage::Completed: nID = IDS_ED2K_EPI_STAGE_DONE; break;
	case PartialImportStage::NoUsefulData: nID = IDS_ED2K_EPI_STAGE_NO_DATA; break;
	case PartialImportStage::Cancelled: nID = IDS_ED2K_EPI_STAGE_CANCEL; break;
	case PartialImportStage::Failed:
		if ( nError == PartialImportError::AlreadyExists )
			nID = IDS_ED2K_EPI_ALREADY;
		else if ( nError == PartialImportError::DiskSpace )
			nID = IDS_ED2K_EPI_DISK_SPACE;
		else
			nID = IDS_ED2K_EPI_FILE_FAILED;
		break;
	default:
		break;
	}

	CString str;
	LoadString( str, nID );
	str.Trim();
	return str;
}

void CDonkeyImportDlg::RefreshJobs()
{
	int nJobs = 0, nCompleted = 0, nFailed = 0, nCancelled = 0, nOverall = 0, nCurrent = 0;
	CString sCurrent;
	ULONGLONG tLast = 0;
	m_pImporter.GetTotals( nJobs, nCompleted, nFailed, nCancelled, nOverall, sCurrent, nCurrent, tLast );

	m_wndOverall.SetPos( nOverall );
	m_wndFile.SetPos( nCurrent );

	CString sOverall;
	sOverall.Format( L"%i / %i  (%i%%)", nCompleted, nJobs, nOverall );
	m_wndOverallText.SetWindowText( sOverall );

	CString sCur = sCurrent;
	if ( ! sCur.IsEmpty() )
	{
		CString sPct;
		sPct.Format( L"  (%i%%)", nCurrent );
		sCur += sPct;
		if ( tLast )
		{
			const ULONGLONG nIdle = GetTickCount64() - tLast;
			if ( nIdle > 15000 )
			{
				CString sStall;
				sStall.Format( LoadString( IDS_ED2K_EPI_STALLED ), static_cast< unsigned >( nIdle / 1000 ) );
				sCur += L"  ";
				sCur += sStall;
			}
		}
	}
	m_wndCurrentText.SetWindowText( sCur );

	CArray< CEDPartImportJob > oJobs;
	m_pImporter.CopyJobs( oJobs );

	m_wndJobs.SetRedraw( FALSE );
	m_wndJobs.DeleteAllItems();
	for ( int i = 0; i < oJobs.GetCount(); ++i )
	{
		const CEDPartImportJob& oJob = oJobs.GetAt( i );
		const int nItem = m_wndJobs.InsertItem( i, oJob.sDisplayName );
		m_wndJobs.SetItemText( nItem, 1, StageText( oJob.nStage, oJob.nError ) );
		CString sPct;
		sPct.Format( L"%i%%", oJob.nPercent );
		m_wndJobs.SetItemText( nItem, 2, sPct );
	}
	m_wndJobs.SetRedraw( TRUE );
}
