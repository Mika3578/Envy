//
// PageSettingsRemote.cpp
//
// This file is part of Envy (getenvy.com) ù 2016-2018
// Portions copyright Shareaza 2002-2007 and PeerProject 2008-2016
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
#include "PageSettingsRemote.h"
#include "Colors.h"
#include "Network.h"
#include "Handshakes.h"
#include "QRCode.h"
#include "QRCode.cpp"	// Why does this need to be included?
#include "RemoteSecurity.h"

#include <string>

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#define new DEBUG_NEW
#endif	// Debug

IMPLEMENT_DYNAMIC(CRemoteSettingsPage, CSettingsPage)

BEGIN_MESSAGE_MAP(CRemoteSettingsPage, CSettingsPage)
	ON_BN_CLICKED(IDC_REMOTE_ENABLE,  &CRemoteSettingsPage::OnBnClickedRemoteEnable)
	ON_EN_CHANGE(IDC_REMOTE_USERNAME, &CRemoteSettingsPage::OnBnClickedRemoteEnable)
	ON_EN_CHANGE(IDC_REMOTE_PASSWORD, &CRemoteSettingsPage::OnNewPassword)
	ON_WM_CTLCOLOR()
	ON_WM_SETCURSOR()
	ON_WM_LBUTTONUP()
END_MESSAGE_MAP()


//////////////////////////////////////////////////////////////////////////////
// CRemoteSettingsPage construction

CRemoteSettingsPage::CRemoteSettingsPage()
	: CSettingsPage( CRemoteSettingsPage::IDD )
	, m_bEnable( FALSE )
	, m_bPasswordDirty( FALSE )
{
}

CRemoteSettingsPage::~CRemoteSettingsPage()
{
}

void CRemoteSettingsPage::DoDataExchange(CDataExchange* pDX)
{
	CSettingsPage::DoDataExchange(pDX);
	DDX_Check(pDX, IDC_REMOTE_ENABLE, m_bEnable);
	DDX_Control(pDX, IDC_REMOTE_URL, m_wndURL);
	DDX_Control(pDX, IDC_REMOTE_QRCODE, m_wndQRCode);
	DDX_Control(pDX, IDC_REMOTE_USERNAME, m_wndUsername);
	DDX_Control(pDX, IDC_REMOTE_PASSWORD, m_wndPassword);
	DDX_Text(pDX, IDC_REMOTE_USERNAME, m_sUsername);
	DDX_Text(pDX, IDC_REMOTE_PASSWORD, m_sPassword);
}

//////////////////////////////////////////////////////////////////////////////
// CRemoteSettingsPage message handlers

BOOL CRemoteSettingsPage::OnInitDialog()
{
	CSettingsPage::OnInitDialog();

	m_bEnable	= m_bOldEnable   = Settings.Remote.Enable;
	m_sUsername	= m_sOldUsername = Settings.Remote.Username;
				  m_sOldPassword = Settings.Remote.Password;

	if ( ! m_sOldPassword.IsEmpty() ) m_sPassword = L"      ";

	UpdateData( FALSE );

	return TRUE;
}

void CRemoteSettingsPage::OnNewPassword()
{
	UpdateData();

	if ( m_sPassword.GetLength() < 2 )		// Password too short
	{
		m_bPasswordDirty = FALSE;
		Settings.Remote.Password = m_sOldPassword;
	}
	else if ( m_sPassword == L"      " )	// Password hasn't been edited
	{
		m_bPasswordDirty = FALSE;
		Settings.Remote.Password = m_sOldPassword;
	}
	else
	{
		// Keep prior at-rest hash until Apply/OK ù PBKDF2 is too costly for EN_CHANGE
		m_bPasswordDirty = TRUE;
		Settings.Remote.Password = m_sOldPassword;
	}

	OnBnClickedRemoteEnable();
}

BOOL CRemoteSettingsPage::CommitRemotePassword()
{
	if ( ! m_bPasswordDirty )
		return TRUE;

	UpdateData();
	if ( m_sPassword.GetLength() < 2 || m_sPassword == L"      " )
	{
		m_bPasswordDirty = FALSE;
		Settings.Remote.Password = m_sOldPassword;
		return TRUE;
	}

	CW2A utf8( m_sPassword, CP_UTF8 );
	std::string hashOutput;
	if ( ! CRemoteSecurity::HashPassword( std::string( utf8 ), hashOutput ) )
	{
		Settings.Remote.Password = m_sOldPassword;
		return FALSE;
	}

	Settings.Remote.Password = CString( hashOutput.c_str() );
	m_bPasswordDirty = FALSE;
	return TRUE;
}

void CRemoteSettingsPage::OnBnClickedRemoteEnable()
{
	UpdateData();

	if ( m_sUsername.FindOneOf( L"\\\"/?&=") >= 0 )
		m_sUsername.Empty();

	Settings.Remote.Enable		= m_bEnable != FALSE && ! m_sUsername.IsEmpty();
	Settings.Remote.Username	= m_sUsername;

	m_wndUsername.EnableWindow( m_bEnable );
	m_wndPassword.EnableWindow( m_bEnable );

	CString strURL;
	const BOOL bHasPassword = m_bPasswordDirty || ! Settings.Remote.Password.IsEmpty();

	if ( m_bEnable && ! m_sUsername.IsEmpty() && bHasPassword )
	{
		if ( Network.IsListening() )
		{
			strURL = L"http://" + Network.m_sAddress + L"/remote";
			m_wndURL.EnableWindow( TRUE );
		}
		else if ( Handshakes.IsValid() && Network.m_pHost.sin_port != 0 )
		{
			strURL.Format( L"http://localhost:%hu/remote",
				ntohs( Network.m_pHost.sin_port ) );
			m_wndURL.EnableWindow( TRUE );
		}
		else
		{
			LoadString( strURL, IDS_REMOTE_UNAVAILABLE );
			m_wndURL.EnableWindow( FALSE );
		}
	}
	else if ( m_bEnable )
	{
		strURL = Network.m_sAddress + L"  -  " + LoadString( IDS_REMOTE_ENABLED );
		m_wndURL.EnableWindow( FALSE );
	}
	else
	{
		LoadString( strURL, IDS_REMOTE_DISABLED );
		m_wndURL.EnableWindow( FALSE );
	}

	m_wndURL.SetWindowText( strURL );

	if ( m_bEnable && strURL[0] == L'h' && ! StartsWith( strURL, _P( L"http://localhost" ) ) )	// http:
	{
		CString strToken = L"/?username=" + m_sUsername;
		if ( strURL.GetLength() + strToken.GetLength() < 53 )
			strURL += strToken;
		QREncode.UpdateRemote( strURL );
		m_wndQRCode.SetBitmap( (HBITMAP)QREncode.m_bmRemote.m_hObject );
	}
	else // Disabled
	{
		m_wndQRCode.SetBitmap( Skin.LoadBitmap( IDR_QRCODE ) );
	}
}

HBRUSH CRemoteSettingsPage::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	HBRUSH hbr = CSettingsPage::OnCtlColor( pDC, pWnd, nCtlColor );

	if ( pWnd == &m_wndURL && m_wndURL.IsWindowEnabled() )
	{
		pDC->SelectObject( &theApp.m_gdiFontLine );
		pDC->SetTextColor( Colors.m_crTextLink );
	}

	return hbr;
}

BOOL CRemoteSettingsPage::OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message)
{
	if ( m_wndURL.IsWindowEnabled() )
	{
		CPoint point;
		GetCursorPos( &point );
		CRect rect;
		m_wndURL.GetWindowRect( &rect );

		if ( rect.PtInRect( point ) )
		{
			SetCursor( AfxGetApp()->LoadCursor( IDC_HAND ) );
			return TRUE;
		}
	}

	return CSettingsPage::OnSetCursor( pWnd, nHitTest, message );
}

void CRemoteSettingsPage::OnLButtonUp(UINT nFlags, CPoint point)
{
	if ( m_wndURL.IsWindowEnabled() )
	{
		CRect rect;
		m_wndURL.GetWindowRect( &rect );
		ScreenToClient( &rect );

		if ( rect.PtInRect( point ) )
		{
			CString strURL;
			m_wndURL.GetWindowText( strURL );
			strURL += L"/?username=" + m_sUsername;
			ShellExecute( GetSafeHwnd(), NULL, strURL, NULL, NULL, SW_SHOWNORMAL );
		}
	}

	CSettingsPage::OnLButtonUp( nFlags, point );
}

void CRemoteSettingsPage::OnOK()
{
	CommitRemotePassword();
	CSettingsPage::OnOK();
}

void CRemoteSettingsPage::OnCancel()
{
	m_bPasswordDirty = FALSE;
	Settings.Remote.Enable		= m_bOldEnable != FALSE;
	Settings.Remote.Username	= m_sOldUsername;
	Settings.Remote.Password	= m_sOldPassword;

	CSettingsPage::OnCancel();
}

void CRemoteSettingsPage::OnSkinChange()
{
	if ( ! IsWindow( GetSafeHwnd() ) )
		return;		// Page not created yet

	CSettingsPage::OnSkinChange();

	OnBnClickedRemoteEnable();
}
