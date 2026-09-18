//
// Firewall.h
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

// CFirewall wraps Windows Firewall with Advanced Security (WFAS / INetFwPolicy2).
// OS target is Windows 10 1809+; legacy INetFwMgr is not used (#166 / D-009 P1).

#pragma once

#include <netfw.h>

class CFirewall
{
public:
	CFirewall();
	~CFirewall();

public:
	CComPtr< INetFwPolicy2 >	Policy2;
	CComPtr< INetFwRules >		Rules;
	CComPtr< INetFwRule >		Rule;	// Scratch for Item / create paths

	BOOL Init();
	BOOL AddProgram( const CString& path, const CString& name );
	BOOL RemoveProgram( const CString& path );
	BOOL SetupService( NET_FW_SERVICE_TYPE service );
	BOOL SetupProgram( const CString& path, const CString& name, BOOL bRemove = FALSE );
	BOOL EnableService( NET_FW_SERVICE_TYPE service );
	BOOL EnableProgram( const CString& path );
	BOOL IsServiceEnabled( NET_FW_SERVICE_TYPE service, BOOL* enabled );
	BOOL IsProgramEnabled( const CString& path, BOOL* enabled );
	BOOL IsProgramListed( const CString& path, BOOL* listed );
	BOOL AreExceptionsAllowed() const;

private:
	BOOL FindRuleByApplication( const CString& path, INetFwRule** ppRule ) const;
	static CString UPnPRuleGroupName();
};
