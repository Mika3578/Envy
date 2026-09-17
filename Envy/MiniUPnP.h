//
// MiniUPnP.h
//
// This file is part of Envy (getenvy.com) ù 2016-2018
// Portions copyright Shareaza 2014 and PeerProject 2014
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

#include "UPnP.h"
#include "ThreadImpl.h"

class CMiniUPnP : public CUPnP, public CThreadImpl
{
public:
	CMiniUPnP();
	virtual ~CMiniUPnP();

public:
	virtual void DeletePorts();
	virtual void StartDiscovery();
	virtual void StopAsyncFind();
	virtual bool IsAsyncFindRunning();

protected:
	WORD		m_nExternalTCPPort;
	WORD		m_nExternalUDPPort;
	CStringA	m_sControlURL;
	CStringA	m_sServiceType;
	CStringA	m_sExternalAddress;

	// Map+verify one protocol (TCP or UDP). On failure leaves *pnCommandResult set.
	// pszInternalIP is in/out for GetSpecificPortMappingEntry (MiniUPnPc intClient).
	bool MapAndVerifyProtocol( LPCSTR pszProtocol, WORD nPort, char* pszInternalIP, int& nCommandResult );
	// Map TCP then UDP for one local/external port; cleans up on partial failure.
	bool TryMapPortPair( WORD nPort, char* pszInternalIP, bool bRandomPort, int& nCommandResult );
	// Up to 5 mapping attempts with sleep + sequential/random port advance.
	bool TryMapWithPortRetries( char* pszInternalIP, int& nCommandResult );

	void OnRun();
};
