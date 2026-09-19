//
// Datagram.cpp
//
// This file is part of Envy (getenvy.com) © 2016-2018
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

#include "StdAfx.h"
#include "Envy.h"
#include "Settings.h"
#include "Datagram.h"
#include "Datagrams.h"
#include "Buffer.h"
#include "G2Packet.h"
#include "PacketLengthValidate.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#define new DEBUG_NEW
#endif	// Debug


//////////////////////////////////////////////////////////////////////
// CDatagramIn construction

CDatagramIn::CDatagramIn()
	: m_pBuffer	( NULL )
	, m_pLocked	( NULL )
	, m_nBuffer	( 0 )
{
}

CDatagramIn::~CDatagramIn()
{
	if ( m_pLocked ) delete [] m_pLocked;
	if ( m_pBuffer ) delete [] m_pBuffer;
}

//////////////////////////////////////////////////////////////////////
// CDatagramIn prepare to handle a datagram

void CDatagramIn::Create(const SOCKADDR_IN* pHost, BYTE nFlags, WORD nSequence, BYTE nCount)
{
	CopyMemory( &m_pHost, pHost, sizeof( SOCKADDR_IN ) );

	m_bCompressed	= ( nFlags & SGP_DEFLATE ) ? TRUE : FALSE;
	m_nSequence		= nSequence;
	m_nCount		= nCount;
	m_nLeft			= nCount;

	m_tStarted	= GetTickCount();

	if ( m_nBuffer < m_nCount )
	{
		if ( m_pLocked ) delete [] m_pLocked;
		if ( m_pBuffer ) delete [] m_pBuffer;

		m_nBuffer	= m_nCount;
		m_pBuffer	= new CBuffer*[ m_nBuffer ];
		m_pLocked	= new BOOL[ m_nBuffer ];
	}

	ZeroMemory( m_pBuffer, sizeof( CBuffer* ) * m_nBuffer );
	ZeroMemory( m_pLocked, sizeof( BOOL ) * m_nBuffer );
}

//////////////////////////////////////////////////////////////////////
// CDatagramIn add a datagram part

BOOL CDatagramIn::Add(BYTE nPart, LPCVOID pData, DWORD nLength)
{
	if (nPart < 1 || nPart > m_nCount)
		return FALSE;
	if (m_nLeft == 0)
		return FALSE;

	const DWORD nCap = G2SgpEffectiveByteCap(Settings.Gnutella.MaximumPacket);
	if (nLength > nCap)
		return FALSE;

	if (m_pLocked[nPart - 1] == FALSE)
	{
		// Enforce cumulative reassembly budget before allocating into the part buffer.
		DWORD nTotal = nLength;
		for (int i = 0; i < m_nCount; i++)
		{
			if (i == (int)nPart - 1)
				continue;
			if (!m_pLocked[i] || m_pBuffer[i] == NULL)
				continue;
			const DWORD nPartLen = m_pBuffer[i]->m_nLength;
			if (nPartLen > nCap - nTotal)
				return FALSE;
			nTotal += nPartLen;
		}
		if (nTotal > nCap)
			return FALSE;

		m_pLocked[nPart - 1] = TRUE;
		m_pBuffer[nPart - 1]->Add(pData, nLength);

		if (--m_nLeft == 0)
			return TRUE;
	}

	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// CDatagramIn convert to a packet

CG2Packet* CDatagramIn::ToG2Packet()
{
	const DWORD nCap = G2SgpEffectiveByteCap(Settings.Gnutella.MaximumPacket);
	DWORD nTotal = 0;
	for (int nPart = 0; nPart < m_nCount; nPart++)
	{
		if (m_pBuffer[nPart] == NULL)
			return NULL;
		const DWORD nPartLen = m_pBuffer[nPart]->m_nLength;
		if (nPartLen > nCap - nTotal)
			return NULL;
		nTotal += nPartLen;
		if (!G2SgpReassembledBytesOk(nTotal, nCap))
			return NULL;
	}

	if (m_nCount != 1)
	{
		for (int nPart = 1; nPart < m_nCount; nPart++)
		{
			m_pBuffer[0]->AddBuffer(m_pBuffer[nPart]);
		}
	}

	if (m_bCompressed)
	{
		if (!m_pBuffer[0]->Inflate(nCap))
			return NULL;
	}
	else if (!G2SgpReassembledBytesOk(m_pBuffer[0]->m_nLength, nCap))
	{
		return NULL;
	}

	return CG2Packet::ReadBuffer(m_pBuffer[0]);
}
