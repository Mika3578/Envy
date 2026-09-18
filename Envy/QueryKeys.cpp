//
// QueryKeys.cpp
//
// This file is part of Envy (getenvy.com) ù 2016-2018
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
#include "QueryKeys.h"
#include "SecureRandom.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#define new DEBUG_NEW
#endif	// Debug


//////////////////////////////////////////////////////////////////////
// CQueryKeys construction

CQueryKeys::CQueryKeys()
	: m_nBits	( 0 )
	, m_pTable	( NULL )
	, m_nTable	( 0 )
	, m_pMap	( NULL )
{
}

void CQueryKeys::Alloc()
{
	m_nBits		= 12;
	m_nTable	= 1u << m_nBits;
	m_pTable	= new DWORD[ m_nTable ];
	m_pMap		= new DWORD[ m_nBits * 2 ];

	DWORD* pMap = m_pMap;

	for ( DWORD nCount = m_nBits; nCount; nCount-- )
	{
		BYTE nShiftA = 0;
		BYTE nShiftB = 0;
		if ( ! TryGetSecureRandomNum( nShiftA, (BYTE)0, (BYTE)31 ) ||
			 ! TryGetSecureRandomNum( nShiftB, (BYTE)0, (BYTE)31 ) )
		{
			delete [] m_pMap;
			delete [] m_pTable;
			m_pMap = NULL;
			m_pTable = NULL;
			m_nTable = 0;
			m_nBits = 0;
			theApp.Message( MSG_ERROR, L"G2 QueryKeys: secure RNG failed during table init" );
			return;
		}
		*pMap++ = 1u << nShiftA;
		*pMap++ = 1u << nShiftB;
	}

	// Fill the key table in one CSPRNG call (DWORD[] as bytes ù same wire key width)
	if ( ! GenerateCryptographicBytes( (BYTE*)m_pTable, m_nTable * sizeof( DWORD ) ) )
	{
		delete [] m_pMap;
		delete [] m_pTable;
		m_pMap = NULL;
		m_pTable = NULL;
		m_nTable = 0;
		m_nBits = 0;
		theApp.Message( MSG_ERROR, L"G2 QueryKeys: secure RNG failed during table fill" );
		return;
	}

	// ToDo: Add check for invalid (for Shareaza/Envy) zero keys
}

CQueryKeys::~CQueryKeys()
{
	delete [] m_pMap;
	delete [] m_pTable;
}

//////////////////////////////////////////////////////////////////////
// CQueryKeys create or lookup

DWORD CQueryKeys::Create(DWORD nAddress)
{
	if ( ! m_pTable )
		Alloc();

	if ( ! m_pTable || ! m_pMap )
		return 0;

	const DWORD* pMap = m_pMap;
	DWORD nHash = 0;

	for ( DWORD nCount = m_nBits, nBit = 1; nCount; nCount--, nBit <<= 1 )
	{
		BOOL bOne = ( nAddress & (*pMap++) ) != 0;
		BOOL bTwo = ( nAddress & (*pMap++) ) != 0;
		if ( bOne ^ bTwo ) nHash |= nBit;
	}

	return m_pTable[ nHash & ( m_nTable - 1 ) ];
}

//////////////////////////////////////////////////////////////////////
// CQueryKeys check

BOOL CQueryKeys::Check(DWORD nAddress, DWORD nKey)
{
	return nKey == Create( nAddress );
}
