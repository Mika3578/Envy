//
// RC4.h
//
// RC4 encryption implementation for CryptLayer
//
// This file is part of Envy (getenvy.com) © 2016-2026
//
// Envy is free software. You may redistribute and/or modify it
// under the terms of the GNU Affero General Public License
// as published by the Free Software Foundation (fsf.org);
// version 3 or later at your option. (AGPLv3)
//
// The cipher is header-only so the MFC-free modules (KadUdpObfuscation.h) and
// the native tests can reuse it without linking the Envy MFC project.
//

#pragma once

#include <windows.h>

class CRC4
{
public:
	CRC4()
	    : m_bInitialized(false)
	    , m_i(0)
	    , m_j(0)
	{
		ZeroMemory(m_S, sizeof(m_S));
	}

	virtual ~CRC4()
	{
		// Clear sensitive data
		ZeroMemory(m_S, sizeof(m_S));
		m_i = m_j = 0;
	}

	// Initialize with key
	void Init(const BYTE* pKey, size_t nKeyLen)
	{
		if (!pKey || nKeyLen == 0 || nKeyLen > 256)
		{
			m_bInitialized = false;
			return;
		}

		// Initialize S-box
		for (int i = 0; i < 256; i++)
		{
			m_S[i] = (BYTE)i;
		}

		// Key scheduling algorithm (KSA)
		int j = 0;
		for (int i = 0; i < 256; i++)
		{
			j = (j + m_S[i] + pKey[i % nKeyLen]) & 0xFF;
			Swap(m_S[i], m_S[j]);
		}

		m_i = 0;
		m_j = 0;
		m_bInitialized = true;
	}

	// Encrypt/decrypt data (RC4 is symmetric)
	void Process(BYTE* pData, size_t nDataLen)
	{
		if (!m_bInitialized || !pData || nDataLen == 0)
			return;

		// Pseudo-random generation algorithm (PRGA)
		for (size_t n = 0; n < nDataLen; n++)
		{
			m_i = (m_i + 1) & 0xFF;
			m_j = (m_j + m_S[m_i]) & 0xFF;
			Swap(m_S[m_i], m_S[m_j]);

			BYTE k = m_S[(m_S[m_i] + m_S[m_j]) & 0xFF];
			pData[n] ^= k;
		}
	}

	// Check if initialized
	bool IsInitialized() const { return m_bInitialized; }

private:
	bool m_bInitialized;
	BYTE m_S[256]; // S-box
	int m_i, m_j;  // Indices

	void Swap(BYTE& a, BYTE& b)
	{
		BYTE temp = a;
		a = b;
		b = temp;
	}
};
