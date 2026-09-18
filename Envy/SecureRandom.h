//
// SecureRandom.h
//
// Cryptographically secure RNG helpers for security-sensitive values
// (session IDs, CSRF tokens, salts, protocol anti-spoof nonces).
// Fail closed: never falls back to rand().
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include <new>
#include <string>

#pragma comment(lib, "bcrypt.lib")

//////////////////////////////////////////////////////////////////////
// SecureRandomFill
//
// Fills pBuffer with nLength cryptographically secure random bytes.
//
// Priority:
// 1. BCryptGenRandom(..., BCRYPT_USE_SYSTEM_PREFERRED_RNG) — preferred on Win10+
// 2. CryptGenRandom(hLegacyProv) — only when a valid CryptoAPI provider is passed
// 3. FALSE — never rand()
//
// Returns FALSE on null buffer, zero length, size_t truncation, or RNG failure.
// On FALSE, pBuffer contents are unspecified; callers must not use them.

inline BOOL SecureRandomFill(BYTE* pBuffer, size_t nLength, HCRYPTPROV hLegacyProv = 0)
{
	if ( ! pBuffer || nLength == 0 )
		return FALSE;

	// BCryptGenRandom takes ULONG — reject oversized requests rather than truncate.
	if ( nLength > static_cast< size_t >( (ULONG)-1 ) )
		return FALSE;

	const ULONG cb = static_cast< ULONG >( nLength );
	const NTSTATUS status = BCryptGenRandom(
		nullptr,
		pBuffer,
		cb,
		BCRYPT_USE_SYSTEM_PREFERRED_RNG );

	if ( BCRYPT_SUCCESS( status ) )
		return TRUE;

	if ( hLegacyProv != 0 )
	{
		if ( CryptGenRandom( hLegacyProv, cb, pBuffer ) )
			return TRUE;
	}

	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// TryGetSecureRandomNum
//
// Uniform-ish value in [min, max] from CSPRNG. Fail closed (FALSE).
// Preserves width of T; does not change wire serialization of callers.

template < typename T >
inline BOOL TryGetSecureRandomNum(T& nOut, const T& min, const T& max)
{
	if ( max < min )
		return FALSE;

	// Wider accumulator avoids the signed GetRandomNum denom bug (static_cast<T>(-1)+1 == 0)
	// and handles full-range spans (e.g. 0 .. UINT32_MAX) without ULONG overflow.
	unsigned __int64 nRandom = 0;
	if ( ! SecureRandomFill( reinterpret_cast< BYTE* >( &nRandom ), sizeof( T ) ) )
		return FALSE;

	const unsigned __int64 nSpan =
		static_cast< unsigned __int64 >( max ) - static_cast< unsigned __int64 >( min ) + 1ull;
	nOut = static_cast< T >( static_cast< unsigned __int64 >( min ) + ( nRandom % nSpan ) );
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// SecureRandomHexId
//
// Writes nHexChars lowercase hex digits (must be even, > 0) into out.
// Fail closed: out cleared and FALSE on any error.

inline bool SecureRandomHexId(size_t nHexChars, std::string& out)
{
	out.clear();

	if ( nHexChars == 0 || ( nHexChars % 2 ) != 0 )
		return false;

	const size_t nBytes = nHexChars / 2;
	BYTE stackBuf[64];
	BYTE* pBytes = stackBuf;
	BYTE* pHeap = nullptr;

	if ( nBytes > sizeof( stackBuf ) )
	{
		pHeap = new ( std::nothrow ) BYTE[ nBytes ];
		if ( ! pHeap )
			return false;
		pBytes = pHeap;
	}

	const bool bOk = SecureRandomFill( pBytes, nBytes ) != FALSE;
	if ( bOk )
	{
		out.reserve( nHexChars );
		for ( size_t i = 0; i < nBytes; ++i )
		{
			static const char hex[] = "0123456789abcdef";
			out.push_back( hex[ ( pBytes[ i ] >> 4 ) & 0x0F ] );
			out.push_back( hex[ pBytes[ i ] & 0x0F ] );
		}
	}

	if ( pHeap )
		delete[] pHeap;

	if ( ! bOk )
		out.clear();

	return bOk;
}
